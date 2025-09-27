"""
FastAPI router for scan management endpoints.
Handles scan session creation, monitoring, and control.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc, func
import logging
from datetime import datetime, timedelta

from api.dependencies.database import get_db
from api.dependencies.auth import get_current_user, require_permissions
from api.schemas.scan import (
    ScanSessionCreate,
    ScanSessionUpdate,
    ScanSessionResponse,
    ScanSessionListResponse,
    ScanConfiguration,
    ScanProgress,
    ScanResults,
    ToolExecutionResponse,
    ScanQueryFilters
)
from apps.scanning.models import ScanSession, ScanStatus, ToolExecution, ToolStatus
from apps.targets.models import Target
from core.pagination import ScanFastAPIPagination
from core.exceptions import (
    RecordNotFoundException,
    InvalidDataException,
    InvalidScanConfigurationException,
    ConcurrentScanLimitException
)
from services.scanning_service import ScanningService
from services.notification_service import NotificationService
from core.constants import RECON_PHASES, MAX_CONCURRENT_SCANS

logger = logging.getLogger(__name__)

router = APIRouter()
scanning_service = ScanningService()
notification_service = NotificationService()

@router.get("/", response_model=ScanSessionListResponse)
async def list_scan_sessions(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(15, ge=1, le=50, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by scan status"),
    target_id: Optional[str] = Query(None, description="Filter by target ID"),
    search: Optional[str] = Query(None, description="Search in session names"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of scan sessions with filtering, searching, and pagination.
    """
    try:
        # Build query
        query = db.query(ScanSession)

        # Apply filters
        if status:
            try:
                status_enum = ScanStatus(status.lower())
                query = query.filter(ScanSession.status == status_enum)
            except ValueError:
                raise InvalidDataException("status", status, "Invalid scan status value")

        if target_id:
            query = query.filter(ScanSession.target_id == target_id)

        if search:
            search_filter = or_(
                ScanSession.session_name.ilike(f"%{search}%")
            )
            query = query.filter(search_filter)

        # Apply sorting
        sort_field = getattr(ScanSession, sort_by, ScanSession.created_at)
        if sort_order == "desc":
            query = query.order_by(desc(sort_field))
        else:
            query = query.order_by(asc(sort_field))

        # Apply pagination
        pagination = ScanFastAPIPagination(page, page_size)
        result = pagination.paginate_scans(query, status)

        return ScanSessionListResponse(
            scan_sessions=[ScanSessionResponse.from_orm(session) for session in result['items']],
            pagination=result['pagination'],
            status_counts=result.get('status_counts', {}),
            applied_filters=result.get('applied_filters', {})
        )

    except Exception as e:
        logger.error("Error listing scan sessions: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan sessions"
        )

@router.post("/", response_model=ScanSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_session(
    scan_data: ScanSessionCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new scan session.
    """
    try:
        # Verify target exists and is active
        target = db.query(Target).filter(Target.id == scan_data.target_id).first()

        if not target:
            raise RecordNotFoundException("Target", scan_data.target_id)

        if not target.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot scan inactive target"
            )

        # Check concurrent scan limit
        running_scans = db.query(func.count(ScanSession.id)).filter(
            ScanSession.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED])
        ).scalar()

        if running_scans >= MAX_CONCURRENT_SCANS:
            raise ConcurrentScanLimitException(MAX_CONCURRENT_SCANS)

        # Validate scan configuration
        if scan_data.scan_config:
            config_validation = scanning_service.validate_scan_config(
                scan_data.scan_config, target
            )
            if not config_validation.is_valid:
                raise InvalidScanConfigurationException(config_validation.message)

        # Create scan session
        db_scan = ScanSession(
            target_id=scan_data.target_id,
            session_name=scan_data.session_name,
            scan_config=scan_data.scan_config or {},
            methodology_phases=scan_data.methodology_phases or RECON_PHASES,
            status=ScanStatus.QUEUED
        )

        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)

        # Queue scan execution in background
        background_tasks.add_task(
            scanning_service.execute_scan_session,
            db_scan.id,
            current_user.get("user_id")
        )

        # Send notification
        await notification_service.send_notification(
            "scan_started",
            {
                "scan_id": str(db_scan.id),
                "target_name": target.target_name,
                "user_id": current_user.get("user_id")
            }
        )

        logger.info("Created scan session: %s", db_scan.id)

        return ScanSessionResponse.from_orm(db_scan)

    except Exception as e:
        db.rollback()
        logger.error("Error creating scan session: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scan session"
        )

@router.get("/{scan_id}", response_model=ScanSessionResponse)
async def get_scan_session(
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a specific scan session by ID.
    """
    scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

    if not scan_session:
        raise RecordNotFoundException("Scan Session", scan_id)

    return ScanSessionResponse.from_orm(scan_session)

@router.put("/{scan_id}", response_model=ScanSessionResponse)
async def update_scan_session(
    scan_data: ScanSessionUpdate,
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Update an existing scan session (only if not running).
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        # Check if scan can be updated
        if scan_session.status in [ScanStatus.RUNNING, ScanStatus.COMPLETED]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot update scan session in {scan_session.status.value} status"
            )

        # Update fields
        update_data = scan_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(scan_session, field, value)

        scan_session.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(scan_session)

        logger.info("Updated scan session: %s", scan_id)

        return ScanSessionResponse.from_orm(scan_session)

    except Exception as e:
        db.rollback()
        logger.error("Error updating scan session {scan_id}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update scan session"
        )

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_session(
    scan_id: str = Path(..., description="Scan session ID"),
    force: bool = Query(False, description="Force delete even if scan is running"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions(["admin", "delete_scan"]))
):
    """
    Delete a scan session (admin only).
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        # Check if scan is running
        if scan_session.status == ScanStatus.RUNNING and not force:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete running scan session. Use force=true to override."
            )

        # Stop scan if running
        if scan_session.status == ScanStatus.RUNNING:
            await scanning_service.stop_scan_session(scan_id)

        db.delete(scan_session)
        db.commit()

        logger.info("Deleted scan session: %s", scan_id)

    except Exception as e:
        db.rollback()
        logger.error("Error deleting scan session {scan_id}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scan session"
        )

@router.post("/{scan_id}/start")
async def start_scan_session(
    background_tasks: BackgroundTasks,
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Start a queued scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        if scan_session.status != ScanStatus.QUEUED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot start scan session in {scan_session.status.value} status"
            )

        # Check concurrent scan limit
        running_scans = db.query(func.count(ScanSession.id)).filter(
            ScanSession.status == ScanStatus.RUNNING
        ).scalar()

        if running_scans >= MAX_CONCURRENT_SCANS:
            raise ConcurrentScanLimitException(MAX_CONCURRENT_SCANS)

        # Update status and start execution
        scan_session.status = ScanStatus.RUNNING
        scan_session.started_at = datetime.utcnow()
        db.commit()

        # Execute scan in background
        background_tasks.add_task(
            scanning_service.execute_scan_session,
            scan_id,
            current_user.get("user_id")
        )

        logger.info("Started scan session: %s", scan_id)

        return {"message": "Scan session started successfully"}

    except Exception as e:
        db.rollback()
        logger.error("Error starting scan session {scan_id}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start scan session"
        )

@router.post("/{scan_id}/pause")
async def pause_scan_session(
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Pause a running scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        if scan_session.status != ScanStatus.RUNNING:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot pause scan session in {scan_session.status.value} status"
            )

        # Pause scan execution
        await scanning_service.pause_scan_session(scan_id)

        scan_session.status = ScanStatus.PAUSED
        db.commit()

        logger.info("Paused scan session: %s", scan_id)

        return {"message": "Scan session paused successfully"}

    except Exception as e:
        db.rollback()
        logger.error("Error pausing scan session {scan_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to pause scan session"
        )

@router.post("/{scan_id}/resume")
async def resume_scan_session(
    background_tasks: BackgroundTasks,
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Resume a paused scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        if scan_session.status != ScanStatus.PAUSED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot resume scan session in {scan_session.status.value} status"
            )

        # Check concurrent scan limit
        running_scans = db.query(func.count(ScanSession.id)).filter(
            ScanSession.status == ScanStatus.RUNNING
        ).scalar()

        if running_scans >= MAX_CONCURRENT_SCANS:
            raise ConcurrentScanLimitException(MAX_CONCURRENT_SCANS)

        # Resume scan execution
        scan_session.status = ScanStatus.RUNNING
        db.commit()

        background_tasks.add_task(
            scanning_service.resume_scan_session,
            scan_id,
            current_user.get("user_id")
        )

        logger.info("Resumed scan session: %s", scan_id)

        return {"message": "Scan session resumed successfully"}

    except Exception as e:
        db.rollback()
        logger.error("Error resuming scan session {scan_id}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resume scan session"
        )

@router.post("/{scan_id}/stop")
async def stop_scan_session(
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Stop a running or paused scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        if scan_session.status not in [ScanStatus.RUNNING, ScanStatus.PAUSED]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot stop scan session in {scan_session.status.value} status"
            )

        # Stop scan execution
        await scanning_service.stop_scan_session(scan_id)

        scan_session.status = ScanStatus.CANCELLED
        scan_session.completed_at = datetime.utcnow()
        db.commit()

        logger.info("Stopped scan session: %s", scan_id)

        return {"message": "Scan session stopped successfully"}

    except Exception as e:
        db.rollback()
        logger.error("Error stopping scan session {scan_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop scan session"
        )

@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(
    scan_id: str = Path(..., description="Scan session ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get real-time progress information for a scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        # Get tool execution progress
        tool_executions = db.query(ToolExecution).filter(
            ToolExecution.scan_session_id == scan_id
        ).all()

        progress_info = scanning_service.calculate_scan_progress(
            scan_session, tool_executions
        )

        return ScanProgress(**progress_info)

    except Exception as e:
        logger.error("Error getting scan progress for {scan_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scan progress"
        )

@router.get("/{scan_id}/results", response_model=ScanResults)
async def get_scan_results(
    scan_id: str = Path(..., description="Scan session ID"),
    include_raw_output: bool = Query(False, description="Include raw tool output"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get results from a completed scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        # Get scan results
        results = await scanning_service.get_scan_results(
            scan_id, include_raw_output
        )

        return ScanResults(**results)

    except Exception as e:
        logger.error("Error getting scan results for {scan_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scan results"
        )

@router.get("/{scan_id}/tools", response_model=List[ToolExecutionResponse])
async def get_scan_tool_executions(
    scan_id: str = Path(..., description="Scan session ID"),
    status: Optional[str] = Query(None, description="Filter by tool status"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get tool execution information for a scan session.
    """
    try:
        scan_session = db.query(ScanSession).filter(ScanSession.id == scan_id).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", scan_id)

        query = db.query(ToolExecution).filter(ToolExecution.scan_session_id == scan_id)

        if status:
            try:
                status_enum = ToolStatus(status.lower())
                query = query.filter(ToolExecution.status == status_enum)
            except ValueError:
                raise InvalidDataException("status", status, "Invalid tool status value")

        tool_executions = query.order_by(ToolExecution.started_at).all()

        return [ToolExecutionResponse.from_orm(tool) for tool in tool_executions]

    except Exception as e:
        logger.error("Error getting tool executions for scan {scan_id}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get tool executions"
        )

@router.get("/statistics/summary")
async def get_scan_statistics(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get scan statistics and summary.
    """
    try:
        # Total scans
        total = db.query(func.count(ScanSession.id)).scalar()

        # Status breakdown
        status_stats = db.query(
            ScanSession.status,
            func.count(ScanSession.id)
        ).group_by(ScanSession.status).all()

        # Recent scans (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent = db.query(func.count(ScanSession.id)).filter(
            ScanSession.created_at >= week_ago
        ).scalar()

        # Average scan duration
        avg_duration = db.query(
            func.avg(
                func.extract('epoch', ScanSession.completed_at - ScanSession.started_at)
            )
        ).filter(
            and_(
                ScanSession.started_at.isnot(None),
                ScanSession.completed_at.isnot(None)
            )
        ).scalar()

        return {
            "total_scans": total,
            "recent_scans": recent,
            "status_distribution": {
                status.value: count for status, count in status_stats
            },
            "average_duration_seconds": float(avg_duration) if avg_duration else 0,
            "success_rate": len([s for s, c in status_stats if s == ScanStatus.COMPLETED]) / total * 100 if total > 0 else 0
        }

    except Exception as e:
        logger.error("Error getting scan statistics: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scan statistics"
        )

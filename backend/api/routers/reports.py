"""
FastAPI router for report management endpoints.
Handles report generation, retrieval, and export.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc, func
import logging
from datetime import datetime, timedelta
import os

from api.dependencies.database import get_db
from api.dependencies.auth import get_current_user, require_permissions
from api.schemas.report import (
    ReportCreate,
    ReportUpdate,
    ReportResponse,
    ReportListResponse,
    ReportGeneration,
    ReportTemplate,
    ReportExport
)
from apps.reports.models import Report
from apps.scans.models import ScanSession
from core.pagination import FastAPIPagination
from core.exceptions import (
    RecordNotFoundException,
    InvalidDataException,
    ReportGenerationException,
    TemplateNotFoundException
)
from services.reporting_service import ReportingService
from core.constants import REPORT_TYPES, REPORT_FORMATS, REPORT_TEMPLATES

logger = logging.getLogger(__name__)

router = APIRouter()
reporting_service = ReportingService()

@router.get("/", response_model=ReportListResponse)
async def list_reports(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    scan_session_id: Optional[str] = Query(None, description="Filter by scan session ID"),
    search: Optional[str] = Query(None, description="Search in report names"),
    sort_by: str = Query("generated_at", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of reports with filtering, searching, and pagination.
    """
    try:
        # Build query
        query = db.query(Report)

        # Apply filters
        if report_type:
            if report_type not in REPORT_TYPES:
                raise InvalidDataException("report_type", report_type, f"Must be one of: {', '.join(REPORT_TYPES)}")
            query = query.filter(Report.report_type == report_type)

        if scan_session_id:
            query = query.filter(Report.scan_session_id == scan_session_id)

        if search:
            search_filter = or_(
                Report.report_name.ilike(f"%{search}%"),
                Report.executive_summary.ilike(f"%{search}%")
            )
            query = query.filter(search_filter)

        # Apply sorting
        sort_field = getattr(Report, sort_by, Report.generated_at)
        if sort_order == "desc":
            query = query.order_by(desc(sort_field))
        else:
            query = query.order_by(asc(sort_field))

        # Apply pagination
        pagination = FastAPIPagination(page, page_size)
        result = pagination.paginate_query(query)

        # Get report type statistics
        type_stats = db.query(
            Report.report_type,
            func.count(Report.id)
        ).group_by(Report.report_type).all()

        return ReportListResponse(
            reports=[ReportResponse.from_orm(report) for report in result['items']],
            pagination=result['pagination'],
            type_counts={
                report_type: count for report_type, count in type_stats
            }
        )

    except Exception as e:
        logger.error("Error listing reports: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve reports"
        )

@router.post("/", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def create_report(
    report_data: ReportCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Create and generate a new report.
    """
    try:
        # Verify scan session exists
        scan_session = db.query(ScanSession).filter(
            ScanSession.id == report_data.scan_session_id
        ).first()

        if not scan_session:
            raise RecordNotFoundException("Scan Session", report_data.scan_session_id)

        # Validate report type
        if report_data.report_type not in REPORT_TYPES:
            raise InvalidDataException(
                "report_type",
                report_data.report_type,
                f"Must be one of: {', '.join(REPORT_TYPES)}"
            )

        # Create report instance
        db_report = Report(
            scan_session_id=report_data.scan_session_id,
            report_name=report_data.report_name,
            report_type=report_data.report_type,
            generated_by=current_user.get("username", "unknown")
        )

        db.add(db_report)
        db.commit()
        db.refresh(db_report)

        # Generate report in background
        background_tasks.add_task(
            reporting_service.generate_report,
            db_report.id,
            report_data.template_options,
            current_user.get("user_id")
        )

        logger.info("Created report: %s", db_report.id)

        return ReportResponse.from_orm(db_report)

    except Exception as e:
        db.rollback()
        logger.error("Error creating report: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create report"
        )

@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str = Path(..., description="Report ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a specific report by ID.
    """
    report = db.query(Report).filter(Report.id == report_id).first()

    if not report:
        raise RecordNotFoundException("Report", report_id)

    return ReportResponse.from_orm(report)

@router.put("/{report_id}", response_model=ReportResponse)
async def update_report(
    report_data: ReportUpdate,
    report_id: str = Path(..., description="Report ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Update an existing report.
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()

        if not report:
            raise RecordNotFoundException("Report", report_id)

        # Update fields
        update_data = report_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(report, field, value)

        db.commit()
        db.refresh(report)

        logger.info("Updated report: %s", report_id)

        return ReportResponse.from_orm(report)

    except Exception as e:
        db.rollback()
        logger.error("Error updating report {report_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update report"
        )

@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str = Path(..., description="Report ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions(["admin", "delete_report"]))
):
    """
    Delete a report (admin only).
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()

        if not report:
            raise RecordNotFoundException("Report", report_id)

        # Delete associated files
        await reporting_service.cleanup_report_files(report)

        db.delete(report)
        db.commit()

        logger.info("Deleted report: %s", report_id)

    except Exception as e:
        db.rollback()
        logger.error("Error deleting report {report_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete report"
        )

@router.get("/{report_id}/download/{format}")
async def download_report(
    report_id: str = Path(..., description="Report ID"),
    format: str = Path(..., regex="^(pdf|html|json)$", description="Download format"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Download report in specified format.
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()

        if not report:
            raise RecordNotFoundException("Report", report_id)

        # Get file path based on format
        file_path = None
        if format == "pdf" and report.pdf_file_path:
            file_path = report.pdf_file_path
        elif format == "html" and report.html_file_path:
            file_path = report.html_file_path
        elif format == "json" and report.json_file_path:
            file_path = report.json_file_path

        if not file_path or not os.path.exists(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Report file not found in {format} format"
            )

        # Determine media type
        media_types = {
            "pdf": "application/pdf",
            "html": "text/html",
            "json": "application/json"
        }

        filename = f"{report.report_name}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.{format}"

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type=media_types[format]
        )

    except Exception as e:
        logger.error("Error downloading report {report_id}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download report"
        )

@router.post("/{report_id}/regenerate")
async def regenerate_report(
    background_tasks: BackgroundTasks,
    report_id: str = Path(..., description="Report ID"),
    template_options: Optional[Dict[str, Any]] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Regenerate an existing report with updated data.
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()

        if not report:
            raise RecordNotFoundException("Report", report_id)

        # Clean up old report files
        await reporting_service.cleanup_report_files(report)

        # Reset report statistics
        report.total_vulnerabilities_reported = 0
        report.critical_count = 0
        report.high_count = 0
        report.medium_count = 0
        report.low_count = 0
        report.pdf_file_path = None
        report.html_file_path = None
        report.json_file_path = None

        db.commit()

        # Regenerate report in background
        background_tasks.add_task(
            reporting_service.generate_report,
            report_id,
            template_options or {},
            current_user.get("user_id")
        )

        logger.info("Regenerating report: %s", report_id)

        return {"message": "Report regeneration started"}

    except Exception as e:
        db.rollback()
        logger.error("Error regenerating report {report_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate report"
        )

@router.post("/generate", response_model=ReportGeneration)
async def generate_custom_report(
    generation_request: ReportGeneration,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Generate a custom report with specific parameters.
    """
    try:
        # Validate scan session IDs
        scan_sessions = db.query(ScanSession).filter(
            ScanSession.id.in_(generation_request.scan_session_ids)
        ).all()

        if len(scan_sessions) != len(generation_request.scan_session_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Some scan session IDs were not found"
            )

        # Validate report type and template
        if generation_request.report_type not in REPORT_TYPES:
            raise InvalidDataException(
                "report_type",
                generation_request.report_type,
                f"Must be one of: {', '.join(REPORT_TYPES)}"
            )

        if generation_request.template_name not in REPORT_TEMPLATES:
            raise TemplateNotFoundException(generation_request.template_name)

        # Create report record
        db_report = Report(
            scan_session_id=generation_request.scan_session_ids[0],  # Primary scan
            report_name=generation_request.report_name,
            report_type=generation_request.report_type,
            generated_by=current_user.get("username", "unknown")
        )

        db.add(db_report)
        db.commit()
        db.refresh(db_report)

        # Generate custom report in background
        background_tasks.add_task(
            reporting_service.generate_custom_report,
            db_report.id,
            generation_request.dict(),
            current_user.get("user_id")
        )

        logger.info("Started custom report generation: %s", db_report.id)

        generation_request.report_id = str(db_report.id)
        generation_request.status = "generating"

        return generation_request

    except Exception as e:
        db.rollback()
        logger.error("Error generating custom report: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate custom report"
        )

@router.get("/templates/", response_model=List[ReportTemplate])
async def list_report_templates(
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of available report templates.
    """
    try:
        templates = await reporting_service.get_available_templates(report_type)

        return [ReportTemplate(**template) for template in templates]

    except Exception as e:
        logger.error("Error listing report templates: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list report templates"
        )

@router.get("/templates/{template_name}", response_model=ReportTemplate)
async def get_report_template(
    template_name: str = Path(..., description="Template name"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get details of a specific report template.
    """
    try:
        template = await reporting_service.get_template_details(template_name)

        if not template:
            raise TemplateNotFoundException(template_name)

        return ReportTemplate(**template)

    except Exception as e:
        logger.error("Error getting report template {template_name}: %s", e)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get report template"
        )

@router.post("/{report_id}/export", response_model=ReportExport)
async def export_report_data(
    report_id: str = Path(..., description="Report ID"),
    export_format: str = Query("json", regex="^(json|xml|csv)$", description="Export format"),
    include_raw_data: bool = Query(False, description="Include raw scan data"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Export report data in various formats for integration.
    """
    try:
        report = db.query(Report).filter(Report.id == report_id).first()

        if not report:
            raise RecordNotFoundException("Report", report_id)

        # Export report data
        export_data = await reporting_service.export_report_data(
            report, export_format, include_raw_data
        )

        return ReportExport(
            report_id=report_id,
            format=export_format,
            data=export_data,
            exported_at=datetime.utcnow(),
            exported_by=current_user.get("username", "unknown")
        )

    except Exception as e:
        logger.error("Error exporting report {report_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export report data"
        )

@router.get("/statistics/summary")
async def get_report_statistics(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get report generation statistics and summary.
    """
    try:
        # Total reports
        total = db.query(func.count(Report.id)).scalar()

        # Report type breakdown
        type_stats = db.query(
            Report.report_type,
            func.count(Report.id)
        ).group_by(Report.report_type).all()

        # Recent reports (last 30 days)
        month_ago = datetime.utcnow() - timedelta(days=30)
        recent = db.query(func.count(Report.id)).filter(
            Report.generated_at >= month_ago
        ).scalar()

        # PII redaction statistics
        redacted_reports = db.query(func.count(Report.id)).filter(
            Report.pii_redacted == True
        ).scalar()

        # Average vulnerabilities per report
        avg_vulns = db.query(
            func.avg(Report.total_vulnerabilities_reported)
        ).scalar()

        return {
            "total_reports": total,
            "recent_reports": recent,
            "type_distribution": {
                report_type: count for report_type, count in type_stats
            },
            "pii_redacted_reports": redacted_reports,
            "average_vulnerabilities_per_report": float(avg_vulns) if avg_vulns else 0,
            "redaction_rate": (redacted_reports / total * 100) if total > 0 else 0
        }

    except Exception as e:
        logger.error("Error getting report statistics: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get report statistics"
        )

@router.get("/analytics/trends")
async def get_report_trends(
    days: int = Query(30, ge=7, le=365, description="Number of days for trend analysis"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get report generation trends over time.
    """
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Daily report generation
        daily_trends = db.query(
            func.date(Report.generated_at).label('date'),
            func.count(Report.id).label('count')
        ).filter(
            Report.generated_at >= start_date
        ).group_by(
            func.date(Report.generated_at)
        ).order_by('date').all()

        # Report type trends
        type_trends = db.query(
            func.date(Report.generated_at).label('date'),
            Report.report_type,
            func.count(Report.id).label('count')
        ).filter(
            Report.generated_at >= start_date
        ).group_by(
            func.date(Report.generated_at),
            Report.report_type
        ).order_by('date').all()

        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "daily_generation": [
                {"date": str(date), "count": count}
                for date, count in daily_trends
            ],
            "type_trends": [
                {"date": str(date), "type": report_type, "count": count}
                for date, report_type, count in type_trends
            ]
        }

    except Exception as e:
        logger.error("Error getting report trends: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get report trends"
        )

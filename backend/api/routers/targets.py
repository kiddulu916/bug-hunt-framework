"""
FastAPI router for target management endpoints.
Handles CRUD operations for bug bounty targets and scope management.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc, func
import logging
from datetime import datetime

from api.dependencies.database import get_db
from api.dependencies.auth import get_current_user, require_permissions
from api.schemas.target import (
    TargetCreate,
    TargetUpdate,
    TargetResponse,
    TargetListResponse,
    ScopeValidation,
    TargetConfiguration
)
from apps.targets.models import Target, BugBountyPlatform
from core.pagination import FastAPIPagination
from core.exceptions import (
    RecordNotFoundException, 
    InvalidDataException, 
    InvalidTargetException
)
from core.security import InputValidator
from services.target_service import TargetService
from core.constants import BUG_BOUNTY_PLATFORMS

logger = logging.getLogger(__name__)

router = APIRouter()
target_service = TargetService()
input_validator = InputValidator()

@router.get("/", response_model=TargetListResponse)
async def list_targets(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    platform: Optional[str] = Query(None, description="Filter by bug bounty platform"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search in target names and URLs"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get list of targets with filtering, searching, and pagination.
    """
    try:
        # Build query
        query = db.query(Target)
        
        # Apply filters
        if platform:
            try:
                platform_enum = BugBountyPlatform(platform.lower())
                query = query.filter(Target.platform == platform_enum)
            except ValueError:
                raise InvalidDataException("platform", platform, "Invalid platform value")
        
        if is_active is not None:
            query = query.filter(Target.is_active == is_active)
        
        if search:
            search_filter = or_(
                Target.target_name.ilike(f"%{search}%"),
                Target.main_url.ilike(f"%{search}%"),
                Target.program_notes.ilike(f"%{search}%")
            )
            query = query.filter(search_filter)
        
        # Apply sorting
        sort_field = getattr(Target, sort_by, Target.created_at)
        if sort_order == "desc":
            query = query.order_by(desc(sort_field))
        else:
            query = query.order_by(asc(sort_field))
        
        # Apply pagination
        pagination = FastAPIPagination(page, page_size)
        result = pagination.paginate_query(query)
        
        # Get platform statistics
        platform_stats = db.query(
            Target.platform,
            func.count(Target.id)
        ).group_by(Target.platform).all()
        
        return TargetListResponse(
            targets=[TargetResponse.from_orm(target) for target in result['items']],
            pagination=result['pagination'],
            platform_counts={
                platform.value: count for platform, count in platform_stats
            },
            total_active=db.query(func.count(Target.id)).filter(Target.is_active == True).scalar()
        )
        
    except Exception as e:
        logger.error(f"Error listing targets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve targets"
        )

@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    target_data: TargetCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new target.
    """
    try:
        # Validate target data
        if not input_validator.validate_url(target_data.main_url):
            raise InvalidDataException("main_url", target_data.main_url, "Invalid URL format")
        
        if not input_validator.validate_target_name(target_data.target_name):
            raise InvalidDataException("target_name", target_data.target_name, "Invalid target name format")
        
        # Check for duplicate target name
        existing_target = db.query(Target).filter(
            Target.target_name == target_data.target_name
        ).first()
        
        if existing_target:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Target with this name already exists"
            )
        
        # Validate scope URLs
        scope_validation = target_service.validate_scope(
            target_data.in_scope_urls,
            target_data.out_of_scope_urls
        )
        
        if not scope_validation.is_valid:
            raise InvalidTargetException(f"Invalid scope configuration: {scope_validation.message}")
        
        # Create target instance
        db_target = Target(**target_data.dict())
        
        db.add(db_target)
        db.commit()
        db.refresh(db_target)
        
        logger.info(f"Created target: {db_target.id} - {db_target.target_name}")
        
        return TargetResponse.from_orm(db_target)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating target: {e}")
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create target"
        )

@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a specific target by ID.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    
    if not target:
        raise RecordNotFoundException("Target", target_id)
    
    return TargetResponse.from_orm(target)

@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: str = Path(..., description="Target ID"),
    target_data: TargetUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Update an existing target.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        # Validate updated data
        update_data = target_data.dict(exclude_unset=True)
        
        if 'main_url' in update_data and not input_validator.validate_url(update_data['main_url']):
            raise InvalidDataException("main_url", update_data['main_url'], "Invalid URL format")
        
        if 'target_name' in update_data:
            if not input_validator.validate_target_name(update_data['target_name']):
                raise InvalidDataException("target_name", update_data['target_name'], "Invalid target name format")
            
            # Check for duplicate name (excluding current target)
            existing_target = db.query(Target).filter(
                and_(
                    Target.target_name == update_data['target_name'],
                    Target.id != target_id
                )
            ).first()
            
            if existing_target:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Target with this name already exists"
                )
        
        # Validate scope if updated
        in_scope = update_data.get('in_scope_urls', target.in_scope_urls)
        out_of_scope = update_data.get('out_of_scope_urls', target.out_of_scope_urls)
        
        scope_validation = target_service.validate_scope(in_scope, out_of_scope)
        if not scope_validation.is_valid:
            raise InvalidTargetException(f"Invalid scope configuration: {scope_validation.message}")
        
        # Update fields
        for field, value in update_data.items():
            setattr(target, field, value)
        
        target.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(target)
        
        logger.info(f"Updated target: {target_id}")
        
        return TargetResponse.from_orm(target)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating target {target_id}: {e}")
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update target"
        )

@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions(["admin", "delete_target"]))
):
    """
    Delete a target (admin only).
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        # Check if target has associated scan sessions
        from apps.scans.models import ScanSession
        scan_count = db.query(func.count(ScanSession.id)).filter(
            ScanSession.target_id == target_id
        ).scalar()
        
        if scan_count > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot delete target with {scan_count} associated scan sessions"
            )
        
        db.delete(target)
        db.commit()
        
        logger.info(f"Deleted target: {target_id}")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting target {target_id}: {e}")
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete target"
        )

@router.post("/{target_id}/validate-scope", response_model=ScopeValidation)
async def validate_target_scope(
    target_id: str = Path(..., description="Target ID"),
    asset_url: str = Query(..., description="Asset URL to validate"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Validate if an asset URL is within the target's scope.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        validation = target_service.validate_asset_scope(
            asset_url,
            target.in_scope_urls,
            target.out_of_scope_urls,
            target.in_scope_assets,
            target.out_of_scope_assets
        )
        
        return validation
        
    except Exception as e:
        logger.error(f"Error validating scope for target {target_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate scope"
        )

@router.get("/{target_id}/configuration", response_model=TargetConfiguration)
async def get_target_configuration(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get target configuration for scanning tools.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        config = target_service.generate_scan_configuration(target)
        
        return TargetConfiguration(**config)
        
    except Exception as e:
        logger.error(f"Error getting configuration for target {target_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get target configuration"
        )

@router.post("/{target_id}/test-connectivity")
async def test_target_connectivity(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Test connectivity to the target's main URL.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        connectivity_result = await target_service.test_connectivity(target.main_url)
        
        return {
            "target_id": target_id,
            "url": target.main_url,
            "connectivity": connectivity_result
        }
        
    except Exception as e:
        logger.error(f"Error testing connectivity for target {target_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test connectivity"
        )

@router.get("/{target_id}/statistics")
async def get_target_statistics(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get statistics for a specific target.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        from apps.scans.models import ScanSession
        from apps.vulnerabilities.models import Vulnerability
        from apps.recon.models import ReconResult
        
        # Scan statistics
        total_scans = db.query(func.count(ScanSession.id)).filter(
            ScanSession.target_id == target_id
        ).scalar()
        
        completed_scans = db.query(func.count(ScanSession.id)).filter(
            and_(
                ScanSession.target_id == target_id,
                ScanSession.status == 'completed'
            )
        ).scalar()
        
        # Vulnerability statistics
        total_vulns = db.query(func.count(Vulnerability.id)).join(
            ScanSession
        ).filter(ScanSession.target_id == target_id).scalar()
        
        critical_vulns = db.query(func.count(Vulnerability.id)).join(
            ScanSession
        ).filter(
            and_(
                ScanSession.target_id == target_id,
                Vulnerability.severity == 'critical'
            )
        ).scalar()
        
        # Recon statistics
        total_assets = db.query(func.count(ReconResult.id)).join(
            ScanSession
        ).filter(ScanSession.target_id == target_id).scalar()
        
        return {
            "target_id": target_id,
            "target_name": target.target_name,
            "scans": {
                "total": total_scans,
                "completed": completed_scans,
                "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0
            },
            "vulnerabilities": {
                "total": total_vulns,
                "critical": critical_vulns
            },
            "assets_discovered": total_assets,
            "scope": {
                "in_scope_urls": len(target.in_scope_urls),
                "out_of_scope_urls": len(target.out_of_scope_urls),
                "in_scope_assets": len(target.in_scope_assets),
                "out_of_scope_assets": len(target.out_of_scope_assets)
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics for target {target_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get target statistics"
        )

@router.patch("/{target_id}/activate")
async def activate_target(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Activate a target for scanning.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        target.is_active = True
        target.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Activated target: {target_id}")
        
        return {"message": "Target activated successfully"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error activating target {target_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate target"
        )

@router.patch("/{target_id}/deactivate")
async def deactivate_target(
    target_id: str = Path(..., description="Target ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Deactivate a target to prevent new scans.
    """
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            raise RecordNotFoundException("Target", target_id)
        
        target.is_active = False
        target.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Deactivated target: {target_id}")
        
        return {"message": "Target deactivated successfully"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deactivating target {target_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate target"
        )
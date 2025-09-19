"""
FastAPI router for reconnaissance endpoints
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from backend.core.database import get_db
from backend.api.schemas.reconnaissance import (
    ReconConfigSchema, ReconResultSchema, ReconStatisticsSchema,
    ReconResultCreate, ReconResultUpdate, ReconExportRequest
)
from backend.models import ScanSession, ReconResult as ReconResultModel, Target
from backend.services.recon_service import ReconService, ReconConfig
from backend.api.dependencies import get_current_user


router = APIRouter(prefix="/api/v1/reconnaissance", tags=["reconnaissance"])
recon_service = ReconService()


@router.post("/scan/{scan_session_id}/start")
async def start_reconnaissance(
    scan_session_id: UUID,
    config: ReconConfigSchema,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Start reconnaissance for a scan session"""
    
    # Verify scan session exists and user has access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    # Check if user owns this target
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Convert schema to config object
    recon_config = ReconConfig(
        passive_only=config.passive_only,
        max_subdomains=config.max_subdomains,
        max_endpoints=config.max_endpoints,
        port_scan_top_ports=config.port_scan_top_ports,
        enable_service_detection=config.enable_service_detection,
        enable_technology_detection=config.enable_technology_detection,
        enable_certificate_transparency=config.enable_certificate_transparency,
        enable_search_engines=config.enable_search_engines,
        enable_web_crawling=config.enable_web_crawling,
        crawl_depth=config.crawl_depth,
        wordlist_size=config.wordlist_size,
        timeout_seconds=config.timeout_seconds
    )
    
    # Start reconnaissance in background
    background_tasks.add_task(
        recon_service.run_reconnaissance_async.delay,
        str(scan_session_id),
        recon_config.__dict__
    )
    
    return {
        "message": "Reconnaissance started",
        "scan_session_id": str(scan_session_id),
        "config": config.dict()
    }


@router.get("/scan/{scan_session_id}/results", response_model=List[ReconResultSchema])
async def get_reconnaissance_results(
    scan_session_id: UUID,
    result_type: Optional[str] = Query(None, description="Filter by result type"),
    in_scope_only: bool = Query(True, description="Only return in-scope results"),
    limit: int = Query(100, le=1000, description="Maximum number of results"),
    offset: int = Query(0, description="Number of results to skip"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get reconnaissance results for a scan session"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get results from service
    results = await recon_service.get_reconnaissance_results(
        str(scan_session_id),
        result_type=result_type,
        in_scope_only=in_scope_only
    )
    
    # Apply pagination
    paginated_results = results[offset:offset + limit]
    
    return paginated_results


@router.get("/scan/{scan_session_id}/statistics", response_model=ReconStatisticsSchema)
async def get_reconnaissance_statistics(
    scan_session_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get reconnaissance statistics for a scan session"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get statistics from service
    stats = await recon_service.get_reconnaissance_statistics(str(scan_session_id))
    
    return stats


@router.get("/scan/{scan_session_id}/subdomains")
async def get_discovered_subdomains(
    scan_session_id: UUID,
    in_scope_only: bool = Query(True),
    with_ip_resolution: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get discovered subdomains with optional IP resolution"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get subdomain results
    results = await recon_service.get_reconnaissance_results(
        str(scan_session_id),
        result_type="subdomain",
        in_scope_only=in_scope_only
    )
    
    subdomains = []
    for result in results:
        subdomain_data = {
            "subdomain": result["discovered_asset"],
            "ip_address": result["ip_address"],
            "discovered_by": result["discovered_by_tool"],
            "discovery_method": result["discovery_method"],
            "confidence_score": result["confidence_score"],
            "discovered_at": result["discovered_at"],
            "is_in_scope": result["is_in_scope"]
        }
        
        if with_ip_resolution and not result["ip_address"]:
            # Resolve IP if not already resolved
            try:
                import socket
                ip = socket.gethostbyname(result["discovered_asset"])
                subdomain_data["ip_address"] = ip
            except socket.gaierror:
                subdomain_data["ip_address"] = None
        
        subdomains.append(subdomain_data)
    
    return {
        "total_subdomains": len(subdomains),
        "in_scope_count": len([s for s in subdomains if s["is_in_scope"]]),
        "subdomains": subdomains
    }


@router.get("/scan/{scan_session_id}/endpoints")
async def get_discovered_endpoints(
    scan_session_id: UUID,
    in_scope_only: bool = Query(True),
    endpoint_type: Optional[str] = Query(None, description="Filter by endpoint type (api, web, etc.)"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get discovered endpoints"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get endpoint results
    results = await recon_service.get_reconnaissance_results(
        str(scan_session_id),
        result_type="endpoint",
        in_scope_only=in_scope_only
    )
    
    endpoints = []
    for result in results:
        endpoint_data = {
            "url": result["discovered_asset"],
            "discovery_method": result["discovery_method"],
            "discovered_by": result["discovered_by_tool"],
            "confidence_score": result["confidence_score"],
            "discovered_at": result["discovered_at"],
            "additional_info": result["additional_info"],
            "is_in_scope": result["is_in_scope"]
        }
        
        # Filter by endpoint type if specified
        if endpoint_type:
            api_type = result["additional_info"].get("api_type", "").lower()
            if endpoint_type.lower() not in api_type:
                continue
        
        endpoints.append(endpoint_data)
    
    return {
        "total_endpoints": len(endpoints),
        "endpoints": endpoints
    }


@router.get("/scan/{scan_session_id}/services")
async def get_discovered_services(
    scan_session_id: UUID,
    in_scope_only: bool = Query(True),
    service_type: Optional[str] = Query(None, description="Filter by service type"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get discovered services"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get service results
    results = await recon_service.get_reconnaissance_results(
        str(scan_session_id),
        result_type="service",
        in_scope_only=in_scope_only
    )
    
    services = []
    for result in results:
        service_data = {
            "host": result["ip_address"],
            "port": result["port"],
            "service_name": result["service_name"],
            "service_version": result["service_version"],
            "discovered_by": result["discovered_by_tool"],
            "discovery_method": result["discovery_method"],
            "confidence_score": result["confidence_score"],
            "discovered_at": result["discovered_at"],
            "additional_info": result["additional_info"],
            "is_in_scope": result["is_in_scope"]
        }
        
        # Filter by service type if specified
        if service_type:
            if service_type.lower() not in (result["service_name"] or "").lower():
                continue
        
        services.append(service_data)
    
    return {
        "total_services": len(services),
        "services": services
    }


@router.get("/scan/{scan_session_id}/technologies")
async def get_discovered_technologies(
    scan_session_id: UUID,
    in_scope_only: bool = Query(True),
    technology_type: Optional[str] = Query(None, description="Filter by technology type"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get discovered technologies"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get technology results
    results = await recon_service.get_reconnaissance_results(
        str(scan_session_id),
        result_type="technology",
        in_scope_only=in_scope_only
    )
    
    technologies = {}
    for result in results:
        url = result["discovered_asset"]
        if url not in technologies:
            technologies[url] = {
                "url": url,
                "technologies": [],
                "discovered_at": result["discovered_at"],
                "is_in_scope": result["is_in_scope"]
            }
        
        for tech in result["technologies"]:
            if technology_type and technology_type.lower() not in tech.lower():
                continue
            
            tech_info = {
                "name": tech,
                "version": result["additional_info"].get("version"),
                "confidence": result["confidence_score"],
                "detection_method": result["additional_info"].get("detection_method"),
                "evidence": result["additional_info"].get("evidence")
            }
            
            technologies[url]["technologies"].append(tech_info)
    
    return {
        "total_urls": len(technologies),
        "technologies": list(technologies.values())
    }


@router.post("/scan/{scan_session_id}/export")
async def export_reconnaissance_results(
    scan_session_id: UUID,
    export_request: ReconExportRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Export reconnaissance results"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Export results
    try:
        exported_data = await recon_service.export_reconnaissance_results(
            str(scan_session_id),
            format=export_request.format
        )
        
        # Determine content type and filename
        if export_request.format.lower() == "json":
            content_type = "application/json"
            filename = f"recon_results_{scan_session_id}.json"
        elif export_request.format.lower() == "csv":
            content_type = "text/csv"
            filename = f"recon_results_{scan_session_id}.csv"
        else:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
        # Create streaming response
        def iter_data():
            yield exported_data
        
        return StreamingResponse(
            io.StringIO(exported_data),
            media_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.put("/result/{result_id}", response_model=ReconResultSchema)
async def update_reconnaissance_result(
    result_id: UUID,
    update_data: ReconResultUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update a reconnaissance result (e.g., manually verify scope)"""
    
    # Get result
    result = db.query(ReconResultModel).filter(
        ReconResultModel.id == result_id
    ).first()
    
    if not result:
        raise HTTPException(status_code=404, detail="Reconnaissance result not found")
    
    # Verify access
    if result.scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update fields
    if update_data.is_in_scope is not None:
        result.is_in_scope = update_data.is_in_scope
    
    if update_data.scope_validation_reason is not None:
        result.scope_validation_reason = update_data.scope_validation_reason
    
    if update_data.confidence_score is not None:
        result.confidence_score = update_data.confidence_score
    
    if update_data.additional_info is not None:
        result.additional_info.update(update_data.additional_info)
    
    db.commit()
    db.refresh(result)
    
    # Convert to response format
    return {
        "id": str(result.id),
        "result_type": result.result_type,
        "discovered_asset": result.discovered_asset,
        "ip_address": result.ip_address,
        "port": result.port,
        "service_name": result.service_name,
        "service_version": result.service_version,
        "technologies": result.technologies,
        "discovered_by_tool": result.discovered_by_tool,
        "discovery_method": result.discovery_method,
        "confidence_score": result.confidence_score,
        "is_in_scope": result.is_in_scope,
        "scope_validation_reason": result.scope_validation_reason,
        "discovered_at": result.discovered_at.isoformat(),
        "additional_info": result.additional_info
    }


@router.delete("/result/{result_id}")
async def delete_reconnaissance_result(
    result_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a reconnaissance result"""
    
    # Get result
    result = db.query(ReconResultModel).filter(
        ReconResultModel.id == result_id
    ).first()
    
    if not result:
        raise HTTPException(status_code=404, detail="Reconnaissance result not found")
    
    # Verify access
    if result.scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Delete result
    db.delete(result)
    db.commit()
    
    return {"message": "Reconnaissance result deleted"}


@router.get("/scan/{scan_session_id}/status")
async def get_reconnaissance_status(
    scan_session_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get current reconnaissance status"""
    
    # Verify access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {
        "scan_session_id": str(scan_session_id),
        "status": scan_session.status.value,
        "current_phase": scan_session.current_phase,
        "phase_progress": scan_session.phase_progress,
        "total_progress": scan_session.total_progress,
        "total_subdomains_found": scan_session.total_subdomains_found,
        "total_endpoints_found": scan_session.total_endpoints_found,
        "started_at": scan_session.started_at.isoformat() if scan_session.started_at else None,
        "estimated_completion": scan_session.estimated_completion.isoformat() if scan_session.estimated_completion else None
    }
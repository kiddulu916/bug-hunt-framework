"""
FastAPI router for callback server endpoints
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.api.schemas.callbacks import (
    CallbackServerConfigSchema, CallbackStatusSchema, CallbackStatisticsSchema,
    CallbackPayloadGenerateRequest, CallbackPayloadResponse, CallbackDetailsSchema,
    CallbackListResponse, CallbackServerStatusSchema
)
from backend.models import Vulnerability, ScanSession, Target
from backend.services.callback_server import callback_service, CallbackType
from backend.api.dependencies import get_current_user


router = APIRouter(prefix="/api/v1/callbacks", tags=["callbacks"])


@router.post("/server/start")
async def start_callback_server(
    config: CallbackServerConfigSchema,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Start the callback server with specified configuration"""
    
    # Only allow admin users to start/stop callback server
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        # Start callback servers
        background_tasks.add_task(
            callback_service.start_servers,
            config.dict()
        )
        
        return {
            "message": "Callback server startup initiated",
            "config": config.dict()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start callback server: {str(e)}")


@router.get("/server/status", response_model=CallbackServerStatusSchema)
async def get_callback_server_status(
    current_user: dict = Depends(get_current_user)
):
    """Get callback server status"""
    
    try:
        # Get server health status
        active_callbacks_count = len(callback_service.active_callbacks)
        
        return {
            "status": "running" if callback_service.http_server else "stopped",
            "base_domain": callback_service.base_domain,
            "http_port": callback_service.http_port,
            "dns_port": callback_service.dns_port,
            "active_callbacks": active_callbacks_count,
            "shell_listeners": len(callback_service.shell_handler.shell_servers),
            "uptime_seconds": 0,  # Calculate actual uptime
            "last_callback": None  # Get from database
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get server status: {str(e)}")


@router.post("/generate", response_model=CallbackPayloadResponse)
async def generate_callback_payloads(
    request: CallbackPayloadGenerateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Generate callback payloads for a vulnerability"""
    
    # Verify vulnerability exists and user has access
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == request.vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Check if user owns this target
    if vulnerability.scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        # Generate callback payloads
        payloads = callback_service.generate_callback_payloads(
            vulnerability_id=str(request.vulnerability_id),
            vuln_type=request.vulnerability_type or vulnerability.vulnerability_type,
            affected_url=vulnerability.affected_url,
            parameter=vulnerability.affected_parameter or ""
        )
        
        return payloads
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payload generation failed: {str(e)}")


@router.get("/status/{callback_id}", response_model=CallbackStatusSchema)
async def get_callback_status(
    callback_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get status of a specific callback"""
    
    try:
        callback_status = await callback_service.get_callback_status(callback_id)
        
        if not callback_status:
            raise HTTPException(status_code=404, detail="Callback not found")
        
        # Verify user has access to this callback
        if callback_status.get('vulnerability_id'):
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == callback_status['vulnerability_id']
            ).first()
            
            if vulnerability and vulnerability.scan_session.target.researcher_username != current_user["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
        
        return callback_status
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get callback status: {str(e)}")


@router.get("/list", response_model=CallbackListResponse)
async def list_callbacks(
    vulnerability_id: Optional[UUID] = Query(None, description="Filter by vulnerability ID"),
    scan_session_id: Optional[UUID] = Query(None, description="Filter by scan session ID"),
    callback_type: Optional[str] = Query(None, description="Filter by callback type"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, le=500, description="Maximum number of results"),
    offset: int = Query(0, description="Number of results to skip"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List callbacks with filtering options"""
    
    try:
        # Verify access to vulnerability/scan session if specified
        if vulnerability_id:
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == vulnerability_id
            ).first()
            
            if not vulnerability:
                raise HTTPException(status_code=404, detail="Vulnerability not found")
            
            if vulnerability.scan_session.target.researcher_username != current_user["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
        
        if scan_session_id:
            scan_session = db.query(ScanSession).filter(
                ScanSession.id == scan_session_id
            ).first()
            
            if not scan_session:
                raise HTTPException(status_code=404, detail="Scan session not found")
            
            if scan_session.target.researcher_username != current_user["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Get callbacks - for now, get all active callbacks
        # In production, you'd filter by user's accessible callbacks
        callbacks = await callback_service.get_active_callbacks(
            vulnerability_id=str(vulnerability_id) if vulnerability_id else None,
            scan_session_id=str(scan_session_id) if scan_session_id else None
        )
        
        # Apply additional filters
        if callback_type:
            callbacks = [cb for cb in callbacks if cb['callback_type'] == callback_type]
        
        if status:
            callbacks = [cb for cb in callbacks if cb['status'] == status]
        
        # Apply pagination
        total_count = len(callbacks)
        paginated_callbacks = callbacks[offset:offset + limit]
        
        return {
            "callbacks": paginated_callbacks,
            "total_count": total_count,
            "page_info": {
                "limit": limit,
                "offset": offset,
                "has_more": total_count > offset + limit
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list callbacks: {str(e)}")


@router.get("/details/{callback_id}", response_model=CallbackDetailsSchema)
async def get_callback_details(
    callback_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get detailed information about a callback"""
    
    try:
        callback_status = await callback_service.get_callback_status(callback_id)
        
        if not callback_status:
            raise HTTPException(status_code=404, detail="Callback not found")
        
        # Verify user has access to this callback
        if callback_status.get('vulnerability_id'):
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == callback_status['vulnerability_id']
            ).first()
            
            if vulnerability and vulnerability.scan_session.target.researcher_username != current_user["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Enhance with additional details
        enhanced_details = callback_status.copy()
        
        # Add vulnerability context if available
        if callback_status.get('vulnerability_id'):
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == callback_status['vulnerability_id']
            ).first()
            
            if vulnerability:
                enhanced_details['vulnerability_context'] = {
                    'vulnerability_name': vulnerability.vulnerability_name,
                    'vulnerability_type': vulnerability.vulnerability_type,
                    'severity': vulnerability.severity.value,
                    'affected_url': vulnerability.affected_url,
                    'target_name': vulnerability.scan_session.target.target_name
                }
        
        return enhanced_details
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get callback details: {str(e)}")


@router.get("/statistics", response_model=CallbackStatisticsSchema)
async def get_callback_statistics(
    timeframe_days: int = Query(30, ge=1, le=365, description="Statistics timeframe in days"),
    current_user: dict = Depends(get_current_user)
):
    """Get callback statistics"""
    
    try:
        stats = await callback_service.get_callback_statistics(timeframe_days)
        return stats
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@router.delete("/{callback_id}")
async def delete_callback(
    callback_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a callback and clean up associated resources"""
    
    try:
        # Verify callback exists and user has access
        callback_status = await callback_service.get_callback_status(callback_id)
        
        if not callback_status:
            raise HTTPException(status_code=404, detail="Callback not found")
        
        # Verify user has access to this callback
        if callback_status.get('vulnerability_id'):
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == callback_status['vulnerability_id']
            ).first()
            
            if vulnerability and vulnerability.scan_session.target.researcher_username != current_user["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Delete callback
        success = await callback_service.delete_callback(callback_id)
        
        if success:
            return {"message": f"Callback {callback_id} deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete callback")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Callback deletion failed: {str(e)}")


@router.get("/types")
async def get_callback_types():
    """Get available callback types"""
    
    return {
        "callback_types": [
            {
                "type": callback_type.value,
                "description": callback_type.value.replace('_', ' ').title(),
                "use_cases": _get_callback_type_use_cases(callback_type)
            }
            for callback_type in CallbackType
        ]
    }


@router.post("/test/{callback_id}")
async def test_callback(
    callback_id: str,
    test_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Test a callback endpoint with sample data"""
    
    try:
        # Verify callback exists and user has access
        callback_status = await callback_service.get_callback_status(callback_id)
        
        if not callback_status:
            raise HTTPException(status_code=404, detail="Callback not found")
        
        # Verify user has access to this callback
        if callback_status.get('vulnerability_id'):
            vulnerability = db.query(Vulnerability).filter(
                Vulnerability.id == callback_status['vulnerability_id']
            ).first()
            
            if vulnerability and vulnerability.scan_session.target.researcher_username != current_user["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Process test callback
        await callback_service.process_callback(
            callback_id=callback_id,
            callback_type=CallbackType.HTTP_REQUEST,
            source_ip=test_data.get('source_ip', '127.0.0.1'),
            headers=test_data.get('headers', {'User-Agent': 'Test-Agent'}),
            request_data=str(test_data.get('data', 'test_callback_data')),
            user_agent=test_data.get('user_agent', 'Test-Agent'),
            additional_data={
                'test_mode': True,
                'test_timestamp': test_data.get('timestamp')
            }
        )
        
        return {
            "message": "Test callback processed successfully",
            "callback_id": callback_id,
            "test_data": test_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Callback test failed: {str(e)}")


@router.get("/vulnerability/{vulnerability_id}/callbacks")
async def get_vulnerability_callbacks(
    vulnerability_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all callbacks associated with a specific vulnerability"""
    
    # Verify vulnerability exists and user has access
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if vulnerability.scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        callbacks = await callback_service.get_active_callbacks(
            vulnerability_id=str(vulnerability_id)
        )
        
        return {
            "vulnerability_id": str(vulnerability_id),
            "vulnerability_name": vulnerability.vulnerability_name,
            "vulnerability_type": vulnerability.vulnerability_type,
            "callbacks": callbacks,
            "total_callbacks": len(callbacks)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerability callbacks: {str(e)}")


@router.post("/vulnerability/{vulnerability_id}/generate-all")
async def generate_all_callback_payloads(
    vulnerability_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Generate all appropriate callback payloads for a vulnerability"""
    
    # Verify vulnerability exists and user has access
    vulnerability = db.query(Vulnerability).filter(
        Vulnerability.id == vulnerability_id
    ).first()
    
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if vulnerability.scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        # Generate callback payloads
        payloads = callback_service.generate_callback_payloads(
            vulnerability_id=str(vulnerability_id),
            vuln_type=vulnerability.vulnerability_type,
            affected_url=vulnerability.affected_url,
            parameter=vulnerability.affected_parameter or ""
        )
        
        return {
            "vulnerability_id": str(vulnerability_id),
            "vulnerability_type": vulnerability.vulnerability_type,
            "payloads_generated": payloads,
            "callback_info": {
                "callback_id": payloads['callback_id'],
                "callback_domain": payloads['callback_domain'],
                "callback_url": payloads['callback_url'],
                "total_payloads": len(payloads['payloads'])
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payload generation failed: {str(e)}")


@router.get("/scan/{scan_session_id}/callbacks")
async def get_scan_callbacks(
    scan_session_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all callbacks associated with a specific scan session"""
    
    # Verify scan session exists and user has access
    scan_session = db.query(ScanSession).filter(
        ScanSession.id == scan_session_id
    ).first()
    
    if not scan_session:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    if scan_session.target.researcher_username != current_user["username"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        callbacks = await callback_service.get_active_callbacks(
            scan_session_id=str(scan_session_id)
        )
        
        # Group callbacks by type
        callbacks_by_type = {}
        for callback in callbacks:
            callback_type = callback['callback_type']
            if callback_type not in callbacks_by_type:
                callbacks_by_type[callback_type] = []
            callbacks_by_type[callback_type].append(callback)
        
        return {
            "scan_session_id": str(scan_session_id),
            "target_name": scan_session.target.target_name,
            "total_callbacks": len(callbacks),
            "callbacks_by_type": callbacks_by_type,
            "callbacks": callbacks
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan callbacks: {str(e)}")


@router.get("/real-time/stream")
async def callback_real_time_stream(
    current_user: dict = Depends(get_current_user)
):
    """Server-sent events stream for real-time callback updates"""
    
    async def event_stream():
        """Generate server-sent events for callback updates"""
        while True:
            try:
                # In a real implementation, you would yield callback updates
                # For now, we'll just send periodic status updates
                import json
                
                stats = await callback_service.get_callback_statistics(1)  # Last 24 hours
                
                event_data = {
                    "type": "callback_stats",
                    "data": stats,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                yield f"data: {json.dumps(event_data)}\n\n"
                await asyncio.sleep(10)  # Update every 10 seconds
                
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break
    
    from fastapi.responses import StreamingResponse
    return StreamingResponse(event_stream(), media_type="text/plain")


@router.post("/bulk-generate")
async def bulk_generate_callbacks(
    request: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Generate callbacks for multiple vulnerabilities at once"""
    
    vulnerability_ids = request.get('vulnerability_ids', [])
    if not vulnerability_ids:
        raise HTTPException(status_code=400, detail="vulnerability_ids required")
    
    # Verify all vulnerabilities exist and user has access
    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.id.in_(vulnerability_ids)
    ).all()
    
    if len(vulnerabilities) != len(vulnerability_ids):
        raise HTTPException(status_code=404, detail="Some vulnerabilities not found")
    
    # Check access to all vulnerabilities
    for vuln in vulnerabilities:
        if vuln.scan_session.target.researcher_username != current_user["username"]:
            raise HTTPException(status_code=403, detail="Access denied to one or more vulnerabilities")
    
    try:
        results = []
        
        for vulnerability in vulnerabilities:
            try:
                payloads = callback_service.generate_callback_payloads(
                    vulnerability_id=str(vulnerability.id),
                    vuln_type=vulnerability.vulnerability_type,
                    affected_url=vulnerability.affected_url,
                    parameter=vulnerability.affected_parameter or ""
                )
                
                results.append({
                    "vulnerability_id": str(vulnerability.id),
                    "success": True,
                    "callback_id": payloads['callback_id'],
                    "payloads_count": len(payloads['payloads'])
                })
                
            except Exception as e:
                results.append({
                    "vulnerability_id": str(vulnerability.id),
                    "success": False,
                    "error": str(e)
                })
        
        successful_count = len([r for r in results if r['success']])
        
        return {
            "message": f"Generated callbacks for {successful_count}/{len(vulnerabilities)} vulnerabilities",
            "results": results,
            "total_processed": len(vulnerabilities),
            "successful": successful_count,
            "failed": len(vulnerabilities) - successful_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk callback generation failed: {str(e)}")


def _get_callback_type_use_cases(callback_type: CallbackType) -> List[str]:
    """Get use cases for a callback type"""
    use_cases = {
        CallbackType.HTTP_REQUEST: [
            "SSRF detection",
            "XXE exploitation", 
            "File inclusion vulnerabilities",
            "Template injection"
        ],
        CallbackType.DNS_QUERY: [
            "Blind SSRF detection",
            "DNS exfiltration",
            "Out-of-band data extraction"
        ],
        CallbackType.REVERSE_SHELL: [
            "Command injection exploitation",
            "Remote code execution",
            "File upload exploitation"
        ],
        CallbackType.BLIND_XSS: [
            "Stored XSS detection",
            "DOM-based XSS",
            "CSP bypass testing"
        ],
        CallbackType.SSRF: [
            "Server-side request forgery",
            "Internal network scanning",
            "Cloud metadata access"
        ],
        CallbackType.XXE: [
            "XML external entity injection",
            "File system access",
            "Internal network reconnaissance"
        ]
    }
    
    return use_cases.get(callback_type, ["General vulnerability exploitation"])
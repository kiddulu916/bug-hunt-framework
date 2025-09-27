"""
FastAPI router for vulnerability management endpoints.
Handles CRUD operations and analysis for vulnerabilities.
"""

from typing import List, Optional, Dict, Any
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    Path,
    File,
    UploadFile,
)
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc
import logging
from datetime import datetime

from api.dependencies.database import get_db
from api.dependencies.auth import get_current_user, require_permissions
from api.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnerabilityResponse,
    VulnerabilityListResponse,
    VulnerabilityAnalysis,
    BulkVulnerabilityOperation,
    VulnerabilityExport,
    VulnerabilityFilter,
    VulnerabilityQueryFilters,
)
from apps.vulnerabilities.models import Vulnerability, VulnSeverity, ExploitationChain
from core.pagination import VulnerabilityFastAPIPagination
from core.exceptions import RecordNotFoundException, InvalidDataException
from services.vulnerability_services.analyzer import VulnerabilityAnalyzer
from services.vulnerability_services.cvss import CVSSCalculator
from services.vulnerability_services.evidence import EvidenceHandler
from core.constants import VULNERABILITY_TYPES, OWASP_TOP_10_2021

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize services
vulnerability_analyzer = VulnerabilityAnalyzer()
cvss_calculator = CVSSCalculator()
evidence_handler = EvidenceHandler()


@router.get("/", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    filters: VulnerabilityQueryFilters = Depends(),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get list of vulnerabilities with filtering, searching, and pagination.
    """
    try:
        # Build query
        query = db.query(Vulnerability)

        # Apply filters
        if filters.severity:
            try:
                severity_enum = VulnSeverity(filters.severity.lower())
                query = query.filter(Vulnerability.severity == severity_enum)
            except ValueError:
                raise InvalidDataException(
                    "severity", filters.severity, "Invalid severity value"
                )

        if filters.vulnerability_type:
            query = query.filter(
                Vulnerability.vulnerability_type == filters.vulnerability_type
            )

        if filters.status:
            if filters.status == "verified":
                query = query.filter(Vulnerability.manually_verified == True)
            elif filters.status == "unverified":
                query = query.filter(Vulnerability.manually_verified == False)

        if filters.target_id:
            query = query.join(Vulnerability.scan_session).filter(
                Vulnerability.scan_session.has(target_id=filters.target_id)
            )

        if filters.scan_session_id:
            query = query.filter(
                Vulnerability.scan_session_id == filters.scan_session_id
            )

        if filters.search:
            search_filter = or_(
                Vulnerability.vulnerability_name.ilike(f"%{filters.search}%"),
                Vulnerability.impact_description.ilike(f"%{filters.search}%"),
                Vulnerability.affected_url.ilike(f"%{filters.search}%"),
            )
            query = query.filter(search_filter)

        # Apply sorting
        sort_field = getattr(
            Vulnerability, filters.sort_by, Vulnerability.discovered_at
        )
        if filters.sort_order == "desc":
            query = query.order_by(desc(sort_field))
        else:
            query = query.order_by(asc(sort_field))

        # Apply pagination
        pagination = VulnerabilityFastAPIPagination(filters.page, filters.page_size)
        result = pagination.paginate_vulnerabilities(query, filters.severity)

        return VulnerabilityListResponse(
            vulnerabilities=[
                VulnerabilityResponse.from_orm(vuln) for vuln in result["items"]
            ],
            pagination=result["pagination"],
            severity_counts=result.get("severity_counts", {}),
            applied_filters=result.get("applied_filters", {}),
        )

    except Exception as e:
        logger.error("Error listing vulnerabilities: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve vulnerabilities",
        )


@router.post(
    "/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED
)
async def create_vulnerability(
    vulnerability_data: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new vulnerability.
    """
    try:
        # Validate vulnerability data
        if vulnerability_data.vulnerability_type not in VULNERABILITY_TYPES:
            raise InvalidDataException(
                "vulnerability_type",
                vulnerability_data.vulnerability_type,
                f"Must be one of: {', '.join(VULNERABILITY_TYPES)}",
            )

        # Calculate CVSS score if not provided
        if not vulnerability_data.cvss_score and vulnerability_data.severity:
            vulnerability_data.cvss_score = cvss_calculator.calculate_base_score(
                vulnerability_data.severity.value, vulnerability_data.vulnerability_type
            )

        # Create vulnerability instance
        db_vulnerability = Vulnerability(**vulnerability_data.dict())

        # Run initial analysis
        analysis = vulnerability_analyzer.analyze_vulnerability(db_vulnerability)
        if analysis.get("confidence_adjustment"):
            db_vulnerability.confidence_level = analysis["confidence_adjustment"]

        db.add(db_vulnerability)
        db.commit()
        db.refresh(db_vulnerability)

        logger.info("Created vulnerability: %s", db_vulnerability.id)

        return VulnerabilityResponse.from_orm(db_vulnerability)

    except Exception as e:
        db.rollback()
        logger.error("Error creating vulnerability: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create vulnerability",
        )


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get a specific vulnerability by ID.
    """
    vulnerability = (
        db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    )

    if not vulnerability:
        raise RecordNotFoundException("Vulnerability", vulnerability_id)

    return VulnerabilityResponse.from_orm(vulnerability)


@router.put("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vulnerability_data: VulnerabilityUpdate,
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Update an existing vulnerability.
    """
    try:
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            raise RecordNotFoundException("Vulnerability", vulnerability_id)

        # Update fields
        update_data = vulnerability_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(vulnerability, field, value)

        vulnerability.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(vulnerability)

        logger.info("Updated vulnerability: %s", vulnerability_id)

        return VulnerabilityResponse.from_orm(vulnerability)

    except Exception as e:
        db.rollback()
        logger.error("Error updating vulnerability {vulnerability_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update vulnerability",
        )


@router.delete("/{vulnerability_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vulnerability(
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_permissions(["admin", "delete_vulnerability"])
    ),
):
    """
    Delete a vulnerability (admin only).
    """
    try:
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            raise RecordNotFoundException("Vulnerability", vulnerability_id)

        db.delete(vulnerability)
        db.commit()

        logger.info("Deleted vulnerability: %s", vulnerability_id)

    except Exception as e:
        db.rollback()
        logger.error("Error deleting vulnerability {vulnerability_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete vulnerability",
        )


@router.post("/{vulnerability_id}/analyze", response_model=VulnerabilityAnalysis)
async def analyze_vulnerability(
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Perform detailed analysis on a vulnerability.
    """
    try:
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            raise RecordNotFoundException("Vulnerability", vulnerability_id)

        # Run comprehensive analysis
        analysis = vulnerability_analyzer.comprehensive_analysis(vulnerability)

        return VulnerabilityAnalysis(**analysis)

    except Exception as e:
        logger.error("Error analyzing vulnerability {vulnerability_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze vulnerability",
        )


@router.post("/{vulnerability_id}/verify")
async def verify_vulnerability(
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    verification_notes: str = Query(..., description="Verification notes"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions(["verify_vulnerability"])),
):
    """
    Manually verify a vulnerability.
    """
    try:
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            raise RecordNotFoundException("Vulnerability", vulnerability_id)

        vulnerability.manually_verified = True
        vulnerability.verification_notes = verification_notes
        vulnerability.updated_at = datetime.utcnow()

        db.commit()

        logger.info("Verified vulnerability: %s", vulnerability_id)

        return {"message": "Vulnerability verified successfully"}

    except Exception as e:
        db.rollback()
        logger.error("Error verifying vulnerability {vulnerability_id}: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify vulnerability",
        )


@router.post("/{vulnerability_id}/evidence")
async def upload_evidence(
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    files: List[UploadFile] = File(..., description="Evidence files"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload evidence files for a vulnerability.
    """
    try:
        vulnerability = (
            db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
        )

        if not vulnerability:
            raise RecordNotFoundException("Vulnerability", vulnerability_id)

        evidence_paths = []
        for file in files:
            file_path = await evidence_handler.save_evidence_file(
                file, vulnerability_id
            )
            evidence_paths.append(file_path)

        # Update vulnerability with evidence paths
        existing_paths = vulnerability.screenshot_paths or []
        vulnerability.screenshot_paths = existing_paths + evidence_paths
        vulnerability.updated_at = datetime.utcnow()

        db.commit()

        logger.info("Uploaded evidence for vulnerability: %s", vulnerability_id)

        return {
            "message": "Evidence uploaded successfully",
            "files_uploaded": len(files),
            "evidence_paths": evidence_paths,
        }

    except Exception as e:
        db.rollback()
        logger.error(
            "Error uploading evidence for vulnerability {vulnerability_id}: %s", e
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload evidence",
        )


@router.get("/{vulnerability_id}/exploitation-chains")
async def get_exploitation_chains(
    vulnerability_id: str = Path(..., description="Vulnerability ID"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get exploitation chains for a vulnerability.
    """
    vulnerability = (
        db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    )

    if not vulnerability:
        raise RecordNotFoundException("Vulnerability", vulnerability_id)

    chains = (
        db.query(ExploitationChain)
        .filter(ExploitationChain.vulnerability_id == vulnerability_id)
        .order_by(ExploitationChain.step_number)
        .all()
    )

    return {"exploitation_chains": chains}


@router.post("/bulk-operations", response_model=Dict[str, Any])
async def bulk_vulnerability_operations(
    operation: BulkVulnerabilityOperation,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permissions(["bulk_operations"])),
):
    """
    Perform bulk operations on multiple vulnerabilities.
    """
    try:
        query = db.query(Vulnerability).filter(
            Vulnerability.id.in_(operation.vulnerability_ids)
        )

        vulnerabilities = query.all()

        if len(vulnerabilities) != len(operation.vulnerability_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Some vulnerability IDs were not found",
            )

        results = {"processed": 0, "errors": []}

        if operation.operation == "verify":
            for vuln in vulnerabilities:
                try:
                    vuln.manually_verified = True
                    vuln.verification_notes = operation.data.get(
                        "notes", "Bulk verified"
                    )
                    vuln.updated_at = datetime.utcnow()
                    results["processed"] += 1
                except Exception as e:
                    results["errors"].append(f"Error verifying {vuln.id}: {str(e)}")

        elif operation.operation == "update_severity":
            new_severity = VulnSeverity(operation.data.get("severity"))
            for vuln in vulnerabilities:
                try:
                    vuln.severity = new_severity
                    vuln.updated_at = datetime.utcnow()
                    results["processed"] += 1
                except Exception as e:
                    results["errors"].append(f"Error updating {vuln.id}: {str(e)}")

        elif operation.operation == "delete":
            for vuln in vulnerabilities:
                try:
                    db.delete(vuln)
                    results["processed"] += 1
                except Exception as e:
                    results["errors"].append(f"Error deleting {vuln.id}: {str(e)}")

        db.commit()

        logger.info(
            "Bulk operation {operation.operation} processed %s vulnerabilities",
            results["processed"],
        )

        return results

    except Exception as e:
        db.rollback()
        logger.error("Error in bulk vulnerability operation: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk operation",
        )


@router.get("/export/{format}")
async def export_vulnerabilities(
    format: str = Path(..., pattern="^(csv|json|xml|pdf)$", description="Export format"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    verified_only: bool = Query(
        False, description="Export only verified vulnerabilities"
    ),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Export vulnerabilities in various formats.
    """
    try:
        # Build query with filters
        query = db.query(Vulnerability)

        if severity:
            severity_enum = VulnSeverity(severity.lower())
            query = query.filter(Vulnerability.severity == severity_enum)

        if verified_only:
            query = query.filter(Vulnerability.manually_verified == True)

        vulnerabilities = query.all()

        # Generate export file
        from services.reporting_service import ReportingService

        reporting_service = ReportingService()

        export_data = VulnerabilityExport(
            vulnerabilities=[
                VulnerabilityResponse.from_orm(v) for v in vulnerabilities
            ],
            export_format=format,
            filters={"severity": severity, "verified_only": verified_only},
            generated_at=datetime.utcnow(),
            generated_by=current_user.get("username", "unknown"),
        )

        file_path = await reporting_service.export_vulnerabilities(export_data)

        return FileResponse(
            path=file_path,
            filename=f"vulnerabilities_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format}",
            media_type=f"application/{format}",
        )

    except Exception as e:
        logger.error("Error exporting vulnerabilities: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export vulnerabilities",
        )


@router.get("/statistics/summary")
async def get_vulnerability_statistics(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """
    Get vulnerability statistics and summary.
    """
    try:
        from sqlalchemy import func

        # Total vulnerabilities
        total = db.query(func.count(Vulnerability.id)).scalar()

        # Severity breakdown
        severity_stats = (
            db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity)
            .all()
        )

        # Verification status
        verified = (
            db.query(func.count(Vulnerability.id))
            .filter(Vulnerability.manually_verified == True)
            .scalar()
        )

        # Top vulnerability types
        type_stats = (
            db.query(Vulnerability.vulnerability_type, func.count(Vulnerability.id))
            .group_by(Vulnerability.vulnerability_type)
            .order_by(func.count(Vulnerability.id).desc())
            .limit(10)
            .all()
        )

        # OWASP Top 10 distribution
        owasp_stats = (
            db.query(Vulnerability.owasp_category, func.count(Vulnerability.id))
            .group_by(Vulnerability.owasp_category)
            .all()
        )

        # Recent discoveries (last 30 days)
        from datetime import timedelta

        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent = (
            db.query(func.count(Vulnerability.id))
            .filter(Vulnerability.discovered_at >= thirty_days_ago)
            .scalar()
        )

        return {
            "total_vulnerabilities": total,
            "verified_vulnerabilities": verified,
            "unverified_vulnerabilities": total - verified,
            "recent_discoveries": recent,
            "severity_distribution": {
                severity.value: count for severity, count in severity_stats
            },
            "top_vulnerability_types": [
                {"type": vtype, "count": count} for vtype, count in type_stats
            ],
            "owasp_distribution": {
                category: count for category, count in owasp_stats if category
            },
        }

    except Exception as e:
        logger.error("Error getting vulnerability statistics: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get vulnerability statistics",
        )


@router.get("/statistics/trends")
async def get_vulnerability_trends(
    days: int = Query(
        30, ge=7, le=365, description="Number of days for trend analysis"
    ),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get vulnerability discovery trends over time.
    """
    try:
        from sqlalchemy import func, text
        from datetime import timedelta

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Daily vulnerability discoveries
        daily_trends = (
            db.query(
                func.date(Vulnerability.discovered_at).label("date"),
                func.count(Vulnerability.id).label("count"),
            )
            .filter(Vulnerability.discovered_at >= start_date)
            .group_by(func.date(Vulnerability.discovered_at))
            .order_by("date")
            .all()
        )

        # Severity trends
        severity_trends = (
            db.query(
                func.date(Vulnerability.discovered_at).label("date"),
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count"),
            )
            .filter(Vulnerability.discovered_at >= start_date)
            .group_by(func.date(Vulnerability.discovered_at), Vulnerability.severity)
            .order_by("date")
            .all()
        )

        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days,
            },
            "daily_discoveries": [
                {"date": str(date), "count": count} for date, count in daily_trends
            ],
            "severity_trends": [
                {"date": str(date), "severity": severity.value, "count": count}
                for date, severity, count in severity_trends
            ],
        }

    except Exception as e:
        logger.error("Error getting vulnerability trends: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get vulnerability trends",
        )

"""
Services initialization.
This module imports and exposes all business logic services for the Bug Bounty Platform.
"""

# Import individual services
from .target_service import TargetService
from .scanning_service import ScanningService
from .reporting_service import ReportingService
from .vulnerability_scanner import VulnerabilityScanner
from .vulnerability_analyzer import VulnerabilityAnalyzer as AsyncVulnerabilityAnalyzer
from .recon_service import ReconService
from .exploitation_service import ExploitationService
from .notification_service import NotificationService
from .callback_server import CallbackService
from .scan_scheduler import ScanScheduler

# Import vulnerability services (Django-based)
from .vulnerability_services.analyzer import VulnerabilityAnalyzer
from .vulnerability_services.cvss import CVSSCalculator, CVSSMetric
from .vulnerability_services.evidence import EvidenceHandler

# Service metadata
__version__ = "1.0.0"
__title__ = "Bug Bounty Platform Services"
__description__ = "Business logic services for the Bug Bounty Automation Platform"

# Export all services
__all__ = [
    # Main services
    "TargetService",
    "ScanningService",
    "ReportingService",
    "VulnerabilityScanner",
    "AsyncVulnerabilityAnalyzer",
    "ReconService",
    "ExploitationService",
    "NotificationService",
    "CallbackService",
    "ScanScheduler",

    # Vulnerability services (Django-based)
    "VulnerabilityAnalyzer",
    "CVSSCalculator",
    "CVSSMetric",
    "EvidenceHandler",

    # Service metadata
    "__version__",
    "__title__",
    "__description__",
]

# Service registry for dependency injection
SERVICE_REGISTRY = {
    'target_service': TargetService,
    'scanning_service': ScanningService,
    'reporting_service': ReportingService,
    'vulnerability_scanner': VulnerabilityScanner,
    'async_vulnerability_analyzer': AsyncVulnerabilityAnalyzer,
    'recon_service': ReconService,
    'exploitation_service': ExploitationService,
    'notification_service': NotificationService,
    'callback_service': CallbackService,
    'scan_scheduler': ScanScheduler,
    'vulnerability_analyzer': VulnerabilityAnalyzer,
    'cvss_calculator': CVSSCalculator,
    'evidence_handler': EvidenceHandler,
}

def get_service(service_name: str):
    """
    Get service instance by name.
    
    Args:
        service_name: Name of the service
        
    Returns:
        Service instance
        
    Raises:
        KeyError: If service not found
    """
    if service_name not in SERVICE_REGISTRY:
        raise KeyError(f"Service '{service_name}' not found in registry")
    
    service_class = SERVICE_REGISTRY[service_name]
    return service_class()

def get_all_services():
    """
    Get all available services.
    
    Returns:
        dict: Dictionary of service name -> service instance
    """
    return {name: service_class() for name, service_class in SERVICE_REGISTRY.items()}

# Add utility functions to exports
__all__.extend([
    "SERVICE_REGISTRY",
    "get_service", 
    "get_all_services",
])
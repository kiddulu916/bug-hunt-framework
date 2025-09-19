"""
Scanner Engines Module for Bug Bounty Automation Platform
=========================================================

This module provides the core scanning engines and orchestration for automated
penetration testing and vulnerability discovery.

Main Components:
    - ReconEngine: Passive and active reconnaissance
    - VulnerabilityScanner: Automated vulnerability testing
    - ExploitationEngine: Vulnerability verification and exploitation
    - ReportGenerator: Automated report generation
    - ScanOrchestrator: Main orchestration and workflow management
"""

# Version information
__version__ = "1.0.0"
__author__ = "Bug Bounty Automation Platform"

# Import core engine classes
from .recon_engine import (
    ReconEngine,
    SubdomainEnumerator,
    PortScanner,
    ServiceIdentifier,
    TechnologyProfiler,
    AssetDiscovery,
)

from .vulnerability_scanner import (
    VulnerabilityScanner,
    NucleiScanner,
    BurpScanner,
    CustomVulnScanner,
    PayloadGenerator,
    FuzzingEngine,
)

from .exploitation_engine import (
    ExploitationEngine,
    ExploitChainBuilder,
    PayloadExecutor,
    ImpactAnalyzer,
    ProofOfConceptGenerator,
)

from .report_generator import (
    ReportGenerator,
    TechnicalReportBuilder,
    ExecutiveReportBuilder,
    BugBountyReportFormatter,
    PIIRedactor,
    EvidenceCollector,
)

from .scan_orchestrator import (
    ScanOrchestrator,
    ScanScheduler,
    WorkflowManager,
    ProgressTracker,
    RateLimiter,
)

# Import utility modules
from .utils import (
    ScopeValidator,
    RequestBuilder,
    ResponseParser,
    ToolExecutor,
    OutputParser,
    LogManager,
)

# Import tool integrations
from .tools import (
    AmassIntegration,
    SubfinderIntegration,
    NmapIntegration,
    MasscanIntegration,
    NucleiIntegration,
    FFUFIntegration,
    SQLMapIntegration,
    MetasploitIntegration,
    BurpSuiteAPI,
    ZAPIntegration,
)

# Import database interfaces
from .db_interfaces import (
    TargetManager,
    ScanSessionManager,
    VulnerabilityManager,
    ReconResultManager,
    ReportManager,
    ToolExecutionLogger,
)

# Import configuration management
from .config import (
    ScannerConfig,
    ToolConfig,
    RateLimitConfig,
    AuthenticationConfig,
    load_scanner_config,
    validate_config,
)

# Import monitoring and metrics
from .monitoring import (
    ScanMetrics,
    PerformanceMonitor,
    ErrorTracker,
    ProgressReporter,
    AlertManager,
)

# Define public API
__all__ = [
    # Version info
    "__version__",
    "__author__",
    
    # Core Engines
    "ReconEngine",
    "SubdomainEnumerator",
    "PortScanner",
    "ServiceIdentifier",
    "TechnologyProfiler",
    "AssetDiscovery",
    
    # Vulnerability Scanning
    "VulnerabilityScanner",
    "NucleiScanner",
    "BurpScanner",
    "CustomVulnScanner",
    "PayloadGenerator",
    "FuzzingEngine",
    
    # Exploitation
    "ExploitationEngine",
    "ExploitChainBuilder",
    "PayloadExecutor",
    "ImpactAnalyzer",
    "ProofOfConceptGenerator",
    
    # Reporting
    "ReportGenerator",
    "TechnicalReportBuilder",
    "ExecutiveReportBuilder",
    "BugBountyReportFormatter",
    "PIIRedactor",
    "EvidenceCollector",
    
    # Orchestration
    "ScanOrchestrator",
    "ScanScheduler",
    "WorkflowManager",
    "ProgressTracker",
    "RateLimiter",
    
    # Utilities
    "ScopeValidator",
    "RequestBuilder",
    "ResponseParser",
    "ToolExecutor",
    "OutputParser",
    "LogManager",
    
    # Tool Integrations
    "AmassIntegration",
    "SubfinderIntegration",
    "NmapIntegration",
    "MasscanIntegration",
    "NucleiIntegration",
    "FFUFIntegration",
    "SQLMapIntegration",
    "MetasploitIntegration",
    "BurpSuiteAPI",
    "ZAPIntegration",
    
    # Database Interfaces
    "TargetManager",
    "ScanSessionManager",
    "VulnerabilityManager",
    "ReconResultManager",
    "ReportManager",
    "ToolExecutionLogger",
    
    # Configuration
    "ScannerConfig",
    "ToolConfig",
    "RateLimitConfig",
    "AuthenticationConfig",
    "load_scanner_config",
    "validate_config",
    
    # Monitoring
    "ScanMetrics",
    "PerformanceMonitor",
    "ErrorTracker",
    "ProgressReporter",
    "AlertManager",
    
    # Main factory functions
    "create_scan_session",
    "get_scanner_engine",
    "initialize_scanners",
]

# Factory functions for easy instantiation
def create_scan_session(target_id: str, config: dict = None) -> 'ScanOrchestrator':
    """
    Factory function to create a new scan session with proper configuration.
    
    Args:
        target_id: UUID of the target from the database
        config: Optional configuration dictionary
        
    Returns:
        Configured ScanOrchestrator instance
    """
    from .scan_orchestrator import ScanOrchestrator
    from .config import load_scanner_config
    
    if config is None:
        config = load_scanner_config()
    
    orchestrator = ScanOrchestrator(target_id=target_id, config=config)
    return orchestrator


def get_scanner_engine(engine_type: str, **kwargs):
    """
    Factory function to get a specific scanner engine.
    
    Args:
        engine_type: Type of engine ('recon', 'vulnerability', 'exploitation', 'report')
        **kwargs: Additional arguments for engine initialization
        
    Returns:
        Appropriate engine instance
        
    Raises:
        ValueError: If engine_type is not recognized
    """
    engines = {
        'recon': ReconEngine,
        'vulnerability': VulnerabilityScanner,
        'exploitation': ExploitationEngine,
        'report': ReportGenerator,
    }
    
    if engine_type not in engines:
        raise ValueError(f"Unknown engine type: {engine_type}. "
                        f"Valid types are: {list(engines.keys())}")
    
    engine_class = engines[engine_type]
    return engine_class(**kwargs)


def initialize_scanners(db_session, logger=None):
    """
    Initialize all scanner components with database session and logging.
    
    Args:
        db_session: SQLAlchemy database session
        logger: Optional logger instance
        
    Returns:
        Dictionary containing initialized scanner components
    """
    from .utils import LogManager
    
    if logger is None:
        logger = LogManager.get_logger(__name__)
    
    components = {
        'target_manager': TargetManager(db_session, logger),
        'session_manager': ScanSessionManager(db_session, logger),
        'vulnerability_manager': VulnerabilityManager(db_session, logger),
        'recon_manager': ReconResultManager(db_session, logger),
        'report_manager': ReportManager(db_session, logger),
        'tool_logger': ToolExecutionLogger(db_session, logger),
    }
    
    logger.info("Scanner engines initialized successfully")
    return components


# Module-level initialization
def _initialize_module():
    """
    Perform any module-level initialization required.
    This is called when the module is first imported.
    """
    import logging
    import os
    
    # Set up default logging if not already configured
    if not logging.getLogger(__name__).handlers:
        logging.basicConfig(
            level=os.getenv('SCANNER_LOG_LEVEL', 'INFO'),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Verify required directories exist
    required_dirs = [
        'scanner_engines/configs',
        'scanner_engines/logs',
        'scanner_engines/outputs',
        'scanner_engines/wordlists',
        'scanner_engines/payloads',
    ]
    
    for directory in required_dirs:
        os.makedirs(directory, exist_ok=True)
    
    # Load environment variables for tool paths
    tool_paths = {
        'AMASS_PATH': os.getenv('AMASS_PATH', '/usr/bin/amass'),
        'SUBFINDER_PATH': os.getenv('SUBFINDER_PATH', '/usr/bin/subfinder'),
        'NUCLEI_PATH': os.getenv('NUCLEI_PATH', '/usr/bin/nuclei'),
        'NMAP_PATH': os.getenv('NMAP_PATH', '/usr/bin/nmap'),
        'MASSCAN_PATH': os.getenv('MASSCAN_PATH', '/usr/bin/masscan'),
        'FFUF_PATH': os.getenv('FFUF_PATH', '/usr/bin/ffuf'),
        'SQLMAP_PATH': os.getenv('SQLMAP_PATH', '/usr/bin/sqlmap'),
    }
    
    # Store tool paths in module namespace
    globals()['TOOL_PATHS'] = tool_paths


# Run initialization when module is imported
_initialize_module()


# Exception classes for scanner engines
class ScannerException(Exception):
    """Base exception for scanner engine errors."""
    pass


class ConfigurationError(ScannerException):
    """Raised when there's a configuration error."""
    pass


class ToolExecutionError(ScannerException):
    """Raised when a tool fails to execute properly."""
    pass


class ScopeValidationError(ScannerException):
    """Raised when scope validation fails."""
    pass


class RateLimitExceeded(ScannerException):
    """Raised when rate limits are exceeded."""
    pass


# Export exception classes
__all__.extend([
    'ScannerException',
    'ConfigurationError',
    'ToolExecutionError',
    'ScopeValidationError',
    'RateLimitExceeded',
])
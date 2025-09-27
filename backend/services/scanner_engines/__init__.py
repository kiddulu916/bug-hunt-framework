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

# Import available scanner engines
try:
    from .custom_api_engine import CustomAPIEngine
except ImportError:
    CustomAPIEngine = None

try:
    from .custom_infra_engine import CustomInfraEngine
except ImportError:
    CustomInfraEngine = None

try:
    from .custom_web_engine import CustomWebEngine
except ImportError:
    CustomWebEngine = None

try:
    from .nuclei_engine import NucleiEngine
except ImportError:
    NucleiEngine = None

try:
    from .recon_engine import ReconEngine
except ImportError:
    ReconEngine = None

try:
    from .scan_orchestrator import ScanOrchestrator
except ImportError:
    ScanOrchestrator = None

# Define public API - only include available modules
__all__ = [
    # Version info
    "__version__",
    "__author__",

    # Available Scanner Engines
    "CustomAPIEngine",
    "CustomInfraEngine",
    "CustomWebEngine",
    "NucleiEngine",
    "ReconEngine",
    "ScanOrchestrator",

    # Factory functions
    "get_available_engines",
    "get_scanner_engine",
]

# Factory functions for easy instantiation
def get_available_engines():
    """
    Get a list of available scanner engines.

    Returns:
        Dictionary of available engine classes
    """
    available = {}

    if CustomAPIEngine is not None:
        available['custom_api'] = CustomAPIEngine
    if CustomInfraEngine is not None:
        available['custom_infra'] = CustomInfraEngine
    if CustomWebEngine is not None:
        available['custom_web'] = CustomWebEngine
    if NucleiEngine is not None:
        available['nuclei'] = NucleiEngine
    if ReconEngine is not None:
        available['recon'] = ReconEngine
    if ScanOrchestrator is not None:
        available['orchestrator'] = ScanOrchestrator

    return available


def get_scanner_engine(engine_type: str, **kwargs):
    """
    Factory function to get a specific scanner engine.

    Args:
        engine_type: Type of engine ('custom_api', 'custom_web', 'custom_infra', 'nuclei', 'recon', 'orchestrator')
        **kwargs: Additional arguments for engine initialization

    Returns:
        Appropriate engine instance

    Raises:
        ValueError: If engine_type is not recognized or not available
    """
    available_engines = get_available_engines()

    if engine_type not in available_engines:
        raise ValueError(f"Unknown or unavailable engine type: {engine_type}. "
                        f"Available types are: {list(available_engines.keys())}")

    engine_class = available_engines[engine_type]
    return engine_class(**kwargs)


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


# Add exception classes to exports
__all__.extend([
    'ScannerException',
    'ConfigurationError',
    'ToolExecutionError',
    'ScopeValidationError',
    'RateLimitExceeded',
])
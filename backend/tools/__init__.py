"""
Tool Framework Initialization
backend/tools/__init__.py

Initializes all available tools and registers them with the global registry.
"""

import logging
from .base import tool_registry, list_tools

logger = logging.getLogger(__name__)


def initialize_tools():
    """Initialize and register all available tools"""
    logger.info("Initializing tool framework...")

    try:
        # Import all tool modules to trigger registration
        # Note: These imports are intentional to register tools
        from .passive_recon import osint_gathering  # noqa: F401
        from .passive_recon import tech_fingerprinting  # noqa: F401
        from .active_recon import service_detection  # noqa: F401
        from .vulnerability_testing import sql_injection  # noqa: F401
        from .vulnerability_testing import xss_testing  # noqa: F401
        from .vulnerability_testing import file_inclusion  # noqa: F401
        from .vulnerability_testing import auth_bypass  # noqa: F401

        logger.info("Tool modules imported successfully")

        # Log available tools
        available_tools = list_tools()

        logger.info(
            "Registered tools across %s categories:",
            len(available_tools)
        )
        for category, tools in available_tools.items():
            logger.info(
                "  {category}: %s",
                ', '.join(tools) if tools else 'none'
            )

        return True

    except Exception as e:
        logger.error("Error initializing tools: %s", e)
        return False


def get_tool_status():
    """Get status of all registered tools"""
    status = {}

    for tool_name, tool in tool_registry._tools.items():
        status[tool_name] = {
            'name': tool.name,
            'category': tool.category.value,
            'available': tool.is_available(),
            'version': tool.get_version(),
            'binary_path': tool.binary_path
        }

    return status


# Initialize tools when module is imported
initialize_tools()

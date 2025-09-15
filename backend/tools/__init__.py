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
        from .passive_recon import subdomain_enum
        from .active_recon import port_scanning
        from .vulnerability_testing import nuclei_scanner
        
        logger.info("Tool modules imported successfully")
        
        # Log available tools
        available_tools = list_tools()
        total_tools = sum(len(tools) for tools in available_tools.values())
        
        logger.info(f"Registered {total_tools} tools across {len(available_tools)} categories:")
        for category, tools in available_tools.items():
            logger.info(f"  {category}: {', '.join(tools) if tools else 'none'}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error initializing tools: {e}")
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

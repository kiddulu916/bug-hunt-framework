"""
FastAPI routers initialization.
This module imports and exposes all API routers for the Bug Bounty Platform.
"""

from . import vulnerabilities, targets, scans, reports

__all__ = [
    "vulnerabilities",
    "targets", 
    "scans",
    "reports"
]
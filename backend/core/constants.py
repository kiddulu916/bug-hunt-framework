"""
Application constants for Bug Bounty Automation Platform.
"""

from enum import Enum

# Application metadata
APP_NAME = "Bug Bounty Automation Platform"
APP_VERSION = "1.0.0"
API_VERSION = "v1"
APP_DESCRIPTION = (
    "Automated penetration testing and vulnerability management platform"
)

# Database constants
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
DEFAULT_TIMEOUT_SECONDS = 30

# Authentication constants
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# File upload constants
MAX_UPLOAD_SIZE_MB = 50
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'
]
ALLOWED_DOCUMENT_EXTENSIONS = [
    '.pdf', '.doc', '.docx', '.txt', '.md'
]
ALLOWED_EVIDENCE_EXTENSIONS = (
    ALLOWED_IMAGE_EXTENSIONS + ['.html', '.json', '.xml']
)

# Scanning constants
DEFAULT_REQUESTS_PER_SECOND = 5.0
DEFAULT_CONCURRENT_REQUESTS = 10
DEFAULT_REQUEST_DELAY_MS = 200
MAX_SCAN_DURATION_HOURS = 24
MAX_CONCURRENT_SCANS = 5

# Tool timeout constants (in seconds)
TOOL_TIMEOUTS = {
    'amass': 3600,        # 1 hour
    'subfinder': 1800,    # 30 minutes
    'nuclei': 7200,       # 2 hours
    'httpx': 3600,        # 1 hour
    'nmap': 3600,         # 1 hour
    'masscan': 1800,      # 30 minutes
    'sqlmap': 1800,       # 30 minutes
    'nikto': 3600,        # 1 hour
    'gobuster': 3600,     # 1 hour
    'ffuf': 3600,         # 1 hour
}

# Reconnaissance phases
RECON_PHASES = [
    'passive_recon',
    'active_recon',
    'vulnerability_testing',
    'exploitation',
    'reporting'
]


# Tool categories
class ToolCategory(Enum):
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCANNING = "port_scanning"
    WEB_SCANNING = "web_scanning"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


# Common tool configurations
TOOL_CONFIGS = {
    'amass': {
        'category': ToolCategory.SUBDOMAIN_ENUM,
        'default_args': ['-passive'],
        'output_format': 'text',
        'requires_wordlist': False,
    },
    'subfinder': {
        'category': ToolCategory.SUBDOMAIN_ENUM,
        'default_args': ['-silent'],
        'output_format': 'text',
        'requires_wordlist': False,
    },
    'nuclei': {
        'category': ToolCategory.VULNERABILITY_SCANNING,
        'default_args': ['-silent', '-no-color'],
        'output_format': 'json',
        'requires_wordlist': False,
    },
    'httpx': {
        'category': ToolCategory.ACTIVE_RECON,
        'default_args': ['-silent', '-no-color'],
        'output_format': 'json',
        'requires_wordlist': False,
    },
    'nmap': {
        'category': ToolCategory.PORT_SCANNING,
        'default_args': ['-sS', '-T4'],
        'output_format': 'xml',
        'requires_wordlist': False,
    },
    'gobuster': {
        'category': ToolCategory.WEB_SCANNING,
        'default_args': ['dir', '-q'],
        'output_format': 'text',
        'requires_wordlist': True,
    }
}

# HTTP status codes for analysis
HTTP_SUCCESS_CODES = [200, 201, 202, 204]
HTTP_REDIRECT_CODES = [300, 301, 302, 303, 304, 307, 308]
HTTP_CLIENT_ERROR_CODES = [400, 401, 403, 404, 405, 406, 409, 410, 422, 429]
HTTP_SERVER_ERROR_CODES = [500, 501, 502, 503, 504, 505]

INTERESTING_HTTP_CODES = [
    200,  # OK - Successful responses
    201,  # Created
    204,  # No Content
    301,  # Moved Permanently
    302,  # Found
    400,  # Bad Request
    401,  # Unauthorized
    403,  # Forbidden
    500,  # Internal Server Error
    502,  # Bad Gateway
    503,  # Service Unavailable
]

# Common ports for scanning
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080
]

TOP_1000_PORTS = list(range(1, 1001))  # Simplified - use nmap's top-ports list

# Vulnerability severity scoring
CVSS_SCORE_RANGES = {
    'critical': (9.0, 10.0),
    'high': (7.0, 8.9),
    'medium': (4.0, 6.9),
    'low': (0.1, 3.9),
    'info': (0.0, 0.0),
}

# Common vulnerability types
VULNERABILITY_TYPES = [
    'sql_injection',
    'xss_reflected',
    'xss_stored',
    'xss_dom',
    'csrf',
    'xxe',
    'ssrf',
    'lfi',
    'rfi',
    'rce',
    'authentication_bypass',
    'authorization_bypass',
    'information_disclosure',
    'directory_traversal',
    'insecure_deserialization',
    'broken_access_control',
    'security_misconfiguration',
    'vulnerable_components',
    'insufficient_logging',
    'business_logic_flaw',
]

# OWASP Top 10 2021 mappings
OWASP_TOP_10_2021 = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
}

# CWE (Common Weakness Enumeration) mappings
COMMON_CWE_MAPPINGS = {
    'sql_injection': 'CWE-89',
    'xss_reflected': 'CWE-79',
    'xss_stored': 'CWE-79',
    'xss_dom': 'CWE-79',
    'csrf': 'CWE-352',
    'xxe': 'CWE-611',
    'ssrf': 'CWE-918',
    'lfi': 'CWE-22',
    'rfi': 'CWE-98',
    'rce': 'CWE-78',
    'authentication_bypass': 'CWE-287',
    'authorization_bypass': 'CWE-285',
    'information_disclosure': 'CWE-200',
    'directory_traversal': 'CWE-22',
    'insecure_deserialization': 'CWE-502',
}

# Regular expressions for common patterns
REGEX_PATTERNS = {
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'url': (
        r'^https?://(?:[-\w.])+(?:\:[0-9]+)?'
        r'(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    ),
    'ip_address': (
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ),
    'domain': (
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
    ),
    'subdomain': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?',
    'port': (
        r'^(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|'
        r'65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'
    ),
    'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
}

# Technology detection patterns
TECHNOLOGY_FINGERPRINTS = {
    'apache': {
        'headers': ['Server: Apache'],
        'keywords': ['apache'],
    },
    'nginx': {
        'headers': ['Server: nginx'],
        'keywords': ['nginx'],
    },
    'php': {
        'headers': ['X-Powered-By: PHP'],
        'keywords': ['php'],
        'extensions': ['.php'],
    },
    'nodejs': {
        'headers': ['X-Powered-By: Express'],
        'keywords': ['node.js', 'express'],
    },
    'wordpress': {
        'keywords': ['wp-content', 'wp-admin', 'wordpress'],
        'paths': ['/wp-admin/', '/wp-content/'],
    },
    'joomla': {
        'keywords': ['joomla'],
        'paths': ['/administrator/'],
    },
    'drupal': {
        'keywords': ['drupal'],
        'paths': ['/node/', '/admin/'],
    },
}

# Report generation constants
REPORT_TYPES = [
    'technical',
    'executive',
    'bug_bounty',
    'compliance',
]

REPORT_FORMATS = [
    'pdf',
    'html',
    'json',
    'xml',
    'csv',
]

# Template names for reports
REPORT_TEMPLATES = {
    'technical': 'technical_report.html',
    'executive': 'executive_summary.html',
    'bug_bounty': 'bug_bounty_report.html',
    'compliance': 'compliance_report.html',
}

# Notification types
NOTIFICATION_TYPES = [
    'scan_started',
    'scan_completed',
    'scan_failed',
    'vulnerability_found',
    'critical_vulnerability_found',
    'report_generated',
    'target_added',
    'target_updated',
]

# Rate limiting constants
RATE_LIMITS = {
    'api_default': '1000/hour',
    'api_authenticated': '5000/hour',
    'api_admin': '10000/hour',
    'scan_requests': '100/minute',
    'report_generation': '10/minute',
    'file_upload': '50/hour',
}

# Cache timeouts (in seconds)
CACHE_TIMEOUTS = {
    'vulnerability_list': 300,      # 5 minutes
    'target_list': 600,             # 10 minutes
    'scan_status': 60,              # 1 minute
    'report_metadata': 1800,        # 30 minutes
    'user_permissions': 900,        # 15 minutes
    'tool_status': 120,             # 2 minutes
}

# Default wordlists and dictionaries
DEFAULT_WORDLISTS = {
    'subdomain': '/usr/share/wordlists/subdomains-top1million-5000.txt',
    'directory': '/usr/share/wordlists/dirb/common.txt',
    'files': '/usr/share/wordlists/dirb/extensions_common.txt',
    'parameters': '/usr/share/wordlists/burp-parameter-names.txt',
}

# Bug bounty platform specific constants
BUG_BOUNTY_PLATFORMS = {
    'hackerone': {
        'name': 'HackerOne',
        'base_url': 'https://hackerone.com',
        'api_url': 'https://api.hackerone.com/v1',
        'report_format': 'markdown',
    },
    'bugcrowd': {
        'name': 'Bugcrowd',
        'base_url': 'https://bugcrowd.com',
        'api_url': 'https://api.bugcrowd.com',
        'report_format': 'html',
    },
    'intigriti': {
        'name': 'Intigriti',
        'base_url': 'https://intigriti.com',
        'api_url': 'https://api.intigriti.com',
        'report_format': 'markdown',
    },
    'synack': {
        'name': 'Synack',
        'base_url': 'https://synack.com',
        'report_format': 'custom',
    },
    'yeswehack': {
        'name': 'YesWeHack',
        'base_url': 'https://yeswehack.com',
        'api_url': 'https://api.yeswehack.com',
        'report_format': 'markdown',
    },
}

# Common payloads for testing (simplified examples)
TEST_PAYLOADS = {
    'xss': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '"><script>alert(1)</script>',
    ],
    'sqli': [
        "' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "admin'--",
        "' OR 'x'='x",
    ],
    'lfi': [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '/etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    ],
    'rce': [
        '; ls -la',
        '| whoami',
        '`id`',
        '$(whoami)',
    ],
}

# Status messages
STATUS_MESSAGES = {
    'scan_queued': 'Scan has been queued for execution',
    'scan_started': 'Scan execution has started',
    'scan_running': 'Scan is currently in progress',
    'scan_paused': 'Scan has been paused',
    'scan_completed': 'Scan has completed successfully',
    'scan_failed': 'Scan execution failed',
    'scan_cancelled': 'Scan has been cancelled by user',
    'tool_not_found': 'Required scanning tool not found',
    'target_out_of_scope': 'Target is out of scope for scanning',
    'rate_limit_exceeded': 'Rate limit exceeded, please try again later',
}

# Error codes for API responses
ERROR_CODES = {
    # Authentication errors (1000-1099)
    'INVALID_CREDENTIALS': 1001,
    'TOKEN_EXPIRED': 1002,
    'INVALID_TOKEN': 1003,
    'INSUFFICIENT_PERMISSIONS': 1004,

    # Validation errors (1100-1199)
    'INVALID_DATA': 1101,
    'MISSING_REQUIRED_FIELD': 1102,
    'INVALID_FORMAT': 1103,
    'VALUE_OUT_OF_RANGE': 1104,

    # Resource errors (1200-1299)
    'RECORD_NOT_FOUND': 1201,
    'DUPLICATE_RECORD': 1202,
    'RESOURCE_LOCKED': 1203,
    'RESOURCE_CONFLICT': 1204,

    # Scanning errors (1300-1399)
    'TOOL_NOT_FOUND': 1301,
    'TOOL_EXECUTION_FAILED': 1302,
    'SCAN_TIMEOUT': 1303,
    'CONCURRENT_SCAN_LIMIT': 1304,
    'INVALID_SCAN_CONFIG': 1305,

    # Target errors (1400-1499)
    'INVALID_TARGET': 1401,
    'OUT_OF_SCOPE': 1402,
    'TARGET_UNREACHABLE': 1403,

    # File errors (1500-1599)
    'FILE_UPLOAD_FAILED': 1501,
    'FILE_TOO_LARGE': 1502,
    'INVALID_FILE_FORMAT': 1503,
    'FILE_PROCESSING_FAILED': 1504,

    # Rate limiting (1600-1699)
    'RATE_LIMIT_EXCEEDED': 1601,
    'QUOTA_EXCEEDED': 1602,

    # System errors (1700-1799)
    'SYSTEM_ERROR': 1701,
    'DATABASE_ERROR': 1702,
    'EXTERNAL_API_ERROR': 1703,
}

# HTTP headers for security
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': (
        'max-age=31536000; includeSubDomains'
    ),
    'Content-Security-Policy': "default-src 'self'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
}

# Logging formats
LOG_FORMATS = {
    'simple': '%(levelname)s %(message)s',
    'detailed': '%(asctime)s %(name)s %(levelname)s %(message)s',
    'json': (
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
        '"logger": "%(name)s", "message": "%(message)s"}'
    ),
}

# Environment types
ENVIRONMENT_TYPES = [
    'development',
    'testing',
    'staging',
    'production',
]

# Export commonly used constants
__all__ = [
    'APP_NAME',
    'APP_VERSION',
    'API_VERSION',
    'RECON_PHASES',
    'ToolCategory',
    'TOOL_CONFIGS',
    'TOOL_TIMEOUTS',
    'HTTP_SUCCESS_CODES',
    'HTTP_REDIRECT_CODES',
    'HTTP_CLIENT_ERROR_CODES',
    'HTTP_SERVER_ERROR_CODES',
    'INTERESTING_HTTP_CODES',
    'COMMON_PORTS',
    'CVSS_SCORE_RANGES',
    'VULNERABILITY_TYPES',
    'OWASP_TOP_10_2021',
    'COMMON_CWE_MAPPINGS',
    'REGEX_PATTERNS',
    'TECHNOLOGY_FINGERPRINTS',
    'REPORT_TYPES',
    'REPORT_FORMATS',
    'NOTIFICATION_TYPES',
    'RATE_LIMITS',
    'CACHE_TIMEOUTS',
    'BUG_BOUNTY_PLATFORMS',
    'STATUS_MESSAGES',
    'ERROR_CODES',
    'SECURITY_HEADERS',
]

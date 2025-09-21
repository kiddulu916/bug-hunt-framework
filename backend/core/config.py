"""
Enhanced configuration management for Bug Bounty Platform.
Provides centralized configuration, environment management, and dynamic settings.
"""

import os
import json
import logging
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from pathlib import Path
import yaml
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    url: str = "postgresql://bugbounty_user:password@localhost:5432/bugbounty_platform"
    pool_size: int = 10
    max_overflow: int = 20
    pool_recycle: int = 300
    echo_queries: bool = False
    timeout: int = 30


@dataclass
class CacheConfig:
    """Cache configuration settings."""
    redis_url: str = "redis://localhost:6379/1"
    default_ttl: int = 300
    key_prefix: str = "bbp:cache:"
    max_connections: int = 10


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    jwt_secret_key: str = "your-secret-key-here"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_min_length: int = 8
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60


@dataclass
class ScanningConfig:
    """Scanning configuration settings."""
    max_concurrent_scans: int = 5
    default_scan_timeout: int = 3600
    nuclei_template_path: str = "/tools/nuclei-templates"
    tools_directory: str = "/tools"
    evidence_storage_path: str = "/evidence"
    max_scan_targets: int = 1000


@dataclass
class MonitoringConfig:
    """Monitoring and alerting configuration."""
    enable_metrics: bool = True
    metrics_retention_hours: int = 24
    alert_check_interval_seconds: int = 60
    email_alerts_enabled: bool = False
    webhook_alerts_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""


@dataclass
class APIConfig:
    """API configuration settings."""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: List[str] = field(default_factory=lambda: ["http://localhost:3000"])
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    response_compression_enabled: bool = True
    api_key_header: str = "X-API-Key"


@dataclass
class PlatformConfig:
    """Complete platform configuration."""
    environment: str = "development"
    log_level: str = "INFO"
    secret_key: str = "fallback-secret-key"
    debug: bool = False
    timezone: str = "UTC"

    # Component configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    api: APIConfig = field(default_factory=APIConfig)


class ConfigManager:
    """
    Centralized configuration manager with environment override support.
    """

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = PlatformConfig()
        self._load_configuration()

    def _load_configuration(self):
        """Load configuration from various sources."""
        # 1. Load from config file if provided
        if self.config_file and os.path.exists(self.config_file):
            self._load_from_file(self.config_file)

        # 2. Load from default config files
        self._load_from_default_files()

        # 3. Override with environment variables
        self._load_from_environment()

        # 4. Validate configuration
        self._validate_configuration()

    def _load_from_file(self, file_path: str):
        """Load configuration from file (JSON or YAML)."""
        try:
            file_path = Path(file_path)
            if file_path.suffix.lower() in ['.yml', '.yaml']:
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
            elif file_path.suffix.lower() == '.json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
            else:
                logger.warning(f"Unsupported config file format: {file_path}")
                return

            self._merge_config_data(data)
            logger.info(f"Loaded configuration from {file_path}")

        except Exception as e:
            logger.error(f"Error loading config file {file_path}: {e}")

    def _load_from_default_files(self):
        """Load from default configuration files."""
        default_files = [
            'config/settings.yml',
            'config/settings.yaml',
            'config/settings.json',
            'settings.yml',
            'settings.yaml',
            'settings.json'
        ]

        for file_path in default_files:
            if os.path.exists(file_path):
                self._load_from_file(file_path)
                break

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        env_mappings = {
            # General settings
            'ENVIRONMENT': 'environment',
            'DEBUG': 'debug',
            'SECRET_KEY': 'secret_key',
            'LOG_LEVEL': 'log_level',
            'TIMEZONE': 'timezone',

            # Database
            'DATABASE_URL': 'database.url',
            'DB_POOL_SIZE': 'database.pool_size',
            'DB_MAX_OVERFLOW': 'database.max_overflow',
            'DB_POOL_RECYCLE': 'database.pool_recycle',
            'SQL_ECHO': 'database.echo_queries',

            # Cache
            'REDIS_URL': 'cache.redis_url',
            'CACHE_DEFAULT_TTL': 'cache.default_ttl',
            'CACHE_KEY_PREFIX': 'cache.key_prefix',

            # Security
            'JWT_SECRET_KEY': 'security.jwt_secret_key',
            'JWT_ALGORITHM': 'security.jwt_algorithm',
            'JWT_ACCESS_TOKEN_EXPIRE_MINUTES': 'security.access_token_expire_minutes',
            'PASSWORD_MIN_LENGTH': 'security.password_min_length',
            'MAX_LOGIN_ATTEMPTS': 'security.max_login_attempts',
            'RATE_LIMIT_REQUESTS': 'security.rate_limit_requests',

            # Scanning
            'MAX_CONCURRENT_SCANS': 'scanning.max_concurrent_scans',
            'DEFAULT_SCAN_TIMEOUT': 'scanning.default_scan_timeout',
            'NUCLEI_TEMPLATE_PATH': 'scanning.nuclei_template_path',
            'TOOLS_DIRECTORY': 'scanning.tools_directory',
            'EVIDENCE_STORAGE_PATH': 'scanning.evidence_storage_path',

            # API
            'API_HOST': 'api.host',
            'API_PORT': 'api.port',
            'CORS_ALLOWED_ORIGINS': 'api.cors_origins',
            'MAX_REQUEST_SIZE': 'api.max_request_size',

            # Monitoring
            'ENABLE_METRICS': 'monitoring.enable_metrics',
            'METRICS_RETENTION_HOURS': 'monitoring.metrics_retention_hours',
            'EMAIL_ALERTS_ENABLED': 'monitoring.email_alerts_enabled',
            'SMTP_HOST': 'monitoring.smtp_host',
            'SMTP_PORT': 'monitoring.smtp_port',
            'SMTP_USERNAME': 'monitoring.smtp_username',
            'SMTP_PASSWORD': 'monitoring.smtp_password',
        }

        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                self._set_nested_config(config_path, self._convert_env_value(env_value))

    def _merge_config_data(self, data: Dict[str, Any]):
        """Merge configuration data into current config."""
        def merge_dict(target: Any, source: Dict[str, Any], path: str = ""):
            for key, value in source.items():
                current_path = f"{path}.{key}" if path else key

                if hasattr(target, key):
                    current_value = getattr(target, key)
                    if isinstance(current_value, (DatabaseConfig, CacheConfig, SecurityConfig,
                                                ScanningConfig, MonitoringConfig, APIConfig)):
                        # Recursively merge nested configs
                        if isinstance(value, dict):
                            merge_dict(current_value, value, current_path)
                    else:
                        # Set primitive values
                        setattr(target, key, value)
                else:
                    logger.warning(f"Unknown configuration key: {current_path}")

        merge_dict(self.config, data)

    def _set_nested_config(self, path: str, value: Any):
        """Set configuration value using dot notation path."""
        parts = path.split('.')
        current = self.config

        for part in parts[:-1]:
            if hasattr(current, part):
                current = getattr(current, part)
            else:
                logger.warning(f"Invalid config path: {path}")
                return

        if hasattr(current, parts[-1]):
            setattr(current, parts[-1], value)
        else:
            logger.warning(f"Invalid config key: {parts[-1]} in {path}")

    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate type."""
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'

        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass

        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass

        # List conversion (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]

        # Return as string
        return value

    def _validate_configuration(self):
        """Validate configuration settings."""
        errors = []

        # Validate database configuration
        if not self.config.database.url:
            errors.append("Database URL is required")

        # Validate security configuration
        if len(self.config.security.jwt_secret_key) < 32:
            errors.append("JWT secret key should be at least 32 characters")

        # Validate scanning configuration
        if self.config.scanning.max_concurrent_scans < 1:
            errors.append("Max concurrent scans must be at least 1")

        # Validate API configuration
        if not (1 <= self.config.api.port <= 65535):
            errors.append("API port must be between 1 and 65535")

        if errors:
            logger.error("Configuration validation errors:")
            for error in errors:
                logger.error(f"  - {error}")
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")

        logger.info("Configuration validation passed")

    def get(self, path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        parts = path.split('.')
        current = self.config

        try:
            for part in parts:
                current = getattr(current, part)
            return current
        except AttributeError:
            return default

    def set(self, path: str, value: Any) -> bool:
        """Set configuration value using dot notation."""
        try:
            self._set_nested_config(path, value)
            return True
        except Exception as e:
            logger.error(f"Error setting config {path}: {e}")
            return False

    def reload(self):
        """Reload configuration from sources."""
        logger.info("Reloading configuration...")
        self.config = PlatformConfig()
        self._load_configuration()

    def export_config(self, format: str = 'yaml') -> str:
        """Export current configuration to string."""
        config_dict = self._config_to_dict(self.config)

        if format.lower() == 'yaml':
            return yaml.dump(config_dict, default_flow_style=False, indent=2)
        elif format.lower() == 'json':
            return json.dumps(config_dict, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _config_to_dict(self, config_obj: Any) -> Dict[str, Any]:
        """Convert configuration object to dictionary."""
        if hasattr(config_obj, '__dict__'):
            result = {}
            for key, value in config_obj.__dict__.items():
                if hasattr(value, '__dict__'):  # Nested config object
                    result[key] = self._config_to_dict(value)
                else:
                    result[key] = value
            return result
        else:
            return config_obj

    def get_health_status(self) -> Dict[str, Any]:
        """Get configuration health status."""
        return {
            'status': 'healthy',
            'environment': self.config.environment,
            'debug': self.config.debug,
            'config_file': self.config_file,
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'database': {'url_configured': bool(self.config.database.url)},
                'cache': {'redis_configured': bool(self.config.cache.redis_url)},
                'security': {'jwt_configured': bool(self.config.security.jwt_secret_key)},
                'scanning': {'tools_path_configured': bool(self.config.scanning.tools_directory)},
                'monitoring': {'metrics_enabled': self.config.monitoring.enable_metrics},
                'api': {'port': self.config.api.port, 'debug': self.config.api.debug}
            }
        }


# Global configuration manager
config_manager = ConfigManager()


# Convenience functions for accessing configuration
def get_config() -> PlatformConfig:
    """Get the complete platform configuration."""
    return config_manager.config


def get_database_config() -> DatabaseConfig:
    """Get database configuration."""
    return config_manager.config.database


def get_cache_config() -> CacheConfig:
    """Get cache configuration."""
    return config_manager.config.cache


def get_security_config() -> SecurityConfig:
    """Get security configuration."""
    return config_manager.config.security


def get_scanning_config() -> ScanningConfig:
    """Get scanning configuration."""
    return config_manager.config.scanning


def get_monitoring_config() -> MonitoringConfig:
    """Get monitoring configuration."""
    return config_manager.config.monitoring


def get_api_config() -> APIConfig:
    """Get API configuration."""
    return config_manager.config.api


def get_setting(path: str, default: Any = None) -> Any:
    """Get a specific configuration setting."""
    return config_manager.get(path, default)


def is_production() -> bool:
    """Check if running in production environment."""
    return config_manager.config.environment.lower() == 'production'


def is_development() -> bool:
    """Check if running in development environment."""
    return config_manager.config.environment.lower() == 'development'


def is_debug_enabled() -> bool:
    """Check if debug mode is enabled."""
    return config_manager.config.debug


# Export main components
__all__ = [
    'DatabaseConfig',
    'CacheConfig',
    'SecurityConfig',
    'ScanningConfig',
    'MonitoringConfig',
    'APIConfig',
    'PlatformConfig',
    'ConfigManager',
    'config_manager',
    'get_config',
    'get_database_config',
    'get_cache_config',
    'get_security_config',
    'get_scanning_config',
    'get_monitoring_config',
    'get_api_config',
    'get_setting',
    'is_production',
    'is_development',
    'is_debug_enabled'
]
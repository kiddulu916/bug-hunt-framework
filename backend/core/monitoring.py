"""
Enhanced monitoring and alerting system for Bug Bounty Platform.
Provides comprehensive system monitoring, alerting, and performance tracking.
"""

import asyncio
import logging
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

from core.cache import cache_manager
from core.database_optimizer import performance_monitor, get_database_health
from core.exceptions import BugBountyPlatformException

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Alert data structure."""
    id: str
    severity: AlertSeverity
    title: str
    message: str
    source: str
    timestamp: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['timestamp'] = self.timestamp.isoformat()
        if self.resolved_at:
            data['resolved_at'] = self.resolved_at.isoformat()
        return data


class MetricCollector:
    """
    Collect and aggregate system metrics.
    """

    def __init__(self, retention_hours: int = 24):
        self.metrics = defaultdict(lambda: deque(maxlen=retention_hours * 60))  # 1 minute intervals
        self.lock = threading.Lock()
        self.collectors = {}

    def register_collector(self, name: str, collector_func: Callable) -> None:
        """Register a metric collector function."""
        self.collectors[name] = collector_func

    def collect_metric(self, name: str, value: float, timestamp: datetime = None) -> None:
        """Collect a single metric value."""
        if timestamp is None:
            timestamp = datetime.utcnow()

        with self.lock:
            self.metrics[name].append({
                'value': value,
                'timestamp': timestamp
            })

    def get_metric_history(self, name: str, hours: int = 1) -> List[Dict[str, Any]]:
        """Get metric history for specified time period."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        with self.lock:
            return [
                metric for metric in self.metrics[name]
                if metric['timestamp'] > cutoff_time
            ]

    def get_metric_stats(self, name: str, hours: int = 1) -> Dict[str, float]:
        """Get statistical summary of metric."""
        history = self.get_metric_history(name, hours)
        if not history:
            return {}

        values = [metric['value'] for metric in history]
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'latest': values[-1] if values else 0
        }

    async def collect_all_metrics(self) -> None:
        """Collect all registered metrics."""
        for name, collector_func in self.collectors.items():
            try:
                value = await collector_func() if asyncio.iscoroutinefunction(collector_func) else collector_func()
                if isinstance(value, (int, float)):
                    self.collect_metric(name, value)
                elif isinstance(value, dict):
                    for sub_name, sub_value in value.items():
                        if isinstance(sub_value, (int, float)):
                            self.collect_metric(f"{name}.{sub_name}", sub_value)
            except Exception as e:
                logger.error(f"Error collecting metric {name}: {e}")


class AlertManager:
    """
    Manage alerts and notifications.
    """

    def __init__(self):
        self.alerts = deque(maxlen=1000)
        self.alert_rules = []
        self.notification_channels = []
        self.lock = threading.Lock()

    def add_alert_rule(self, rule: 'AlertRule') -> None:
        """Add an alert rule."""
        self.alert_rules.append(rule)

    def add_notification_channel(self, channel: 'NotificationChannel') -> None:
        """Add a notification channel."""
        self.notification_channels.append(channel)

    def create_alert(self, severity: AlertSeverity, title: str, message: str,
                    source: str, metadata: Dict[str, Any] = None) -> Alert:
        """Create a new alert."""
        alert = Alert(
            id=f"alert_{int(time.time() * 1000)}",
            severity=severity,
            title=title,
            message=message,
            source=source,
            timestamp=datetime.utcnow(),
            metadata=metadata or {}
        )

        with self.lock:
            self.alerts.append(alert)

        # Send notifications
        asyncio.create_task(self._send_notifications(alert))

        logger.info(f"Alert created: {alert.title} ({alert.severity.value})")
        return alert

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        with self.lock:
            for alert in self.alerts:
                if alert.id == alert_id and not alert.resolved:
                    alert.resolved = True
                    alert.resolved_at = datetime.utcnow()
                    logger.info(f"Alert resolved: {alert.title}")
                    return True
        return False

    def get_active_alerts(self, severity: AlertSeverity = None) -> List[Alert]:
        """Get active (unresolved) alerts."""
        with self.lock:
            alerts = [alert for alert in self.alerts if not alert.resolved]
            if severity:
                alerts = [alert for alert in alerts if alert.severity == severity]
            return sorted(alerts, key=lambda a: a.timestamp, reverse=True)

    def get_alert_history(self, hours: int = 24) -> List[Alert]:
        """Get alert history for specified time period."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        with self.lock:
            return [
                alert for alert in self.alerts
                if alert.timestamp > cutoff_time
            ]

    async def evaluate_alert_rules(self, metrics: Dict[str, Any]) -> None:
        """Evaluate all alert rules against current metrics."""
        for rule in self.alert_rules:
            try:
                if await rule.evaluate(metrics):
                    # Check for duplicate alerts
                    if not self._is_duplicate_alert(rule):
                        self.create_alert(
                            severity=rule.severity,
                            title=rule.title,
                            message=rule.get_message(metrics),
                            source=rule.source,
                            metadata=rule.metadata
                        )
            except Exception as e:
                logger.error(f"Error evaluating alert rule {rule.title}: {e}")

    def _is_duplicate_alert(self, rule: 'AlertRule') -> bool:
        """Check if similar alert already exists."""
        recent_alerts = self.get_alert_history(hours=1)
        return any(
            alert.title == rule.title and alert.source == rule.source
            for alert in recent_alerts
            if not alert.resolved
        )

    async def _send_notifications(self, alert: Alert) -> None:
        """Send alert notifications through all channels."""
        for channel in self.notification_channels:
            try:
                if channel.should_notify(alert):
                    await channel.send_notification(alert)
            except Exception as e:
                logger.error(f"Error sending notification through {channel.__class__.__name__}: {e}")


class AlertRule:
    """
    Base class for alert rules.
    """

    def __init__(self, title: str, severity: AlertSeverity, source: str,
                 condition: Callable, message_template: str = None,
                 metadata: Dict[str, Any] = None):
        self.title = title
        self.severity = severity
        self.source = source
        self.condition = condition
        self.message_template = message_template or "{title}"
        self.metadata = metadata or {}

    async def evaluate(self, metrics: Dict[str, Any]) -> bool:
        """Evaluate if alert condition is met."""
        try:
            if asyncio.iscoroutinefunction(self.condition):
                return await self.condition(metrics)
            else:
                return self.condition(metrics)
        except Exception as e:
            logger.error(f"Error evaluating alert rule {self.title}: {e}")
            return False

    def get_message(self, metrics: Dict[str, Any]) -> str:
        """Generate alert message from template."""
        try:
            return self.message_template.format(
                title=self.title,
                metrics=metrics,
                **self.metadata
            )
        except Exception:
            return f"{self.title} - Alert condition triggered"


class NotificationChannel:
    """
    Base class for notification channels.
    """

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    def should_notify(self, alert: Alert) -> bool:
        """Determine if this channel should send notification for alert."""
        return self.enabled

    async def send_notification(self, alert: Alert) -> None:
        """Send notification for alert."""
        raise NotImplementedError


class EmailNotificationChannel(NotificationChannel):
    """
    Email notification channel.
    """

    def __init__(self, name: str, smtp_host: str, smtp_port: int,
                 username: str, password: str, from_email: str,
                 to_emails: List[str], enabled: bool = True):
        super().__init__(name, enabled)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails

    def should_notify(self, alert: Alert) -> bool:
        """Only notify for warning and above."""
        return (
            self.enabled and
            alert.severity in [AlertSeverity.WARNING, AlertSeverity.ERROR, AlertSeverity.CRITICAL]
        )

    async def send_notification(self, alert: Alert) -> None:
        """Send email notification."""
        try:
            msg = MimeMultipart()
            msg['From'] = self.from_email
            msg['To'] = ", ".join(self.to_emails)
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"

            body = f"""
Alert Details:
--------------
Title: {alert.title}
Severity: {alert.severity.value.upper()}
Source: {alert.source}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Message: {alert.message}

Metadata:
{json.dumps(alert.metadata, indent=2) if alert.metadata else 'None'}
            """

            msg.attach(MimeText(body, 'plain'))

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Email notification sent for alert: {alert.title}")

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")


class WebhookNotificationChannel(NotificationChannel):
    """
    Webhook notification channel.
    """

    def __init__(self, name: str, webhook_url: str, headers: Dict[str, str] = None,
                 enabled: bool = True):
        super().__init__(name, enabled)
        self.webhook_url = webhook_url
        self.headers = headers or {}

    async def send_notification(self, alert: Alert) -> None:
        """Send webhook notification."""
        import aiohttp

        try:
            payload = {
                'alert': alert.to_dict(),
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'bug_bounty_platform'
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info(f"Webhook notification sent for alert: {alert.title}")
                    else:
                        logger.error(f"Webhook notification failed with status: {response.status}")

        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")


class SystemMonitor:
    """
    Main system monitoring coordinator.
    """

    def __init__(self):
        self.metric_collector = MetricCollector()
        self.alert_manager = AlertManager()
        self.monitoring_interval = 60  # seconds
        self.monitoring_task = None
        self.running = False

        # Register default metric collectors
        self._register_default_collectors()

        # Register default alert rules
        self._register_default_alert_rules()

    def _register_default_collectors(self) -> None:
        """Register default system metric collectors."""

        def collect_database_metrics():
            db_health = get_database_health()
            if db_health.get('status') == 'healthy':
                perf = db_health.get('performance', {})
                return {
                    'query_count': perf.get('total_queries', 0),
                    'slow_queries': perf.get('slow_queries', 0),
                    'avg_duration': perf.get('average_duration', 0),
                    'connection_pool_usage': db_health.get('connection_pool', {}).get('utilization_percent', 0)
                }
            return {'status': 0}  # Unhealthy

        def collect_cache_metrics():
            cache_stats = cache_manager.get_stats()
            total_requests = cache_stats.get('total_requests', 1)
            return {
                'hit_rate': cache_stats.get('hit_rate_percent', 0),
                'total_requests': total_requests,
                'hits': cache_stats.get('hits', 0),
                'misses': cache_stats.get('misses', 0)
            }

        def collect_api_metrics():
            # This would be enhanced with actual API metrics
            return {
                'active_connections': 10,  # Placeholder
                'requests_per_minute': 50,  # Placeholder
                'error_rate': 2.5  # Placeholder
            }

        self.metric_collector.register_collector('database', collect_database_metrics)
        self.metric_collector.register_collector('cache', collect_cache_metrics)
        self.metric_collector.register_collector('api', collect_api_metrics)

    def _register_default_alert_rules(self) -> None:
        """Register default alert rules."""

        # Database slow query alert
        self.alert_manager.add_alert_rule(AlertRule(
            title="High Number of Slow Database Queries",
            severity=AlertSeverity.WARNING,
            source="database_monitor",
            condition=lambda m: m.get('database.slow_queries', 0) > 10,
            message_template="Database has {metrics[database.slow_queries]} slow queries in the last minute"
        ))

        # Low cache hit rate alert
        self.alert_manager.add_alert_rule(AlertRule(
            title="Low Cache Hit Rate",
            severity=AlertSeverity.WARNING,
            source="cache_monitor",
            condition=lambda m: m.get('cache.hit_rate', 100) < 50,
            message_template="Cache hit rate is {metrics[cache.hit_rate]:.1f}%, below 50% threshold"
        ))

        # High API error rate alert
        self.alert_manager.add_alert_rule(AlertRule(
            title="High API Error Rate",
            severity=AlertSeverity.ERROR,
            source="api_monitor",
            condition=lambda m: m.get('api.error_rate', 0) > 10,
            message_template="API error rate is {metrics[api.error_rate]:.1f}%, above 10% threshold"
        ))

        # Database connection pool alert
        self.alert_manager.add_alert_rule(AlertRule(
            title="Database Connection Pool Near Capacity",
            severity=AlertSeverity.WARNING,
            source="database_monitor",
            condition=lambda m: m.get('database.connection_pool_usage', 0) > 80,
            message_template="Database connection pool usage is {metrics[database.connection_pool_usage]:.1f}%"
        ))

    async def start_monitoring(self) -> None:
        """Start the monitoring loop."""
        if self.running:
            return

        self.running = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("System monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self.running = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
        logger.info("System monitoring stopped")

    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.running:
            try:
                # Collect all metrics
                await self.metric_collector.collect_all_metrics()

                # Get current metric values for alert evaluation
                current_metrics = {}
                for metric_name in self.metric_collector.metrics:
                    stats = self.metric_collector.get_metric_stats(metric_name, hours=0.1)  # Last 6 minutes
                    current_metrics[metric_name] = stats.get('latest', 0)

                # Evaluate alert rules
                await self.alert_manager.evaluate_alert_rules(current_metrics)

                # Wait for next interval
                await asyncio.sleep(self.monitoring_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.monitoring_interval)

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        # Collect current metrics
        current_metrics = {}
        for metric_name in self.metric_collector.metrics:
            stats = self.metric_collector.get_metric_stats(metric_name, hours=1)
            current_metrics[metric_name] = stats

        # Get active alerts
        active_alerts = self.alert_manager.get_active_alerts()
        alert_counts = {
            'total': len(active_alerts),
            'critical': len([a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]),
            'error': len([a for a in active_alerts if a.severity == AlertSeverity.ERROR]),
            'warning': len([a for a in active_alerts if a.severity == AlertSeverity.WARNING]),
            'info': len([a for a in active_alerts if a.severity == AlertSeverity.INFO])
        }

        # Determine overall system health
        overall_health = 'healthy'
        if alert_counts['critical'] > 0:
            overall_health = 'critical'
        elif alert_counts['error'] > 0:
            overall_health = 'error'
        elif alert_counts['warning'] > 0:
            overall_health = 'warning'

        return {
            'status': overall_health,
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': current_metrics,
            'alerts': {
                'active': [alert.to_dict() for alert in active_alerts[:10]],  # Latest 10
                'counts': alert_counts
            },
            'monitoring': {
                'running': self.running,
                'interval_seconds': self.monitoring_interval,
                'metric_collectors': len(self.metric_collector.collectors),
                'alert_rules': len(self.alert_manager.alert_rules)
            }
        }


# Global system monitor instance
system_monitor = SystemMonitor()


# Utility functions
def create_alert(severity: AlertSeverity, title: str, message: str,
                source: str = "manual", metadata: Dict[str, Any] = None) -> Alert:
    """Create a manual alert."""
    return system_monitor.alert_manager.create_alert(
        severity, title, message, source, metadata
    )


def get_system_metrics(hours: int = 1) -> Dict[str, Any]:
    """Get system metrics for specified time period."""
    metrics = {}
    for metric_name in system_monitor.metric_collector.metrics:
        metrics[metric_name] = system_monitor.metric_collector.get_metric_stats(metric_name, hours)
    return metrics


def get_active_alerts(severity: AlertSeverity = None) -> List[Dict[str, Any]]:
    """Get active alerts."""
    alerts = system_monitor.alert_manager.get_active_alerts(severity)
    return [alert.to_dict() for alert in alerts]


# Export main components
__all__ = [
    'AlertSeverity',
    'Alert',
    'MetricCollector',
    'AlertManager',
    'AlertRule',
    'NotificationChannel',
    'EmailNotificationChannel',
    'WebhookNotificationChannel',
    'SystemMonitor',
    'system_monitor',
    'create_alert',
    'get_system_metrics',
    'get_active_alerts'
]
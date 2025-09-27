#!/usr/bin/env python3
"""
Celery Beat Scheduler for Bug Bounty Platform
backend/celery-beat/beat-scheduler.py

Manages periodic task scheduling for security scanning operations.
"""

import os
import sys
import logging
from pathlib import Path

# Add Django project to Python path
sys.path.insert(0, '/app')

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Setup Django
import django
django.setup()

from celery.schedules import crontab
from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule
from django.utils import timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/celery-beat.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class BugBountyBeatScheduler:
    """Enhanced Beat Scheduler for Bug Bounty Platform"""

    def __init__(self):
        self.scheduled_tasks = []

    def setup_security_scanning_schedules(self):
        """Setup periodic security scanning tasks"""

        # Continuous monitoring tasks
        self.create_interval_task(
            name='continuous-subdomain-monitoring',
            task='apps.reconnaissance.tasks.continuous_subdomain_monitoring',
            interval_minutes=30,  # Every 30 minutes
            description='Monitor subdomains for active targets'
        )

        # Daily comprehensive scans
        self.create_crontab_task(
            name='daily-comprehensive-scan',
            task='apps.scanning.tasks.daily_comprehensive_scan',
            hour=2,  # 2 AM daily
            minute=0,
            description='Run comprehensive daily scans for all active targets'
        )

        # Weekly vulnerability database updates
        self.create_crontab_task(
            name='weekly-nuclei-template-update',
            task='backend.tools.tasks.update_nuclei_templates',
            hour=1,  # 1 AM
            minute=0,
            day_of_week=1,  # Monday
            description='Update Nuclei vulnerability templates weekly'
        )

        # Certificate transparency monitoring
        self.create_interval_task(
            name='certificate-transparency-monitoring',
            task='apps.reconnaissance.tasks.certificate_transparency_monitoring',
            interval_hours=6,  # Every 6 hours
            description='Monitor certificate transparency logs'
        )

    def setup_maintenance_schedules(self):
        """Setup system maintenance and cleanup tasks"""

        # Daily cleanup tasks
        self.create_crontab_task(
            name='daily-cleanup',
            task='apps.scanning.tasks.cleanup_old_results',
            hour=3,  # 3 AM daily
            minute=0,
            description='Clean up old scan results and temporary files'
        )

        # Weekly report generation
        self.create_crontab_task(
            name='weekly-security-report',
            task='apps.reporting.tasks.generate_weekly_security_report',
            hour=6,  # 6 AM
            minute=0,
            day_of_week=1,  # Monday
            description='Generate weekly security summary reports'
        )

        # Database optimization
        self.create_crontab_task(
            name='weekly-database-optimization',
            task='apps.core.tasks.optimize_database',
            hour=4,  # 4 AM
            minute=0,
            day_of_week=0,  # Sunday
            description='Optimize database performance weekly'
        )

    def setup_monitoring_schedules(self):
        """Setup system monitoring tasks"""

        # Health checks every 15 minutes
        self.create_interval_task(
            name='system-health-check',
            task='backend.tools.tasks.system_health_check',
            interval_minutes=15,
            description='Check system health and tool availability'
        )

        # Resource utilization monitoring
        self.create_interval_task(
            name='resource-monitoring',
            task='apps.core.tasks.monitor_resource_utilization',
            interval_minutes=5,
            description='Monitor CPU, memory, and disk usage'
        )

        # Target status updates
        self.create_interval_task(
            name='target-status-updates',
            task='apps.targets.tasks.update_target_statuses',
            interval_hours=1,
            description='Update target availability and status'
        )

    def setup_notification_schedules(self):
        """Setup notification and alerting tasks"""

        # Critical vulnerability alerts (immediate)
        self.create_interval_task(
            name='critical-vulnerability-alerts',
            task='apps.vulnerabilities.tasks.send_critical_alerts',
            interval_minutes=5,
            description='Send immediate alerts for critical vulnerabilities'
        )

        # Daily digest notifications
        self.create_crontab_task(
            name='daily-digest-notifications',
            task='apps.reporting.tasks.send_daily_digest',
            hour=8,  # 8 AM daily
            minute=0,
            description='Send daily digest to stakeholders'
        )

    def create_interval_task(self, name, task, interval_minutes=None, interval_hours=None,
                           description=None, **kwargs):
        """Create or update an interval-based periodic task"""
        try:
            # Determine interval
            if interval_minutes:
                schedule, _ = IntervalSchedule.objects.get_or_create(
                    every=interval_minutes,
                    period=IntervalSchedule.MINUTES
                )
            elif interval_hours:
                schedule, _ = IntervalSchedule.objects.get_or_create(
                    every=interval_hours,
                    period=IntervalSchedule.HOURS
                )
            else:
                raise ValueError("Must specify either interval_minutes or interval_hours")

            # Create or update periodic task
            periodic_task, created = PeriodicTask.objects.get_or_create(
                name=name,
                defaults={
                    'task': task,
                    'interval': schedule,
                    'enabled': True,
                    'description': description or f'Automated task: {task}',
                    **kwargs
                }
            )

            if not created:
                periodic_task.task = task
                periodic_task.interval = schedule
                periodic_task.enabled = True
                periodic_task.description = description or periodic_task.description
                periodic_task.save()

            status = 'Created' if created else 'Updated'
            logger.info(f"{status} interval task: {name}")
            self.scheduled_tasks.append(name)

        except Exception as e:
            logger.error(f"Error creating interval task {name}: {e}")

    def create_crontab_task(self, name, task, hour=0, minute=0, day_of_week='*',
                           day_of_month='*', month_of_year='*', description=None, **kwargs):
        """Create or update a crontab-based periodic task"""
        try:
            # Create crontab schedule
            schedule, _ = CrontabSchedule.objects.get_or_create(
                minute=minute,
                hour=hour,
                day_of_week=day_of_week,
                day_of_month=day_of_month,
                month_of_year=month_of_year
            )

            # Create or update periodic task
            periodic_task, created = PeriodicTask.objects.get_or_create(
                name=name,
                defaults={
                    'task': task,
                    'crontab': schedule,
                    'enabled': True,
                    'description': description or f'Automated task: {task}',
                    **kwargs
                }
            )

            if not created:
                periodic_task.task = task
                periodic_task.crontab = schedule
                periodic_task.enabled = True
                periodic_task.description = description or periodic_task.description
                periodic_task.save()

            status = 'Created' if created else 'Updated'
            logger.info(f"{status} crontab task: {name}")
            self.scheduled_tasks.append(name)

        except Exception as e:
            logger.error(f"Error creating crontab task {name}: {e}")

    def initialize_all_schedules(self):
        """Initialize all periodic task schedules"""
        logger.info("Initializing Bug Bounty Platform periodic tasks...")

        self.setup_security_scanning_schedules()
        self.setup_maintenance_schedules()
        self.setup_monitoring_schedules()
        self.setup_notification_schedules()

        logger.info(f"Successfully initialized {len(self.scheduled_tasks)} periodic tasks")
        for task in self.scheduled_tasks:
            logger.info(f"  - {task}")

def main():
    """Main entry point"""
    # Create logs directory if it doesn't exist
    Path('/app/logs').mkdir(parents=True, exist_ok=True)

    # Initialize scheduler
    scheduler = BugBountyBeatScheduler()
    scheduler.initialize_all_schedules()

    logger.info("Beat scheduler initialization completed")

if __name__ == '__main__':
    main()
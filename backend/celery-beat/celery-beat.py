#!/usr/bin/env python3
"""
Celery Beat Service for Bug Bounty Platform
backend/celery-beat/celery-beat.py

Enhanced beat service with monitoring and error handling.
"""

import os
import sys
import signal
import logging
from pathlib import Path

# Add Django project to Python path
sys.path.insert(0, '/app')

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Setup Django
import django
django.setup()

from celery.beat import Service
from celery.signals import beat_init, beat_embedded_init
from django.conf import settings

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

# Import Celery app
from config.celery import app as celery_app

class BugBountyCeleryBeat:
    """Enhanced Celery Beat service with monitoring"""

    def __init__(self):
        self.app = celery_app
        self.service = None
        self.setup_signal_handlers()
        self.setup_beat_hooks()

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down gracefully...")
            if self.service:
                self.service.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def setup_beat_hooks(self):
        """Setup Celery beat event hooks"""

        @beat_init.connect
        def beat_init_handler(sender=None, **kwargs):
            logger.info("Celery Beat initialized for Bug Bounty Platform")

        @beat_embedded_init.connect
        def beat_embedded_init_handler(sender=None, **kwargs):
            logger.info("Celery Beat embedded service initialized")

    def start_beat(self, argv=None):
        """Start the Celery beat service"""
        if argv is None:
            argv = [
                'beat',
                '--loglevel=info',
                '--scheduler=django_celery_beat.schedulers:DatabaseScheduler',
                '--pidfile=/tmp/celerybeat.pid'
            ]

        logger.info(f"Starting Celery Beat with args: {argv}")

        # Initialize beat scheduler tasks
        self.initialize_periodic_tasks()

        try:
            # Start the beat service
            self.service = Service(
                app=self.app,
                max_interval=None,
                schedule_filename='/app/celerybeat-schedule/celerybeat-schedule.db',
                scheduler_cls='django_celery_beat.schedulers:DatabaseScheduler'
            )

            logger.info("Celery Beat service starting...")
            self.service.start()

        except KeyboardInterrupt:
            logger.info("Beat service interrupted by user")
        except Exception as e:
            logger.error(f"Beat service failed: {e}")
            raise

    def initialize_periodic_tasks(self):
        """Initialize periodic tasks using the beat scheduler"""
        try:
            from beat_scheduler import BugBountyBeatScheduler
            scheduler = BugBountyBeatScheduler()
            scheduler.initialize_all_schedules()
            logger.info("Periodic tasks initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize periodic tasks: {e}")

    def get_beat_status(self):
        """Get current beat service status"""
        if self.service:
            return {
                'service_active': True,
                'scheduler': self.service.scheduler.__class__.__name__,
                'schedule_file': self.service.schedule_filename,
                'pid': os.getpid()
            }
        return {'service_active': False}

def main():
    """Main entry point"""
    # Create logs directory if it doesn't exist
    Path('/app/logs').mkdir(parents=True, exist_ok=True)
    Path('/app/celerybeat-schedule').mkdir(parents=True, exist_ok=True)

    # Initialize beat service
    beat = BugBountyCeleryBeat()

    # Start beat service with command line arguments
    beat.start_beat(sys.argv[1:] if len(sys.argv) > 1 else None)

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Celery Worker Startup Script for Bug Bounty Platform
backend/celery/celery-worker.py

Enhanced worker with monitoring and error handling.
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

from celery import Celery
from celery.signals import (
    worker_ready, worker_shutdown, task_prerun,
    task_postrun, task_failure, task_retry
)
from django.conf import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/celery-worker.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Import Celery app
from config.celery import app as celery_app

class BugBountyCeleryWorker:
    """Enhanced Celery Worker with monitoring and error handling"""

    def __init__(self):
        self.app = celery_app
        self.setup_signal_handlers()
        self.setup_worker_hooks()

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down gracefully...")
            self.app.control.broadcast('shutdown')
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def setup_worker_hooks(self):
        """Setup Celery worker event hooks"""

        @worker_ready.connect
        def worker_ready_handler(sender=None, **kwargs):
            logger.info("Celery worker ready for Bug Bounty Platform")
            logger.info(f"Worker PID: {os.getpid()}")
            logger.info(f"Concurrency: {self.app.conf.worker_concurrency}")
            logger.info(f"Queues: {[q.name for q in self.app.conf.task_queues]}")

        @worker_shutdown.connect
        def worker_shutdown_handler(sender=None, **kwargs):
            logger.info("Celery worker shutting down...")

        @task_prerun.connect
        def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
            logger.info(f"Task {task.name}[{task_id}] starting")

        @task_postrun.connect
        def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None,
                               retval=None, state=None, **kwds):
            logger.info(f"Task {task.name}[{task_id}] finished with state: {state}")

        @task_failure.connect
        def task_failure_handler(sender=None, task_id=None, exception=None, traceback=None,
                                einfo=None, **kwds):
            logger.error(f"Task {sender.name}[{task_id}] failed: {exception}")
            logger.error(f"Traceback: {traceback}")

        @task_retry.connect
        def task_retry_handler(sender=None, task_id=None, reason=None, einfo=None, **kwds):
            logger.warning(f"Task {sender.name}[{task_id}] retrying: {reason}")

    def start_worker(self, argv=None):
        """Start the Celery worker"""
        if argv is None:
            argv = [
                'worker',
                '--loglevel=info',
                f'--concurrency={os.getenv("CELERY_WORKER_CONCURRENCY", 4)}',
                '--max-tasks-per-child=50',
                '--without-gossip',
                '--without-mingle',
                '--without-heartbeat'
            ]

        # Add queues if specified
        queues = os.getenv('CELERY_QUEUES', '').split(',')
        if queues and queues[0]:
            argv.extend(['-Q', ','.join(queues)])

        logger.info(f"Starting Celery worker with args: {argv}")

        try:
            self.app.worker_main(argv)
        except KeyboardInterrupt:
            logger.info("Worker interrupted by user")
        except Exception as e:
            logger.error(f"Worker failed: {e}")
            raise

def main():
    """Main entry point"""
    # Create logs directory if it doesn't exist
    Path('/app/logs').mkdir(parents=True, exist_ok=True)

    # Initialize worker
    worker = BugBountyCeleryWorker()

    # Start worker with command line arguments
    worker.start_worker(sys.argv[1:] if len(sys.argv) > 1 else None)

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Flower Enhanced Dashboard for Bug Bounty Platform
backend/flower/flower-dashboard.py

Custom Flower extensions and dashboard enhancements.
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta

# Add Django project to Python path
sys.path.insert(0, '/app')

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Setup Django
import django
django.setup()

from celery import Celery
from flower.views import BaseHandler
from tornado.web import authenticated
import tornado.gen

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BugBountyDashboardHandler(BaseHandler):
    """Custom dashboard handler for Bug Bounty Platform"""

    @authenticated
    @tornado.gen.coroutine
    def get(self):
        """Render custom Bug Bounty dashboard"""

        # Get application stats
        app = self.application.capp
        inspect = app.control.inspect()

        # Collect worker statistics
        stats = inspect.stats() or {}
        active_tasks = inspect.active() or {}
        scheduled_tasks = inspect.scheduled() or {}
        reserved_tasks = inspect.reserved() or {}

        # Calculate platform-specific metrics
        dashboard_data = {
            'workers': {
                'total': len(stats),
                'active': len([w for w in stats if stats[w]]),
                'offline': len([w for w in stats if not stats[w]])
            },
            'tasks': {
                'active': sum(len(tasks) for tasks in active_tasks.values()),
                'scheduled': sum(len(tasks) for tasks in scheduled_tasks.values()),
                'reserved': sum(len(tasks) for tasks in reserved_tasks.values())
            },
            'categories': self._get_task_categories(active_tasks),
            'recent_activity': self._get_recent_activity(),
            'system_health': self._get_system_health(stats)
        }

        self.render('bugbounty_dashboard.html', dashboard_data=dashboard_data)

    def _get_task_categories(self, active_tasks):
        """Categorize active tasks by Bug Bounty operation type"""
        categories = {
            'reconnaissance': 0,
            'scanning': 0,
            'analysis': 0,
            'exploitation': 0,
            'reporting': 0,
            'other': 0
        }

        for worker, tasks in active_tasks.items():
            for task in tasks:
                task_name = task.get('name', '')

                if 'reconnaissance' in task_name:
                    categories['reconnaissance'] += 1
                elif 'scanning' in task_name:
                    categories['scanning'] += 1
                elif 'vulnerabilities' in task_name:
                    categories['analysis'] += 1
                elif 'exploitation' in task_name:
                    categories['exploitation'] += 1
                elif 'reporting' in task_name:
                    categories['reporting'] += 1
                else:
                    categories['other'] += 1

        return categories

    def _get_recent_activity(self):
        """Get recent task activity for dashboard"""
        try:
            # In a real implementation, this would query the Django database
            # For now, return sample data structure
            return {
                'completed_today': 0,
                'failed_today': 0,
                'success_rate': 0.0,
                'avg_execution_time': 0.0
            }
        except Exception as e:
            logger.error(f"Error getting recent activity: {e}")
            return {}

    def _get_system_health(self, worker_stats):
        """Calculate system health metrics"""
        if not worker_stats:
            return {'status': 'unknown', 'issues': []}

        total_workers = len(worker_stats)
        healthy_workers = 0
        issues = []

        for worker, stats in worker_stats.items():
            if stats and 'rusage' in stats:
                # Check memory usage
                memory_percent = stats.get('rusage', {}).get('maxrss', 0) / (1024 * 1024)  # Convert to MB
                if memory_percent > 512:  # 512MB threshold
                    issues.append(f"High memory usage on {worker}: {memory_percent:.1f}MB")

                # Check CPU usage
                cpu_percent = stats.get('rusage', {}).get('utime', 0)
                if cpu_percent > 80:  # 80% threshold
                    issues.append(f"High CPU usage on {worker}: {cpu_percent:.1f}%")

                if not issues:
                    healthy_workers += 1

        health_percentage = (healthy_workers / total_workers) * 100 if total_workers > 0 else 0

        if health_percentage >= 90:
            status = 'excellent'
        elif health_percentage >= 70:
            status = 'good'
        elif health_percentage >= 50:
            status = 'fair'
        else:
            status = 'poor'

        return {
            'status': status,
            'percentage': health_percentage,
            'issues': issues[:5]  # Limit to top 5 issues
        }

class BugBountyTasksHandler(BaseHandler):
    """Custom tasks handler with Bug Bounty specific filtering"""

    @authenticated
    @tornado.gen.coroutine
    def get(self):
        """Get tasks with Bug Bounty specific formatting"""

        app = self.application.capp
        inspect = app.control.inspect()

        # Get all task types
        active_tasks = inspect.active() or {}
        scheduled_tasks = inspect.scheduled() or {}
        reserved_tasks = inspect.reserved() or {}

        # Format tasks for Bug Bounty operations
        formatted_tasks = []

        # Process active tasks
        for worker, tasks in active_tasks.items():
            for task in tasks:
                formatted_task = self._format_task(task, 'active', worker)
                formatted_tasks.append(formatted_task)

        # Process scheduled tasks
        for worker, tasks in scheduled_tasks.items():
            for task in tasks:
                formatted_task = self._format_task(task, 'scheduled', worker)
                formatted_tasks.append(formatted_task)

        # Process reserved tasks
        for worker, tasks in reserved_tasks.items():
            for task in tasks:
                formatted_task = self._format_task(task, 'reserved', worker)
                formatted_tasks.append(formatted_task)

        # Sort by timestamp
        formatted_tasks.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

        self.write(json.dumps({
            'tasks': formatted_tasks[:100],  # Limit to 100 most recent
            'total': len(formatted_tasks)
        }))

    def _format_task(self, task, state, worker):
        """Format task with Bug Bounty specific information"""
        task_name = task.get('name', 'Unknown')

        # Determine category
        category = 'other'
        if 'reconnaissance' in task_name:
            category = 'reconnaissance'
        elif 'scanning' in task_name:
            category = 'scanning'
        elif 'vulnerabilities' in task_name:
            category = 'analysis'
        elif 'exploitation' in task_name:
            category = 'exploitation'
        elif 'reporting' in task_name:
            category = 'reporting'

        # Extract target information
        args = task.get('args', [])
        target = 'N/A'
        if args and len(args) > 0:
            if isinstance(args[0], dict) and 'target' in args[0]:
                target = args[0]['target']
            elif isinstance(args[0], str):
                target = args[0]

        return {
            'id': task.get('id'),
            'name': task_name,
            'state': state,
            'worker': worker,
            'category': category,
            'target': target,
            'timestamp': task.get('time_start', 0),
            'args': str(args)[:100] if args else '',
            'kwargs': str(task.get('kwargs', {}))[:100]
        }

class BugBountyMetricsHandler(BaseHandler):
    """Custom metrics handler for Bug Bounty operations"""

    @authenticated
    @tornado.gen.coroutine
    def get(self):
        """Get Bug Bounty specific metrics"""

        try:
            # In a real implementation, this would query Django models
            metrics = {
                'targets_scanned_today': 0,
                'vulnerabilities_found_today': 0,
                'active_scans': 0,
                'queue_sizes': {
                    'reconnaissance': 0,
                    'scanning': 0,
                    'analysis': 0,
                    'exploitation': 0,
                    'reporting': 0
                },
                'worker_utilization': 0.0,
                'avg_scan_time': 0.0
            }

            self.write(json.dumps(metrics))

        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            self.write(json.dumps({'error': str(e)}))

def setup_custom_handlers(flower_app):
    """Setup custom handlers for Bug Bounty Platform"""

    # Add custom URL patterns
    custom_handlers = [
        (r"/bugbounty/dashboard", BugBountyDashboardHandler),
        (r"/api/bugbounty/tasks", BugBountyTasksHandler),
        (r"/api/bugbounty/metrics", BugBountyMetricsHandler),
    ]

    # Insert custom handlers into Flower app
    flower_app.handlers[0][1].extend(custom_handlers)

    logger.info("Custom Bug Bounty handlers registered with Flower")

def main():
    """Main entry point for custom dashboard setup"""
    logger.info("Setting up Bug Bounty Platform Flower dashboard extensions...")

if __name__ == '__main__':
    main()
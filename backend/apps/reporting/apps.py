from django.apps import AppConfig

class ReportingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.reporting'
    verbose_name = 'Report Generation'

    def ready(self):
        # Import signal handlers and tasks
        import apps.reporting.signals
        import apps.reporting.tasks

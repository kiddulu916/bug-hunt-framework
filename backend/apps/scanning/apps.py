from django.apps import AppConfig

class ScanningConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.scanning'
    verbose_name = 'Scan Management'
    
    def ready(self):
        # Import signal handlers
        import apps.scanning.signals
        # Tasks will be imported when needed by Celery
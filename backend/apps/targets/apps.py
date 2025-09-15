from django.apps import AppConfig

class TargetsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.targets'
    verbose_name = 'Target Management'

    def ready(self):
        # Import signal handlers
        import apps.targets.signals

from django.apps import AppConfig

class ReconnaissanceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.reconnaissance'
    verbose_name = 'Reconnaissance'
    
    def ready(self):
        # Import signal handlers
        import apps.reconnaissance.signals

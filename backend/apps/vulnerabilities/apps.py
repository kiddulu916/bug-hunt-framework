from django.apps import AppConfig


class VulnerabilitiesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.vulnerabilities'
    verbose_name = 'Vulnerability Management'

    def ready(self):
        # Import signal handlers
        import apps.vulnerabilities.signals

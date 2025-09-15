# Signal handlers for scanning app
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import ScanSession


@receiver(post_save, sender=ScanSession)
def scan_post_save(sender, instance, created, **kwargs):
    """Handle scan creation/update"""
    if created:
        # Log scan creation
        print(f"New scan created: {instance.session_name}")
    else:
        # Log scan update
        print(f"Scan updated: {instance.session_name}")


@receiver(pre_delete, sender=ScanSession)
def scan_pre_delete(sender, instance, **kwargs):
    """Handle scan deletion"""
    print(f"Scan being deleted: {instance.session_name}")

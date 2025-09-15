# Signal handlers for reconnaissance app
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import ReconResult


@receiver(post_save, sender=ReconResult)
def reconnaissance_post_save(sender, instance, created, **kwargs):
    """Handle reconnaissance result creation/update"""
    if created:
        # Log result creation
        print(f"New reconnaissance result created: {instance.value}")
    else:
        # Log result update
        print(f"Reconnaissance result updated: {instance.value}")


@receiver(pre_delete, sender=ReconResult)
def reconnaissance_pre_delete(sender, instance, **kwargs):
    """Handle reconnaissance result deletion"""
    print(f"Reconnaissance result being deleted: {instance.value}")

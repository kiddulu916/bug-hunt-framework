# Signal handlers for vulnerabilities app
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import Vulnerability


@receiver(post_save, sender=Vulnerability)
def vulnerability_post_save(sender, instance, created, **kwargs):
    """Handle vulnerability creation/update"""
    if created:
        # Log vulnerability creation
        print(f"New vulnerability created: {instance.title}")
    else:
        # Log vulnerability update
        print(f"Vulnerability updated: {instance.title}")


@receiver(pre_delete, sender=Vulnerability)
def vulnerability_pre_delete(sender, instance, **kwargs):
    """Handle vulnerability deletion"""
    print(f"Vulnerability being deleted: {instance.title}")

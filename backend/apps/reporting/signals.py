# Signal handlers for reporting app
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import Report


@receiver(post_save, sender=Report)
def report_post_save(sender, instance, created, **kwargs):
    """Handle report creation/update"""
    if created:
        # Log report creation
        print(f"New report created: {instance.title}")
    else:
        # Log report update
        print(f"Report updated: {instance.title}")


@receiver(pre_delete, sender=Report)
def report_pre_delete(sender, instance, **kwargs):
    """Handle report deletion"""
    print(f"Report being deleted: {instance.title}")

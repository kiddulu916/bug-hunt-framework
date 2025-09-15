# Signal handlers for targets app
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import Target


@receiver(post_save, sender=Target)
def target_post_save(sender, instance, created, **kwargs):
    """Handle target creation/update"""
    if created:
        # Log target creation
        print(f"New target created: {instance.target_name}")
    else:
        # Log target update
        print(f"Target updated: {instance.target_name}")


@receiver(pre_delete, sender=Target)
def target_pre_delete(sender, instance, **kwargs):
    """Handle target deletion"""
    print(f"Target being deleted: {instance.target_name}")

from django.dispatch import receiver
from django.db.models.signals import post_save

from .models import Testimony

@receiver(post_save, sender=Testimony)
def increase_comments(sender, instance, created, **kwargs):
    if created:
        pass
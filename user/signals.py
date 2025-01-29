from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.crypto import get_random_string
from .models import User, EntryCode


@receiver(post_save, sender=User)
def create_entry_code(sender, instance, created, **kwargs):
    if created:
        while True:
            # Generate a unique 6-digit code
            code = get_random_string(length=6, allowed_chars='0123456789')
            if not EntryCode.objects.filter(code=code).exists():
                break

        # Create the EntryCode object
        EntryCode.objects.create(user=instance, code=code)

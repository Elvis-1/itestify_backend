from django.db.models.signals import post_save
from django.dispatch import receiver
from .utils import Util 
from .models import User, EntryCode


@receiver(post_save, sender=User)
def create_entry_code(sender, instance, created, **kwargs):
    if created:
        while True:
            # Generate a unique 6-digit code
            code = Util.generate_entry_code()
            if not EntryCode.objects.filter(code=code).exists():
                break

        # Create the EntryCode object
        EntryCode.objects.create(user=instance, code=code)

from django.db.models.signals import post_save, post_migrate, post_delete
from django.dispatch import receiver
from django.core.cache import cache
from .utils import Util 
from .models import User, EntryCode, Role


@receiver(post_save, sender=User)
def create_entry_code(sender, instance, created, **kwargs):
    if created and instance.role == "Admin":
        while True:
            # Generate a unique 6-digit code
            code = Util.generate_entry_code()
            if not EntryCode.objects.filter(code=code).exists():
                break

            # Create the EntryCode object
        EntryCode.objects.create(user=instance, code=code)


@receiver(post_save, sender=Role)
@receiver(post_delete, sender=Role)
def clear_roles_cache(sender, **kwargs):
    cache.delete("all_roles")

@receiver(post_migrate)
def create_default_roles(sender, **kwargs):
    Role.objects.get_or_create(name='Super Admin')
    Role.objects.get_or_create(name='User')

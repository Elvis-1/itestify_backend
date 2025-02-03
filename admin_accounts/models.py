from django.db import models
from django.utils.timezone import now
from datetime import timedelta

class AdminInvitationCode(models.Model):
    email = models.EmailField(unique=True)  # Email of the new admin
    code = models.CharField(max_length=6, unique=True)  # 6-digit invitation code
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp of creation
    is_used = models.BooleanField(default=False)  # To check if the code is already used

    def is_expired(self):
        """
        Check if the code has expired (valid for 24 hours).
        """
        return now() > self.created_at + timedelta(hours=24)

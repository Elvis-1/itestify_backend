import uuid
from django.db import models
# from django.conf import settings
from user.models import User
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from user.models import Role
# Create your models here.


class Notification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length = 20, null = True, blank = True)
    target = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name='target')
    owner = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name='owner')
    redirect_url = models.URLField(max_length=500, null=True, unique=False,
                                   blank=True, help_text="The URL to redirect to when to clicked")
    verb = models.CharField(
        max_length=255, unique=False, blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    content_type = models.ForeignKey(
        ContentType, on_delete=models.SET_NULL, null=True)
    object_id = models.UUIDField()
    content_object = GenericForeignKey('content_type', 'object_id')

    def __str__(self):
        return self.verb

    def get_content_object_type(self):
        return str(self.content_object.get_cname)

from datetime import datetime
import json
import math
import uuid
from django.db import models
from itestify_backend.mixims import TouchDatesMixim
from user.models import User
from testimonies.models import UPLOAD_STATUS
from django.db.models.signals import post_save
from django.dispatch import receiver
from django_celery_beat.models import PeriodicTask, CrontabSchedule

# Create your models here.


class BibleVersion(models.TextChoices):
    KJV = "KJV", "King James Version"
    NIV = "NIV", "New International Version"
    ESV = "ESV", "English Standard Version"
    NLT = "NLT", "New Living Translation"
    CSB = "CSB", "Christian Standard Bible"
    NASB = "NASB", "New American Standard Bible"
    NKJV = "NKJV", "New King James Version"


# SCRIPTURE MODEL/TABLE
class Scriptures(TouchDatesMixim):
    uploaded_by = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name='user_comment')
    bible_text = models.CharField(max_length=30, null=True, blank=True)
    scripture = models.TextField(null=True, blank=True)
    schedule_date = models.DateTimeField(null=True, blank=True)
    bible_version = models.CharField(
        choices=BibleVersion.choices, null=True, blank=True, max_length=30)
    prayer = models.TextField(null=True, blank=True)
    status = models.CharField(
        choices=UPLOAD_STATUS.choices, null=True, blank=True, max_length=30)
    like_scripture = models.ManyToManyField(User, blank=True)

    def __str__(self):
        return self.bible_text

    def get_commented_scripture(self):
        return self.scripturecomment_set.all()

# SCRIPTURE COMMENTS MODEL/TABLE


class ScriptureComment(TouchDatesMixim):
    scripture = models.ForeignKey(
        Scriptures, on_delete=models.CASCADE, null=True, blank=True, related_name='comment')
    commented_by = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name='commented_by')
    comment = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.commented_by.full_name


def clean_value(v):
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        return v
    elif isinstance(v, datetime):
        return v.isoformat()
    elif isinstance(v, uuid.UUID):  # 🛠️ Add this check
        return str(v)
    elif isinstance(v, dict):
        return {k: clean_value(val) for k, val in v.items()}
    elif isinstance(v, list):
        return [clean_value(i) for i in v]
    return v


# Function That Automate Schedule task on Creation of Scripture
@receiver(post_save, sender=Scriptures)
def post_scripture(sender, instance, created, **kwargs):
    if created:
        if instance.schedule_date:
            if isinstance(instance.schedule_date, str):
                instance.schedule_date = datetime.strptime(
                    instance.schedule_date, "%Y-%m-%d %H:%M:%S")
            schedule, created = CrontabSchedule.objects.get_or_create(
                hour=instance.schedule_date.hour, minute=instance.schedule_date.minute, day_of_month=instance.schedule_date.day, month_of_year=instance.schedule_date.month)
            task = PeriodicTask.objects.create(
                crontab=schedule, name=f"schedule-id-{instance.id}", task="scriptures.tasks.schedule_scripture", args=json.dumps((clean_value(instance.id), )))
        else:
            print("No schedule date provided for this scripture.")

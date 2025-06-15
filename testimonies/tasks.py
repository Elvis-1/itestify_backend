from celery import shared_task
from django.utils.timezone import now
from .models import VideoTestimony, UPLOAD_STATUS
from datetime import timedelta, datetime



@shared_task
def upload_schedule_videos():
    # Fetch videos scheduled for later
    print("checking for scheduled videos...")

    scheduled_videos = VideoTestimony.objects.filter(
        upload_status="scheduled", 
    )

    for video in scheduled_videos:
        if video.scheduled_datetime + timedelta(hours=1) < (now() + timedelta(hours=1)):
            video.upload_status = "upload_now"
            video.save()

    return f"{scheduled_videos.count()} video(s) processed for upload."


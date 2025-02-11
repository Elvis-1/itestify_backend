from celery import shared_task
from django.utils.timezone import now
from .models import VideoTestimony


@shared_task
def upload_schedule_vidoes():
    # Fetch videos scheduled for later
    scheduled_videos = VideoTestimony.objects.filter(
        upload_status="schedule_for_later",
        scheduled_datetime__lte=now()   # Due for upload
    )
    
    for video in scheduled_videos:
        video.upload_status = "upload_now"
        video.save()

    return f"{scheduled_videos.count()} video(s) processed for upload."


@shared_task
def upload_video(video_id):
    try:
        video = VideoTestimony.objects.get(id=video_id)
        # Perform the upload logic here
        video.upload_status = VideoTestimony.UPLOAD_STATUS.UPLOAD_NOW
        video.save()
        print(f"Video with ID {video_id} uploaded successfully!")
    except VideoTestimony.DoesNotExist:
        print(f"Video with ID {video_id} does not exist.")
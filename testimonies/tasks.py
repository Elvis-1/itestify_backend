from celery import shared_task
from django.utils.timezone import now
from .models import VideoTestimony, UPLOAD_STATUS
from datetime import timedelta



@shared_task
def upload_schedule_videos():
    # Fetch videos scheduled for later
    print("checking for scheduled videos...")
    scheduled_videos = VideoTestimony.objects.filter(
        upload_status="scheduled",
        scheduled_datetime__lte=now() + timedelta(hours=1)   # Due for upload
    )

    for video in scheduled_videos:
        video.upload_status = "upload_now"
        video.save()

    return f"{scheduled_videos.count()} video(s) processed for upload."


@shared_task
def upload_video(video_id):
    try:
        video = VideoTestimony.objects.get(id=video_id)

        video.upload_status = UPLOAD_STATUS.UPLOAD_NOW.value
        video.save()
        print(f"Video with ID {video_id} uploaded successfully!")
    except VideoTestimony.DoesNotExist:
        print(f"Video with ID {video_id} does not exist.")

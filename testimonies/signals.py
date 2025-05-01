from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from datetime import datetime, timezone, timedelta
from .models import VideoTestimony, UPLOAD_STATUS
from .tasks import upload_video


@receiver(post_save, sender=VideoTestimony)
def schedule_video_upload(sender, instance, **kwargs):
    if instance.upload_status == UPLOAD_STATUS.SCHEDULE_LATER:
        # Get the scheduled time
        upload_time = instance.scheduled_datetime      
        
        # Ensure the time is in the future
        if upload_time > datetime.now(timezone.utc):
            # Schedule the task
            upload_video.apply_async((instance.id,), eta=upload_time)
            print(f"Scheduled upload for video {instance.id} at {upload_time}")
        else:   
            print(f"Cannot schedule video {instance.id} for a past time.")


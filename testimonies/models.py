from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericRelation
from itestify_backend.mixims import TouchDatesMixim
from user.models import User


class CATEGORY(models.TextChoices):
    HEALING = "healing", "healing"
    FINANCE = "finance", "finance"
    BREAKTHROUGH = "breakthrough", "breakthrough"
    PROTECTION = "protection", "protection"
    SALVATION = "salvation", "salvation"
    DELIVERANCE = "deliverance", "deliverance"
    RESTORATION = "restoration", "restoration"
    SPIRITUAL_GROWTH = "spiritual_growth", "spiritual growth"
    EDUCATION = "education", "education"
    CAREER = "career", "career"
    OTHER = "other", "other"


""" Base Testimony Class """

class Testimony(TouchDatesMixim):
    title = models.CharField(max_length=255, help_text="Enter Title")
    category = models.CharField(max_length=50, choices=CATEGORY.choices)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    rejection_reason = models.TextField(blank=True, null=True)
    likes = GenericRelation("Like")
    comments = GenericRelation("Comment")
    shares = GenericRelation("Share")

    class Meta:
        abstract = True

    def __str__(self):
        return f"Testimony by: {self.uploaded_by.full_name}"


class TestimonySettings(models.Model):
    notify_admin = models.BooleanField(default=True)

    def __str__(self):
        return "testimony_settings"

    
class TextTestimony(Testimony):
    
    class STATUS(models.TextChoices):
        PENDING = 'pending', 'pending'
        APPROVED = 'approved', 'approved'
        REJECTED = 'rejected', 'rejected'

    content = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS.choices, default=STATUS.PENDING)
    

class UPLOAD_STATUS(models.TextChoices):
        UPLOAD_NOW = "upload_now", "upload_now"
        SCHEDULE_LATER = "schedule_for_later", "schedule_for_later"
        DRAFT = "drafts", "drafts"



class VideoTestimony(Testimony):
    
    source = models.CharField(max_length=255, help_text="Video source")
    upload_status = models.CharField(max_length=225, choices=UPLOAD_STATUS.choices)
    video_file = models.FileField(upload_to='videos/', help_text="Upload video file")
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True, help_text="Upload thumbnail image or leave blank for auto-generated")
    auto_generate_thumbnail = models.BooleanField(default=True, help_text="Auto-generate thumbnail if no upload")
    scheduled_datetime = models.DateTimeField(
        blank=True, null=True, 
        help_text="Datetime for scheduling the upload (used only for 'Schedule for Later' status)"
    )
    
    
    

""" Base class for the socal interaction """

class SocialInteraction(TouchDatesMixim):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.UUIDField()
    content_object = GenericForeignKey('content_type', 'object_id')
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        abstract = True
        unique_together = ('content_type', 'object_id', 'user')

    def __str__(self):
        return f"{self.__class__.__name__} by {self.user.full_name}"


class Comment(SocialInteraction):
    text = models.TextField()


class Like(SocialInteraction):
    pass


class Share(SocialInteraction):
    pass


class InspirationalPictures(TouchDatesMixim):
    thumbnail = models.ImageField(upload_to="inspirational_picture/")
    status = models.CharField(max_length=225, choices=UPLOAD_STATUS.choices)
    shares = GenericRelation("Share")
    downloads_count = models.PositiveIntegerField(default=0)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    scheduled_datetime = models.DateTimeField(
        blank=True, null=True, 
        help_text="Datetime for scheduling the upload (used only for 'Schedule for Later' status)"
    )
    
    class Meta:
        verbose_name = "Inspirational Picture"
        verbose_name_plural = "Inspirational Pictures"
    
    def __str__(self):
        return f"Inspirational Picture uploaded by {self.uploaded_by}"
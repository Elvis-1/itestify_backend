from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericRelation
from itestify_backend.mixims import TouchDatesMixim
from user.models import User


class CATEGORY(models.TextChoices):
    HEALING = "Healing", "Healing"
    FINANCE = "Finance", "Finance"
    BREAKTHROUGH = "Breakthrough", "Breakthrough"
    PROTECTION = "Protection", "Protection"
    SALVATION = "Salvation", "Salvation"
    DELIVERANCE = "Deliverance", "Deliverance"
    RESTORATION = "Restoration", "Restoration"
    SPIRITUAL_GROWTH = "Spiritual_growth", "Spiritual growth"
    EDUCATION = "Education", "Education"
    CAREER = "Career", "Career"
    OTHER = "Other", "Other"


""" Base Testimony Class """


class UPLOAD_STATUS(models.TextChoices):
    UPLOAD_NOW = "upload_now", "upload_now"
    SCHEDULE_LATER = "scheduled", "scheduled"
    DRAFT = "drafts", "drafts"


class Testimony(TouchDatesMixim):
    title = models.CharField(max_length=255, help_text="Enter Title")
    category = models.CharField(
        max_length=50, choices=CATEGORY.choices, db_index=True)
    # upload_status = models.CharField(
    #    max_length=50, choices=UPLOAD_STATUS.choices, null=True, blank=True)
    uploaded_by = models.ForeignKey(
        User, on_delete=models.CASCADE)
    rejection_reason = models.TextField(blank=True, null=True)
    likes = GenericRelation("Like")
    comments = GenericRelation("Comment")
    shares = GenericRelation("Share")
    views = models.PositiveIntegerField(default=0, null=True, blank=True)

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
    status = models.CharField(
        max_length=20, choices=STATUS.choices, default=STATUS.PENDING, db_index=True)


class VideoTestimony(Testimony):

    source = models.CharField(
        max_length=255, help_text="Video source", null=True, blank=True)
    upload_status = models.CharField(
        max_length=225, choices=UPLOAD_STATUS.choices)
    video_file = models.URLField(null=True, blank=True)
    thumbnail = models.URLField(null=True, blank=True)
    auto_generate_thumbnail = models.BooleanField(
        default=True, help_text="Auto-generate thumbnail if no upload")
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
        # unique_together = ('content_type', 'object_id', 'user')
        unique_together = []

    def __str__(self):
        return f"{self.__class__.__name__} by {self.user.email}"


class Comment(SocialInteraction):
    text = models.TextField()
    reply_to = models.ForeignKey(
        'self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    user_like_comment = models.ManyToManyField(User, blank=True, related_name="user_like_comment")
    



class Like(SocialInteraction):
    pass


class Share(SocialInteraction):
    pass


class InspirationalPictures(TouchDatesMixim):
    thumbnail = models.ImageField(
        upload_to="inspirational_picture/", null=True, blank=True)
    source = models.CharField(
        max_length=255, help_text="Source of the inspirational picture", null=True, blank=True)
    like_inspirational_pic = models.ManyToManyField(User, blank=True, related_name="like_inspirational_pic")
    status = models.CharField(max_length=225, choices=UPLOAD_STATUS.choices, null=True, blank=True)
    shares_count = models.PositiveIntegerField(default=0)
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

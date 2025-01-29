from django.db import models
from itestify_backend.mixims import TouchDatesMixim


class TextTestimony(models.Model):
    CATEGORY_CHOICES = [
        ('Healing', 'Healing'),
        ('Deliverance', 'Deliverance'),
        ('Others', 'Others'),
    ]

    name = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    content = models.TextField()
    date_submitted = models.DateTimeField(auto_now_add=True)
    likes = models.PositiveIntegerField(default=0)
    comments = models.PositiveIntegerField(default=0)
    shares = models.PositiveIntegerField(default=0)
    status = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')],
        default='Pending'
    )
    rejection_reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name
    
    
class VideoTestimony(TouchDatesMixim):
    
    class UPLOAD_STATUS(models.TextChoices):
        UPLOAD_NOW = "now", "Upload Now"
        SCHEDULE_LATER = "later", "Schedule for Later"
        DRAFT = "draft", "Drafts"
        
    
    class CATEGORY(models.TextChoices):
        HEALING = "healing", "Healing"
        FINANCE = "finance", "Finance"
        BREAKTHROUGH = "breakthrough", "Breakthrough"
        PROTECTION = "protection", "Protection"
        SALVATION = "salvation", "Salvation"
        DELIVERANCE = "deliverance", "Deliverance"
        RESTORATION = "restoration", "Restoration"
        SPIRITUAL_GROWTH = "spiritual_growth", "Spiritual Growth"
        EDUCATION = "education", "Education"
        CAREER = "career", "Career"
    
    title = models.CharField(max_length=255, help_text="Enter Video Title")
    source = models.CharField(max_length=255, help_text="Video source")
    category = models.CharField(max_length=100, choices=CATEGORY.choices)
    upload_status = models.CharField(max_length=10, choices=UPLOAD_STATUS.choices)
    video_file = models.FileField(upload_to='videos/', help_text="Upload video file")
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True, help_text="Upload thumbnail image or leave blank for auto-generated")
    auto_generate_thumbnail = models.BooleanField(default=True, help_text="Auto-generate thumbnail if no upload")
    # uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True)


    def __str__(self):
        return self.title
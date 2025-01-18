from django.db import models

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
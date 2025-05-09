from django.db import models
from django.conf import settings
from django.utils import timezone

# Create your models here.

class Review(models.Model):
    RATING_CHOICES = [
        (1, '1 - Poor'),
        (2, '2 - Fair'),
        (3, '3 - Good'),
        (4, '4 - Very Good'),
        (5, '5 - Excellent'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    rating = models.PositiveSmallIntegerField(
        choices=RATING_CHOICES,
        help_text="Rating from 1 (Poor) to 5 (Excellent)"
    )
    message = models.TextField(
        blank=True,
        null=True,
        help_text="Optional review message"
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        editable=False
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Review"
        verbose_name_plural = "Reviews"
    
    def __str__(self):
        return f"Review by {self.user.email} - {self.get_rating_display()}"

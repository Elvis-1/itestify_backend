from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid


def generate_temp_review_id():
    #return f"RE-TEMP-{str(uuid.uuid4())[:8].upper()}"
    return f"{str(uuid.uuid4())[:8]}"


class Review(models.Model):
    RATING_CHOICES = [
        (1, '1 - Poor'),
        (2, '2 - Fair'),
        (3, '3 - Good'),
        (4, '4 - Very Good'),
        (5, '5 - Excellent'),
    ]

    id = models.CharField(
        max_length=20,
        primary_key=True,
        editable=False,
        unique=True,
        default=generate_temp_review_id
    )
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

    '''def save(self, *args, **kwargs):
        if self.id.startswith('RE-TEMP-'):
            # Get the count of existing reviews to generate the next ID
            count = Review.objects.count() + 1
            self.id = f"RE-{count:03d}"
        super().save(*args, **kwargs)'''





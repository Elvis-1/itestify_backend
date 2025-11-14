from django.db import models
from itestify_backend.mixims import TouchDatesMixim
from user.models import User
from django.core.validators import MinValueValidator

# Create your models here.


class DONATION_TYPE(models.TextChoices):
    BANK_TRANSFER = "bank_transfer", "Bank Transfer"
    CARD_PAYMENT = "card_payment", "Card Payment"


class DonationSetting(TouchDatesMixim):
    notify_admin = models.BooleanField(
        default=True,
        help_text="Enable to notify the admin after a user submits a donation for verification",
    )
    notify_user = models.BooleanField(
        default=True,
        help_text="Send a notification to users when a donation cannot be verified",
    )
    send_user_mail = models.BooleanField(
        default=True,
        help_text="Automatically send a thank-you email to users once their donation is verified",
    )
    donation_type = models.CharField(max_length=25, choices=DONATION_TYPE.choices)

    def __str__(self):
        return f"Donation settings - notify_admin: {self.notify_admin}, notify_user: {self.notify_user}, send_user_mail: {self.send_user_mail}, donation_type: {self.donation_type}"



class Donation(TouchDatesMixim):
    class STATUS_CHOICES(models.TextChoices):
        PENDING = "PENDING", "Pending"
        SUCCESS = "SUCCESS", "Success"
        FAILED = "FAILED", "Failed"
        CANCELLED = "CANCELLED", "Cancelled"

    class CURRENCY_TYPE(models.TextChoices):
        NGN = "NGN", "NGN"
        USD = "USD", "USD"

    class TRANSACTION_TYPE(models.TextChoices):
        BANK = "BANK", "BANK"
        TRANSFER = "BANK_TRANSFER", "BANK_TRANSFER"
        CARD = "CARD", "CARD",
        USSD = "USSD", "USSD"

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        help_text="User who initiated the transaction",
        null=True,
        blank=True,
        related_name="donations",
    )
    full_name = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(max_length=255, null=True, blank=True)
    amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(0.01)],
        help_text="Transaction amount",
    )
    transaction_type = models.CharField(max_length=30, choices=TRANSACTION_TYPE.choices)
    currency = models.CharField(max_length=3, choices=CURRENCY_TYPE.choices)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES.choices, default=STATUS_CHOICES.PENDING
    )
    metadata = models.JSONField(default=dict, blank=True)
    tx_ref = models.CharField(max_length=128, unique=True, null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Transaction History"
        verbose_name_plural = "Transaction Histories"
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["status"]),
            models.Index(fields=["tx_ref"]),
        ]

    def __str__(self):
        user_email = self.user.email if self.user else "Unknown"
        return f"{self.reference} - {user_email} - {self.amount}"

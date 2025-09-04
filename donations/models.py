from django.db import models
from itestify_backend.mixims import TouchDatesMixim
from user.models import User

# Create your models here.

class DONATION_TYPE(models.TextChoices):
        BANK_TRANSFER = 'bank_transfer', 'Bank Transfer'
        CARD_PAYMENT = 'card_payment', 'Card Payment'

class DonationSetting(TouchDatesMixim):
    
    notify_admin = models.BooleanField(default=True, help_text="Enable to notify the admin after a user submits a donation for verification")
    notify_user = models.BooleanField(default=True, help_text="Send a notification to users when a donation cannot be verified")
    send_user_mail = models.BooleanField(default=True, help_text="Automatically send a thank-you email to users once their donation is verified")
    donation_type = models.CharField(max_length=25, choices=DONATION_TYPE.choices)
    
    def __str__(self):
        return f"Donation settings - notify_admin: {self.notify_admin}, notify_user: {self.notify_user}, send_user_mail: {self.send_user_mail}, donation_type: {self.donation_type}"  

class Gift(TouchDatesMixim):
    bank_name = models.CharField(max_length=225, blank=True)
    account_number = models.PositiveIntegerField()
    routing_number = models.PositiveIntegerField()
    swift_code = models.CharField(max_length=225)
    account_type = models.CharField(max_length=225)
    address = models.CharField(max_length=225)
    
    def __str__(self):
        return f"NGN Donation {self.account_name}-{self.bank_name}-{self.account_number}" 
    

class Transaction(TouchDatesMixim):
    class STATUS_CHOICES(models.TextChoices):
        PENDING = "pending", "Pending"
        VERIFIED = "verified", "Verified"
        FAILED = "failed", "Failed"

    class CURRENCY_TYPE(models.TextChoices):
        NGN = "NGN", "NGN"
        USD = "USD", "USD"

    class TRANSACTION_TYPE(models.TextChoices):
        BANK = "BANK", "BANK"
        TRANSFER = "TRANSFER", "TRANSFER",
        CARD = "CARD", "CARD"

    user = models.ForeignKey(User, on_delete=models.CASCADE, help_text="User who initiated the transaction")
    reference = models.CharField(max_length=100, unique=True, help_text="Unique transaction reference")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    email = models.EmailField(null=True, blank=True),
    full_name = models.CharField(max_length=255, blank=True)
    type = models.CharField(max_length=255, choices=TRANSACTION_TYPE.choices)
    currency = models.CharField(max_length=10, choices=CURRENCY_TYPE.choices)
    session_id = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES.choices, default="pending")
    description = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Transaction History"
        verbose_name_plural = "Transaction Histories"

    def __str__(self):
        return f"{self.reference} - {self.user.email} - {self.amount}"
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from rest_framework_simplejwt.tokens import RefreshToken
from common.managers import GetOrNoneQuerySet
from django.conf import settings
from django.utils import timezone
from django.utils.crypto import get_random_string

from itestify_backend.mixims import TouchDatesMixim

from django.contrib.postgres.fields import ArrayField


class Role(TouchDatesMixim):
    name = models.CharField(max_length=255)
    permissions = ArrayField(models.CharField(max_length=100), blank=True, default=list)

    def __str__(self):
        return self.name

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if email is None:
            raise TypeError("User should have an Email")

        role = extra_fields.pop("role", None)

        if role is None:
            role, _ = Role.objects.get_or_create(name="viewer")

        user = self.model(email=self.normalize_email(email), role=role, **extra_fields)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, password=None):
        if password is None:
            raise TypeError("Password should not be none")

        role, _ = Role.objects.get_or_create(name="super_admin")

        user = self.create_user(email, password)
        user.role = role
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user

    def get_queryset(self):
        return GetOrNoneQuerySet(self.model, using=self._db)

    def get_or_none(self, **kwargs):
        return self.get_queryset().get_or_none(**kwargs)

    def create_invited_user(self, email, full_name=None, role=None, invited_by=None):
        if email is None:
            raise TypeError("User should have an Email")

        if role == self.model.Roles.SUPER_ADMIN:
            role = self.model.Roles.ADMIN

        user = self.model(
            email=self.normalize_email(email),
            full_name=full_name,
            role=role,
            invited_by=invited_by,
            status=self.model.STATUS.INVITED,
        )
        user.set_unusable_password()
        user.save()
        return user 


class User(AbstractBaseUser, TouchDatesMixim, PermissionsMixin):

    class STATUS(models.TextChoices):
        DELETED = "deleted", "deleted"
        REGISTERED = "registered", "registered"
        INVITED = "invited", "Invited"

    class INVITATION_STATUS(models.TextChoices):
        ACTIVE = "ACTIVE", "ACTIVE"
        EXPIRED = "EXPIRED", "EXPIRED",
        USED = "USED", "USED"

    email = models.EmailField(max_length=255, unique=True)
    full_name = models.CharField(max_length=255, null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, related_name="role")
    is_staff = models.BooleanField(default=False)
    created_password = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)

    status = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        choices=STATUS.choices,
        default=STATUS.REGISTERED,
    )
    invitation_status = models.CharField(default=INVITATION_STATUS.ACTIVE, choices=INVITATION_STATUS.choices, null=True, blank=True)
    is_email_verified = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False, null=True, blank=True)
    invited_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="invited_users",
    )

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = []

    objects = UserManager()

    @property
    def is_super_admin(self):
        return self.role == self.Roles.SUPER_ADMIN

    @property
    def is_active(self):
        return self.status != self.STATUS.DELETED

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)

        return {"refresh": str(refresh), "access": str(refresh.access_token)}


class EntryCode(TouchDatesMixim):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="entry_code")

    code = models.CharField(max_length=4, unique=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.email} - code: {self.code}"


class Otp(TouchDatesMixim):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name="otp"
    )

    code = models.IntegerField()

    def check_expiration(self):
        now = timezone.now()
        diff = now - self.updated_at

        if diff.total_seconds() > settings.EMAIL_OTP_EXPIRE_SECONDS:
            return True
        return False

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=2)


class SendOtp(TouchDatesMixim):
    code = models.IntegerField()

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=2)


class UserInvitation(TouchDatesMixim):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="invitations")
    token = models.CharField(max_length=64, unique=True, blank=True, null=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def create_invitation(cls, user):
        # Generate a unique token
        while True:
            token = get_random_string(length=64)
            if not cls.objects.filter(token=token).exists():
                break

        # Create invitation
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=timezone.now() + timezone.timedelta(days=7),
        )

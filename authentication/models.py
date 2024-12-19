"""Defines the user model and model manager"""
from django.contrib.auth.models import BaseUserManager, AbstractUser
from django.db import models
import uuid
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class CustomUserManager(BaseUserManager):
    """Manager of the user email"""
    
    def create_user(self, email, password=None, **extra_fields):
        """create_user returns a user 
        
        args: (email)
              (password)
        returns: a new user

        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    
    
    def create_superuser(self, email, password=None, **extra_fields):
        """create_user returns a user 
        
        args: (email)
              (password)
        returns: a new superuser

        """
        
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("verified", True)

        
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self.create_user(email, password, **extra_fields)


class Role(models.Model):
    
    role = models.CharField(max_length=50, default="Admin")

    def __str__(self):
        return self.role

    class Meta:
        db_table = 'roles'


class CustomUser(AbstractUser):
    """object model for the user entity"""
    
    first_name = None
    last_name = None

    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4, unique=True)
    fullname = models.CharField(max_length=100)    
    username = models.CharField(max_length=50, unique=True, null=False)
    email = models.EmailField(unique=True)
    location = models.CharField(max_length=255)
    password = models.CharField(max_length=255, blank=False)
    role = models.ForeignKey(Role, related_name="userRole", on_delete=models.DO_NOTHING, null=True)
    status = models.BooleanField(default=True)
    verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)


    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.fullname

    class Meta:
        db_table = 'users'


class Tokens(models.Model):
        email = models.EmailField('email address')
        action = models.CharField(max_length=20)
        token = models.CharField(max_length=200)
        exp_date = models.FloatField()
        date_used = models.DateTimeField(null=True)
        created_at = models.DateTimeField(auto_now=True)
        used = models.BooleanField(default=False)
        confirmed = models.BooleanField(default=False)

        class Meta:
            db_table = 'tokens'

        def __str__(self):
            return self.email
        
        
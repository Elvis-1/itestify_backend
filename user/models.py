from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

from itestify_backend.mixims import TouchDatesMixim

# Create your models here.


class UserManager(BaseUserManager):

    def create_user(self, email, password=None):

        if email is None:
            raise TypeError('User should have an Email')

        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save()

        return user


    def create_superuser(self, email, password=None):

        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(email, password)
        user.role = User.Roles.SUPER_ADMIN
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class User(AbstractBaseUser, TouchDatesMixim, PermissionsMixin):
    
    class Roles(models.TextChoices):
        SUPER_ADMIN = "super_admin", "super_admin"
        ADMIN = "admin", "admin"
        VIWER = "viewer", "viewer"
        
    email = models.EmailField(max_length=255, unique=True)
    full_name = models.CharField(max_length=255, null=True, blank=True)
    role = models.CharField(max_length=20, choices=Roles.choices, default=Roles.VIWER)
    is_staff = models.BooleanField(default=False)
    created_password = models.BooleanField(default=False)
    
    
    USERNAME_FIELD = 'email'

    objects = UserManager()
    
    
    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        

class EntryCode(TouchDatesMixim):
    user =  models.ForeignKey(User, on_delete=models.CASCADE, related_name='entry_code')
    code = models.CharField(max_length=4, unique=True)
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.email} - code: {self.code}"
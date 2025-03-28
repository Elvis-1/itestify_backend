from rest_framework import serializers
from user.models import User
from django.utils.translation import gettext_lazy as _


class ReturnUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [ "id", "email", "full_name", "last_login", "role", "created_at"]


class UserRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    full_name = serializers.CharField()
    password = serializers.CharField()
    password2 = serializers.CharField()

    
class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOtpSerializer(ResendOtpSerializer):
    otp = serializers.IntegerField()

class SetNewPasswordSerializer(ResendOtpSerializer):
    password = serializers.CharField()
    password2 = serializers.CharField()

class LoginSerializer(ResendOtpSerializer):
    password = serializers.CharField()

class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()


        










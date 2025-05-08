from rest_framework import serializers
from user.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
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

User = get_user_model()

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("The two password fields didn't match.")
        
        try:
            validate_password(data['new_password'], self.context['request'].user)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        
        return data

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value


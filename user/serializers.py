from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User


class UserRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    full_name = serializers.CharField(required=False)
    password = serializers.CharField(required=False)
    password2 = serializers.CharField(required=False)
    otp = serializers.IntegerField(required=False)


class LoginCodeEntrySerializer(serializers.Serializer):

    email = serializers.EmailField()
    entry_code = serializers.CharField(max_length=6)


class LoginPasswordSerializer(serializers.Serializer):

    email = serializers.EmailField()
    password = serializers.CharField(max_length=225)


class ReturnUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "full_name",
            "created_password",
            "last_login",
            "status",
            "created_at",
            "updated_at",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        is_testimony = self.context.get("is_testimony")

        # conditionally remove 'uploaded_by' field based on user's role
        if is_testimony:
            fields_to_remove = ["created_password", "last_login", "created_at", "updated_at"]

            for field in fields_to_remove:
                self.fields.pop(field, None)


class SetPasswordSerializer(serializers.Serializer):
    """set user password in dashboard"""

    password = serializers.CharField(max_length=255, write_only=True)
    confirm_password = serializers.CharField(max_length=255, write_only=True)


class ResendEntryCodeSerializer(serializers.Serializer):
    """resend entry code for user"""

    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)


class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()


class VerifyOtpSerializer(ResendOtpSerializer):
    otp = serializers.IntegerField()


class SetNewPasswordSerializer(ResendEntryCodeSerializer):
    """set new password for user"""
    password = serializers.CharField()
    password2 = serializers.CharField()

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
            raise serializers.ValidationError("Password mismatch!")

        try:
            validate_password(data['new_password'],
                              self.context['request'].user)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))

        return data

class SetPasswordWithInvitationSerializer(serializers.Serializer):
    invitation_code = serializers.CharField()
    password = serializers.CharField()
    password2 = serializers.CharField()


from rest_framework import serializers

from user.models import User


class UserRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    full_name = serializers.CharField()
    password = serializers.CharField()
    password2 = serializers.CharField()

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
            "role",
            "created_password",
            "last_login",
            "status",
            "created_at",
            "updated_at",
        ]


class SetPasswordSerializer(serializers.Serializer):
    """set user password in dashboard"""

    password = serializers.CharField(max_length=255, write_only=True)
    confirm_password = serializers.CharField(max_length=255, write_only=True)

    
    
class ResendEntryCodeSerializer(serializers.Serializer):
    """resend entry code for user"""

    email = serializers.EmailField()
    
    
class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    
class VerifyOtpSerializer(ResendOtpSerializer):
    otp = serializers.IntegerField()
    
    
class SetNewPasswordSerializer(ResendEntryCodeSerializer):
    """set new password for user"""
    password = serializers.CharField()
    password2 = serializers.CharField()


class UserInvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'role', 'status']

class CreateMemberSerializer(serializers.Serializer):
    email = serializers.EmailField()
    full_name = serializers.CharField()
    role = serializers.ChoiceField(choices=User.Roles.choices)

class InvitationResponseSerializer(serializers.Serializer):
    user = UserInvitationSerializer()
    invitation_code = serializers.CharField()

class SetPasswordWithInvitationSerializer(serializers.Serializer):
    invitation_code = serializers.CharField()
    password = serializers.CharField()
    password2 = serializers.CharField()
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError 
# from rest_framework.exceptions import ValidationError

from .models import User, Role
from .utils import Util


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

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "name", "permissions", "created_at"]

    def validate_permissions(self, obj):
        if not isinstance(obj, list):
            raise serializers.ValidationError("Permissions must be a list of strings.")
        
        for i in obj:
            if i not in ["User Management", "Testimony Management", "Review Management", "Privacy and Security Management"]:
                raise serializers.ValidationError(f"{i} is an invalid permission.")

        return obj

    def create(self, validated_data):
        permissions = validated_data.pop("permissions", [])
        return Role.objects.create(name=validated_data["name"], permissions=permissions)

class InvitationSerializer(ResendOtpSerializer):
    id = serializers.UUIDField(read_only=True)
    full_name = serializers.CharField(max_length=200)
    role = serializers.CharField(max_length=200)
    invitation_status = serializers.CharField(read_only=True)
    invite_count = serializers.IntegerField(read_only=True)
    alternative_role = serializers.CharField(max_length=200, write_only=True)

    # returns the list of roles in as an array
    def get_roles(self, name=None):
        if name is not None:
            return Role.objects.filter(name=name).first()

        return Role.objects.values_list("name", flat=True)

    
    def get_super_admin(self):
        user = User.objects.filter(role__name="super_admin").order_by("created_at")

        if user.exists():
            return user.first()

        return None

    def validate(self, obj):
        available_roles = self.get_roles()

        if obj["role"] not in available_roles or obj["alternative_role"] not in available_roles:
            raise serializers.ValidationError("Invalid roles, please check again.")

        return obj

    def create(self, validated_data):
        if User.objects.filter(email=validated_data["email"]).exists():
            raise serializers.ValidationError("An account with this email already exists.")

        generated_password = Util.generate_password(8)
        alternative_role = validated_data.get("alternative_role", None)
        
        role = self.get_roles(name=validated_data["role"]) # fetch the role queryset using the name

        # set the alternative role of the current super_admin if it is to assign a new super_admin
        if alternative_role:
            alternative_role = self.get_roles(name=alternative_role)
            super_admin = self.get_super_admin()
            super_admin.alternative_role = alternative_role
            super_admin.save()
        
        user = User.objects.create_user(
            email=validated_data["email"],
            password=generated_password,
            full_name=validated_data["full_name"],
            status=User.STATUS.INVITED,
            role=role,
        )

        return user 

class ResendInvitationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, obj):
        user = User.objects.filter(email=obj["email"])
    
        if not user.exists():
            raise serializers.ValidationError("Account not found.")

        if user.first().invitation_status == User.INVITATION_STATUS.USED:
            raise serializers.ValidationError("This user has accepted the invitation, please use the forgot password option.")

        # increment invite count by 1 and set invitation_status to "ACTIVE"
        user = user.first()
        user.invitation_status = User.INVITATION_STATUS.ACTIVE
        user.invite_count += 1
        user.save()

        return obj

    
class SetInvitedPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def  validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise ValidationError("Passwords do not match.")

        return attrs

    def validate_token(self, token):
        if not token.startswith("ey"):
            raise ValidationError("Incorrect token.")

        return token

    def update(self, instance, validated_data):
        validated_data.pop("password2", None)
    
        instance.set_password(validated_data["password"])
        instance.invitation_status=User.INVITATION_STATUS.USED
        instance.save()

        super_admin = InvitationSerializer.get_super_admin(self)

        if super_admin.alternative_role is not None:
            role = InvitationSerializer.get_roles(self, name=super_admin.alternative_role.name)
            super_admin.status = super_admin.STATUS.INVITED
            super_admin.role = role
            super_admin.save()

        return instance 

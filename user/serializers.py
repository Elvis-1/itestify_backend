from rest_framework import serializers

from user.models import User



class LoginCodeEntrySerialiazer(serializers.Serializer):
        
    email = serializers.EmailField()
    entry_code = serializers.CharField(max_length=6)
    

class LoginPasswordSerialiazer(serializers.Serializer):
        
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
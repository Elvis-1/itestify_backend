from rest_framework import serializers
from user.models import User
from django.utils.translation import gettext_lazy as _


class ReturnUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [ "id", "email", "full_name", "last_login", "created_at"]



class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "full_name", "password2"]

    def validate(self, data):
        password = data['password']
        password2 = data['password2']

        if password != password2:
            raise serializers.ValidationError({'passwords':'Passwords do not match'})
    
        return data
    
    

class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    

class VerifyOtpSerializer(ResendOtpSerializer):
    otp = serializers.IntegerField()


class VerifyOtpSerializer(ResendOtpSerializer):
    otp = serializers.IntegerField()

class SetNewPasswordSerializer(VerifyOtpSerializer):
    password = serializers.CharField()
    password2 = serializers.CharField()

class LoginSerializer(ResendOtpSerializer):
    password = serializers.CharField()

class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()


        











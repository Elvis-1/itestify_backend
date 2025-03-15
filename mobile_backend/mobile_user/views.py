from rest_framework.generics import GenericAPIView
from .serializers import RegistrationSerializer, LoginSerializer, ResendOtpSerializer, SetNewPasswordSerializer, ReturnUserSerializer
from rest_framework import status
from user.models import User, Otp
from ..common.responses import CustomResponse
from ..common.error import ErrorCode
from .emails import Util
from datetime import datetime


class GetRegisteredUsers(GenericAPIView):
    serializer_class = ReturnUserSerializer
    def get(self, request):
        users = User.objects.filter(is_superuser=False)
        serializer = self.serializer_class(users, many=True)
        return CustomResponse.success(
            message="Users retrieved successfully",
            data=serializer.data,
            status_code=200
        )



class RegistrationAPIView(GenericAPIView):
    serializer_class = RegistrationSerializer
    
    def post(self, request):
        data = request.data
        
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        
        # check for existing user
        user = User.objects.get_or_none(email=data['email'])
        
        if user:
            return CustomResponse.error(
                message='User with this email already exists.',
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400
            )
        
        # Create user
        data.pop('password2', None)
        user = User.objects.create_user(**data)
        token = user.token()
        
        response =  CustomResponse.success(
            message="Account created successfully",
            data={"user": 
                {
                    "id": user.id, 
                    "email": user.email,
                    "full_name": user.full_name,
                    "created_at": user.created_at
                },
                "token": {"access": token["access"], "refresh": token["refresh"]}
            },
            status_code=201
        )
        
        response.set_cookie(
                key="refresh",
                value=token["refresh"],
                httponly=True,  # Set HttpOnly flag
            )
        response.set_cookie(
            key="access", value=token["access"], httponly=True  # Set HttpOnly flag
        )
            
        return response
        
        
class LoginAPIView(GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        data = request.data
        serializer = LoginSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        
        user = User.objects.get_or_none(email=serializer.data["email"])   
        
        if not user:
            return CustomResponse.error(
                message="User with this email does not exist.",
                err_code=ErrorCode.INVALID_CREDENTIALS,
                status_code=401
            )
            
        if not user.check_password(serializer.data["password"]):
            return CustomResponse.error(
                message="Password is not correct!",
                err_code=ErrorCode.INVALID_CREDENTIALS,
                status_code=401
            )
            
        token = user.token()
        
        user.last_login = datetime.now()
        user.save()
        
        data = {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "last_login": user.last_login,
            "created_at": user.created_at,
            "token": {
                "access": token['access'],
                "refresh": token['refresh']
            }
        }

        response = CustomResponse.success(
            message="Login successful",
            data=data,
            status_code=201
        )
        
        response.set_cookie(
                key="refresh",
                value=token["refresh"],
                httponly=True,  # Set HttpOnly flag
            )
        response.set_cookie(
            key="access", value=token["access"], httponly=True  # Set HttpOnly flag
        )
            
        return response
      
      
class SendPasswordResetOtpView(GenericAPIView):
    serializer_class = ResendOtpSerializer
    
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        user = User.objects.get_or_none(email=email)

        if not user:
            return CustomResponse.error(
                message="User does not exist",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400
            )
        
        Util.send_password_reset_email(user)

        return CustomResponse.success(
            message="Password reset otp has been sent",
            status_code=200
        )
        
        
class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data["email"]
        otp_code = serializer.validated_data["otp"]
        password = serializer.validated_data["password"]
        password2 = serializer.validated_data["password2"]

        user = User.objects.get_or_none(email=email)

        if not user:
            return CustomResponse.error(
                message="User does not exist!",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400
            )
        
        otp = Otp.objects.get_or_none(user=user)

        if otp is None or otp.code != otp_code:
            return CustomResponse.error(
                message="Otp has expired",
                err_code=ErrorCode.EXPIRED_OTP,
                status_code=400
            )
        
        if password != password2:
            return CustomResponse.error(message='Passwords do not match', err_code=ErrorCode.INVALID_ENTRY, status_code=400)
        
        user.set_password(password)
        user.save()
        otp.delete()

        return CustomResponse.success(
            message="Password changed successfully",
            status_code=200
        )
        
        


        

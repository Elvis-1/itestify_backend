from rest_framework.generics import GenericAPIView
from .serializers import UserRegisterSerializer, LoginSerializer, ResendOtpSerializer, SetNewPasswordSerializer, ReturnUserSerializer, VerifyOtpSerializer
from rest_framework import status
from user.models import User, Otp
from common.responses import CustomResponse
from common.error import ErrorCode
from .emails import Util
from datetime import datetime
from common.exceptions import handle_custom_exceptions


class GetRegisteredUsers(GenericAPIView):
    serializer_class = ReturnUserSerializer
    
    @handle_custom_exceptions
    def get(self, request):
        users = User.objects.all()
        serializer = self.serializer_class(users, many=True)
        return CustomResponse.success(
            message="Users retrieved successfully",
            data=serializer.data,
            status_code=200
        )


class UserRegisterAPIView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    # @handle_custom_exceptions
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)

        password = data["password"]
        password2 = data["password2"]

        if password != password2:
            return CustomResponse.error(
                message="Passwords do not match",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400
            )

        user = User.objects.get_or_none(email=serializer.validated_data["email"])

        if user:
            return CustomResponse.error(
                message="User with this email already exists",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400
            )

        serializer.validated_data.pop("password2", None)
        user = User.objects.create_user(**serializer.validated_data)
        user.role = "viewer"
        token = user.tokens()
        user.save()

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
    
    @handle_custom_exceptions
    def post(self, request):
        data = request.data
        serializer = LoginSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        
        user = User.objects.filter(email=serializer.data["email"]).first()
        
        if not user:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404
            )

        if user.status and user.status == "deleted":
            return CustomResponse.error(
                message="This account has been deleted.",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400
            )
            
        if not user.check_password(serializer.data["password"]):
            return CustomResponse.error(
                message="Password is not correct!",
                err_code=ErrorCode.INVALID_CREDENTIALS,
                status_code=401
            )
            
        token = user.tokens()
        
        user.last_login = datetime.now()
        user.save()
        
        data = {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
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
            status_code=200
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
    
    @handle_custom_exceptions
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
    

class VerifyOtpView(GenericAPIView):
    serializer_class = VerifyOtpSerializer

    @handle_custom_exceptions
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        user = User.objects.get_or_none(email=email)
        otp_obj = Otp.objects.get_or_none(user=user, code=int(otp))

        if otp_obj is None or otp_obj.code != otp:
            return CustomResponse.error(
                message="Otp is not correct",
                err_code=ErrorCode.INCORRECT_OTP,
                status_code=400
            )

        if otp_obj.check_expiration():
             return CustomResponse.error(
                message="Otp has expired",
                err_code=ErrorCode.EXPIRED_OTP,
                status_code=400
            )
            
        return CustomResponse.success(message="Otp successfully verified", status_code=200)

        
        
class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    @handle_custom_exceptions
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        password2 = serializer.validated_data["password2"]

        user = User.objects.get_or_none(email=email)

        if not user:
            return CustomResponse.error(
                message="User does not exist!",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400
            )
           
        
        if password != password2:
            return CustomResponse.error(message='Passwords do not match', err_code=ErrorCode.INVALID_ENTRY, status_code=400)
        
        user.set_password(password)
        user.save()

        return CustomResponse.success(
            message="Password changed successfully",
            status_code=200
        )
        
class DeleteUserAccount(GenericAPIView):
    def delete(self, request):
        current_user = request.user
        try:
            user = User.objects.get_or_none(email=current_user.email)
            user.status = "deleted"
            user.save()
            return CustomResponse.success(
                message="Account deleted successfully.",
                status_code=200
            )
        except User.DoesNotExist:
            return CustomResponse.error(message="User with this account does not exist.", err_code=ErrorCode.NOT_FOUND, status_code=404)


        


        

import string
# from django.urls import reverse
import requests
from django.conf import settings
# from urllib.parse import urljoin
import validate_email

from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import EntryCode, User, Otp
from .utils import Util
from .serializers import LoginCodeEntrySerializer, LoginPasswordSerializer, ResendEntryCodeSerializer, SetPasswordSerializer, ReturnUserSerializer, ResendOtpSerializer, SetNewPasswordSerializer, VerifyOtpSerializer, UserRegisterSerializer
from common.exceptions import handle_custom_exceptions
from common.responses import CustomResponse
from common.error import ErrorCode
from rest_framework.generics import GenericAPIView
from datetime import datetime
from .emails import EmailUtil
from support.helpers import StandardResultsSetPagination
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
# from allauth.socialaccount.providers.oauth2.client import OAuth2Client
# from dj_rest_auth.registration.views import SocialLoginView


# Create your views here.

def has_uppercase(s):
    return any(char.isupper() for char in s)


def has_lowercase(s):
    return any(char.islower() for char in s)


def has_number(s):
    return any(char.isdigit() for char in s)


def has_special_character(s):
    special_char = string.punctuation
    return any(char in special_char for char in s)


# -------------- GOOGLE SOCIAL LOGIN ----------------

'''class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.GOOGLE_OAUTH_CALLBACK_URL
    client_class = OAuth2Client'''


class GoogleLoginCallback(APIView):
    def get(self, request, *args, **kwargs):
        code = request.GET.get("code")

        if code is None:
            return Response({"error": "Missing authorization code"}, status=status.HTTP_400_BAD_REQUEST)

        # Define the payload for Google's token exchange
        payload = {
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_OAUTH_CALLBACK_URL,
            "grant_type": "authorization_code",
        }

        # Make a request to the Google token endpoint
        try:
            response = requests.post(
                "https://oauth2.googleapis.com/token", data=payload)
            response.raise_for_status()  # Check for HTTP errors
        except requests.exceptions.RequestException as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token_data = response.json()  # Attempt to parse the JSON response
        except ValueError:
            return Response({"error": "Invalid response from Google"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(token_data, status=status.HTTP_200_OK)


class RegisterViewSet(viewsets.ViewSet):
    serializer_class = UserRegisterSerializer

    @action(detail=False, methods=["post"], url_path="register")
    def register(self, request):
        data = request.data

        serializer = self.serializer_class(data=data or None)
        if serializer.is_valid(raise_exception=True):
            if not validate_email.validate_email(serializer.validated_data.get("email")) or serializer.validated_data.get("email") == "":
                return CustomResponse.error(
                    message="Invalid email address or email is empty",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400
                )
            elif not serializer.validated_data.get("otp"):
                return CustomResponse.error(
                    message="OTP is required for email verification",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400
                )
            elif len(serializer.validated_data.get("full_name")) < 3:
                return CustomResponse.error(
                    message="Full name must be at least 3 characters long",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400
                )
            elif len(serializer.validated_data.get("password")) < 8 or len(serializer.validated_data.get("password2")) < 8:
                return CustomResponse.error(
                    message="Password must be at least 8 characters long",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400
                )
            elif serializer.validated_data.get("password") != serializer.validated_data.get("password2"):
                return CustomResponse.error(
                    message="Passwords do not match",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400
                )
            else:
                try:
                    otp_code = Otp.objects.get(
                        code=serializer.validated_data.get("otp"))
                    if otp_code.is_expired():
                        return CustomResponse.error(
                            message="OTP has expired",
                            err_code=ErrorCode.EXPIRED_OTP,
                            status_code=400
                        )

                    User.objects.create_user(serializer.validated_data["email"],
                                             full_name=serializer.validated_data["full_name"],
                                             role=User.Roles.VIEWER,
                                             status=User.STATUS.REGISTERED,
                                             password=serializer.validated_data["password"],
                                             is_verified=True,
                                             is_email_verified=True)

                    return CustomResponse.success(
                        message="Account created successfully",
                        status_code=201
                    )
                except Otp.DoesNotExist:
                    return CustomResponse.error(
                        message="Invalid OTP",
                        err_code=ErrorCode.INVALID_ENTRY,
                        status_code=400
                    )

        return CustomResponse.error(
            message="Invalid data",
            err_code=ErrorCode.INVALID_ENTRY,
            status_code=400
        )

    @action(detail=False, methods=["post"])
    def resend_verification_token(self, request):
        data = request.data
        serializer = ResendEntryCodeSerializer(data=data)
        route_name = request.resolver_match.url_name
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        user = User.objects.get_or_none(email=email)

        if route_name == "resend-email-token":
            if user.is_verified == True:
                return CustomResponse.error(
                    message="Email already verified",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403
                )

            EmailUtil.send_verification_email(user)

        return CustomResponse.success(
            message="A new OTP has been sent to your email. Please check your inbox or spam folder.",
            status_code=200
        )


class LoginViewSet(viewsets.ViewSet):

    serializer_class = LoginCodeEntrySerializer
    permission_classes = [permissions.AllowAny]

    @action(detail=False, methods=["post"])
    def entry_code(self, request):

        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        entry_code = serializer.validated_data["entry_code"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        entry_code_obj = user.entry_code.all().first()
        token = user.tokens()

        if entry_code_obj.code == entry_code and not entry_code_obj.is_used:
            entry_code_obj.is_used = True
            entry_code_obj.save()

            serializer = ReturnUserSerializer(user, many=False)

            response = CustomResponse.success(
                data={
                    'user': serializer.data,
                    "token": token["access"],
                    "refresh": token["refresh"]
                },
                status_code=200
            )

            response.set_cookie(
                key="refresh",
                value=token["refresh"],
                httponly=True,  # Set HttpOnly flag
            )
            response.set_cookie(
                # Set HttpOnly flag
                key="access", value=token["access"], httponly=True
            )

            return response

        return CustomResponse.error(
            message="Invalid entry code",
            err_code=ErrorCode.INVALID_ENTRY,
            status_code=400
        )

    @action(detail=False, methods=["post"])
    def password(self, request):
        serializer = LoginPasswordSerializer(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            # Retrieve user by email
            user = User.objects.get(email=email)
            token = user.tokens()
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=404
            )

        if user.status and user.status == "deleted":
            return CustomResponse.error(
                message="This account has been deleted.",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403
            )

        # Check if the password is correct
        if user.check_password(password):
            serializer = ReturnUserSerializer(user, many=False)

            user.last_login = datetime.now()
            user.save()

            data = {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "last_login": user.last_login,
                "created_at": user.created_at,
                "created_password": user.created_password,
                "token": {
                    "access": token['access'],
                    "refresh": token['refresh']
                }
            }

            response = CustomResponse.success(data=data, status_code=200)

            response.set_cookie(
                key="refresh",
                value=token["refresh"],
                httponly=True,  # Set HttpOnly flag
            )
            response.set_cookie(
                key="access",
                value=token["access"],
                httponly=True,  # Set HttpOnly flag
            )

            return response

        else:
            return CustomResponse.error(
                message="Invalid password",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=401
            )

    @action(detail=False, methods=["post"])
    def resend_entry_code(self, request):

        serializer = ResendEntryCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        code = Util.generate_entry_code()
        Otp.objects.create(code=code)

        # Prepare email data and send the email
        email_data = {
            'to_email': email,
            'email_subject': "Request For a New Entry Code",
            'email_body': f"Your new entry code: {code}"
        }
        EmailUtil.send_email(email_data)

        return CustomResponse.success(message=f"A new entry code {code} has been sent to your email {email}", status_code=200)


class SendOtpCodeView(APIView):
    def post(self, request):
        serializer = ResendEntryCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')

        code = Util.generate_entry_code()
        Otp.objects.create(code=code)

        # Prepare email data and send the email
        email_data = {
            'to_email': email,
            'email_subject': "Request For a New Entry Code",
            'email_body': f"Your new entry code: {code}"
        }
        EmailUtil.send_email(email_data)

        return CustomResponse.success(message=f"A new entry code {code} has been sent to your email {email}", status_code=200)


class DashboardViewSet(viewsets.ViewSet):

    serializer_class = SetPasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=["post"])
    def create_password(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data.get("password")
        confirm_password = serializer.validated_data.get("confirm_password")

        if password != confirm_password:
            return CustomResponse.error(message="Passwords does not match", err_code=ErrCode.BAD_REQUEST, status_code=400)

        user = request.user
        user.created_password = True
        user.set_password(password)
        user.save()

        return CustomResponse.success(message="Passwords changed successfully", status_code=200)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        pass


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

        EmailUtil.send_password_reset_email(user)

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
        route_name = request.resolver_match.url_name

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

        if route_name == "verify-email":
            user.is_email_verified = True
        elif route_name == "verify-otp":
            user.is_verified = True

        user.save()

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

        if not user.is_verified:
            return CustomResponse.error(
                message="You have not verified otp",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403
            )

        if password != password2:
            return CustomResponse.error(message='Passwords do not match', err_code=ErrorCode.INVALID_ENTRY, status_code=400)

        user.set_password(password)
        user.is_verified = False
        user.save()

        return CustomResponse.success(
            message="Password changed successfully",
            status_code=200
        )


class UsersViewSet(viewsets.ViewSet):
    serializer_class = ReturnUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    # gets the list of registered users

    @action(detail=False, methods=["get"])
    def all(self, request):
        status = request.query_params.get("status", None)

        if not status or status == "":
            users = User.objects.all()
        else:
            users = User.objects.filter(status=status)
        paginator = self.pagination_class()
        paginator_queryset = paginator.paginate_queryset(users, request)
        serializer = self.serializer_class(paginator_queryset, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=False, methods=["delete"])
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

    def destroy(self, request, pk=None):
        try:
            user = User.objects.get_or_none(id=pk)

            if user.status == "registered":
                return CustomResponse.error(
                    message="Cannot delete a registered user.",
                    err_code=ErrorCode.BAD_REQUEST,
                    status_code=400
                )

            user.delete()
            return CustomResponse.success(
                message="User deleted successfully",
                status_code=200
            )

        except User.DoesNotExist or user is None:
            return CustomResponse.error(
                message="User not found.",
                err_code=ErrCode.NOT_FOUND,
                status_code=404
            )


class LogOutApiView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    @handle_custom_exceptions
    def post(self, request: Request) -> Response:
        refresh_token = request.COOKIES.get('refresh')

        if not refresh_token:
            return CustomResponse.error(
                message="Refresh token not found",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return CustomResponse.error(
                message="Invalid or expired refresh token",
                err_code=ErrorCode.UNAUTHORIZED,
                status_code=401
            )
        except Exception as e:
            # Optional: log exception
            return CustomResponse.error(
                message="Logout failed",
                err_code=ErrorCode.INTERNAL_SERVER_ERROR,
                status_code=500
            )

        response = CustomResponse.success(
            message="Logout successful",
            status_code=200
        )
        response.delete_cookie('refresh')
        response.delete_cookie('access')

        return response


class ForgotPasswordView(APIView):
    account_activation_token = PasswordResetTokenGenerator()

    def post(self, request):
        payload = {}
        email = request.data.get("email")
        if not email:
            return Response({"success": False, "message": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)

            reset_password_token = {
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': self.account_activation_token.make_token(user)
            }

            payload = {
                "success": True, "message": "Password reset link has been sent to your email", "uid": f"{reset_password_token['uid']}", "token": f"{reset_password_token['token']}"
            }
            return Response(payload, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"success": False, "message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)


class ResetPasswordView(APIView):
    account_activation_token = PasswordResetTokenGenerator()

    def post(self, request, uidb64, token):
        # otp = request.data.get('otp')
        password = request.data.get('password')
        if len(password) < 8:
            return Response({"msg": "At least enter 8 Character"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_uppercase(password):
            return Response({"msg": "One Uppercase Letter (A-Z)"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_lowercase(password):
            return Response({"msg": "One Lowercase Letter (A-Z)"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_number(password):
            return Response({"msg": "One Number (0-9)"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_special_character(password):
            return Response({"msg": "One Special Character (!@#$%^&*)"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                user_id = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=user_id)
                if not self.account_activation_token.check_token(user, token):
                    return Response({"msg": "Password link invalid, Pls request for a new one"}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(password)
                user.save()

                return Response({"msg": "Password Reset Successfully"}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"msg": "User Does not exist"})

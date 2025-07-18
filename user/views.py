import string
import os
from tokenize import TokenError
from django.conf import settings
import validate_email
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import EntryCode, User, Otp, UserInvitation, SendOtp

from .utils import Util
from .serializers import (
    LoginCodeEntrySerializer,
    LoginPasswordSerializer,
    ResendEntryCodeSerializer,
    SetPasswordSerializer,
    ReturnUserSerializer,
    ResendOtpSerializer,
    SetNewPasswordSerializer,
    VerifyOtpSerializer,
    UserRegisterSerializer,
    ChangePasswordSerializer,
    SetPasswordWithInvitationSerializer,
)
from common.exceptions import handle_custom_exceptions
from common.responses import CustomResponse
from common.error import ErrorCode
from rest_framework.generics import GenericAPIView
from datetime import datetime
from .emails import EmailUtil
from support.helpers import StandardResultsSetPagination
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from google.oauth2 import id_token

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


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

class GoogleLoginAPIView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # Disable DRF session auth

    def post(self, request):
        token = request.data.get("id_token")
        if not token:
            return Response({"detail": "Missing id_token"}, status=400)

        try:
            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request())

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            email = idinfo.get('email')
            name = idinfo.get('name')

            user, created = User.objects.get_or_create(email=email)
            if created:
                user.full_name = name
                user.set_unusable_password()
                user.save()

            refresh = RefreshToken.for_user(user)
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'email': user.email,
                    'name': user.full_name,
                }
            })

        except ValueError as e:
            return Response({"detail": "Invalid token", "error": str(e)}, status=400)


class RegisterViewSet(viewsets.ViewSet):
    serializer_class = UserRegisterSerializer

    @action(detail=False, methods=["post"], url_path="register")
    def register(self, request):
        data = request.data

        serializer = self.serializer_class(data=data or None)
        if serializer.is_valid(raise_exception=True):
            if (
                not validate_email.validate_email(
                    serializer.validated_data.get("email")
                )
                or serializer.validated_data.get("email") == ""
            ):
                return CustomResponse.error(
                    message="Invalid email address or email is empty",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400,
                )
            elif not serializer.validated_data.get("otp"):
                return CustomResponse.error(
                    message="OTP is required for email verification",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400,
                )
            elif len(serializer.validated_data.get("full_name")) < 3:
                return CustomResponse.error(
                    message="Full name must be at least 3 characters long",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400,
                )
            elif (
                len(serializer.validated_data.get("password")) < 8
                or len(serializer.validated_data.get("password2")) < 8
            ):
                return CustomResponse.error(
                    message="Password must be at least 8 characters long",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400,
                )
            elif serializer.validated_data.get(
                "password"
            ) != serializer.validated_data.get("password2"):
                return CustomResponse.error(
                    message="Passwords do not match",
                    err_code=ErrorCode.INVALID_ENTRY,
                    status_code=400,
                )
            else:
                try:
                    otp_code = SendOtp.objects.get(
                        code=serializer.validated_data.get("otp")
                    )
                    if otp_code.is_expired():
                        return CustomResponse.error(
                            message="OTP has expired",
                            err_code=ErrorCode.EXPIRED_OTP,
                            status_code=400,
                        )

                    if User.objects.filter(email=serializer.validated_data["email"]).exists():
                        return CustomResponse.error(
                            message="User with this email already exists",
                            err_code=ErrorCode.INVALID_ENTRY,
                            status_code=400
                        )
                    # permission = Permission.objects.create(
                        # name="name", codename="codename")
                    # user_role = Role.objects.create(name="VIEWER")
                    # user_role.add(permission)
                    User.objects.create_user(serializer.validated_data["email"],
                                             full_name=serializer.validated_data["full_name"],
                                             role=User.Roles.VIEWER,
                                             status=User.STATUS.REGISTERED,
                                             password=serializer.validated_data["password"],
                                             is_verified=True,
                                             is_email_verified=True
                                             )

                    return CustomResponse.success(
                        message="Account created successfully", status_code=201
                    )
                except Otp.DoesNotExist:
                    return CustomResponse.error(
                        message="Invalid OTP",
                        err_code=ErrorCode.INVALID_ENTRY,
                        status_code=400,
                    )

        else:
            return CustomResponse.error(
                message="Invalid data",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400,
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
                    status_code=403,
                )

            EmailUtil.send_verification_email(user)

        return CustomResponse.success(
            message="A new OTP has been sent to your email. Please check your inbox or spam folder.",
            status_code=200,
        )


class LoginViewSet(viewsets.ViewSet):

    serializer_class = LoginCodeEntrySerializer
    permission_classes = [permissions.AllowAny]

    @action(detail=False, methods=["post"])
    def entry_code(self, request):

        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response(
                {"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data["email"]
        entry_code = serializer.validated_data["entry_code"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                status=404
            )

        entry_code_obj = EntryCode.objects.get(user__email=email)
        token = user.tokens()

        if entry_code_obj.code == entry_code and not entry_code_obj.is_used:
            entry_code_obj.is_used = True
            entry_code_obj.save()

            serializer = ReturnUserSerializer(user, many=False)

            response = CustomResponse.success(
                data={
                    "user": serializer.data,
                    "token": token["access"],
                    "refresh": token["refresh"],
                },
                status_code=200,
            )

            response.set_cookie(
                key="refresh",
                value=token["refresh"],
                httponly=True,  # Set HttpOnly flag
            )
            response.set_cookie(
                # Set HttpOnly flag
                key="access",
                value=token["access"],
                httponly=True,
            )

            return response

        return CustomResponse.error(
            message="Invalid entry code",
            err_code=ErrorCode.INVALID_ENTRY,
            status_code=400,
        )

    @handle_custom_exceptions
    @action(detail=False, methods=["post"])
    def password(self, request):
        serializer = LoginPasswordSerializer(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response(
                {"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            # Retrieve user by email
            user = User.objects.get(email=email)
            token = user.tokens()

            route = request.resolver_match.view_name

            if route == "admin-login-password" and user.role not in ["admin", "super_admin"]:
                return CustomResponse.error(
                    message="Sorry, you are not authorized to login.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403
                )

            if route == "mobile-login-password" and user.role != "viewer":
                return CustomResponse.error(
                    message="Sorry, you are not authorized to login.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403
                )

        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=404,
            )

        if user.status and user.status == "deleted":
            return CustomResponse.error(
                message="This account has been deleted.",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403,
            )

        # Check if the password is correct
        if user.check_password(password):
            serializer = ReturnUserSerializer(user, many=False)

            user.last_login = datetime.now()
            user.save()
            # print(user.role)
            data = {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "last_login": user.last_login,
                "created_at": user.created_at,
                "created_password": user.created_password,
                "token": {"access": token["access"], "refresh": token["refresh"]},
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
                status_code=401,
            )

    @action(detail=False, methods=["post"])
    def resend_entry_code(self, request):

        serializer = ResendEntryCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        code = Util.generate_entry_code()

        user = EntryCode.objects.get(user__email=email)

        user.code = code
        user.save()

        # Prepare email data and send the email

        email_data = {
            "to_email": email,
            "email_subject": "Request For a New Entry Code",
            "email_body": f"Your new entry code: {code}",
        }

        EmailUtil.send_email(email_data)

        return CustomResponse.success(
            message="A new entry code has been sent to your email",
            status_code=200,
        )


class SendOtpCodeView(APIView):
    def post(self, request):
        serializer = ResendEntryCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')

        code = Util.generate_entry_code()
        SendOtp.objects.create(code=code)

        # Prepare email data and send the email
        email_data = {
            'to_email': email,
            'email_subject': "Request For a New Entry Code",
            'email_body': f"Your new entry code: {code}"
        }

        # Email send otp

        EmailUtil.send_email(email_data)

        return CustomResponse.success(
            message=f"A new entry code {code} has been sent to your email {email}",
            status_code=200,
        )


class DashboardViewSet(viewsets.ViewSet):

    serializer_class = SetPasswordSerializer
    permission_classes = [permissions.IsAuthenticated]
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["post"])
    def create_password(self, request):
        serializer = SetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = serializer.validated_data.get("password")
        confirm_password = serializer.validated_data.get("confirm_password")

        if password != confirm_password:

            return CustomResponse.error(
                message="Passwords does not match",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )

        user = request.user
        user.created_password = True
        user.set_password(password)
        user.save()

        return CustomResponse.success(
            message="Password created successfully", status_code=200
        )

    @action(detail=False, methods=["post"])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(

            data=request.data, context={"request": request}
        )

        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return CustomResponse.success(
            message="Password changed successfully", status_code=200
        )

    @action(detail=False, methods=["get"])
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
                status_code=400,
            )

        EmailUtil.send_password_reset_email(user)

        return CustomResponse.success(
            message="Password reset otp has been sent", status_code=200
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
                status_code=400,
            )

        if otp_obj.check_expiration():
            return CustomResponse.error(
                message="Otp has expired",
                err_code=ErrorCode.EXPIRED_OTP,
                status_code=400,
            )

        if route_name == "verify-email":
            user.is_email_verified = True
        elif route_name == "verify-otp":
            user.is_verified = True

        user.save()

        return CustomResponse.success(
            message="Otp successfully verified", status_code=200
        )


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
                status_code=400,
            )

        if not user.is_verified:
            return CustomResponse.error(
                message="You have not verified otp",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403,
            )

        if password != password2:
            return CustomResponse.error(
                message="Passwords do not match",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400,
            )

        user.set_password(password)
        user.is_verified = False
        user.save()

        return CustomResponse.success(
            message="Password changed successfully", status_code=200
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
            users = User.objects.all().exclude(email=os.getenv("ADMIN_EMAIL"))
        else:
            users = User.objects.filter(status=status).exclude(
                email=os.getenv("ADMIN_EMAIL"))
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
                message="Account deleted successfully.", status_code=200
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User with this account does not exist.",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def destroy(self, request, pk=None):
        try:
            user = User.objects.get_or_none(id=pk)

            if user.status == "registered":
                return CustomResponse.error(
                    message="Cannot delete a registered user.",
                    err_code=ErrorCode.BAD_REQUEST,
                    status_code=400,
                )

            user.delete()
            return CustomResponse.success(
                message="User deleted successfully", status_code=200
            )

        except User.DoesNotExist or user is None:
            return CustomResponse.error(
                message="User not found.", err_code=ErrorCode.NOT_FOUND, status_code=404
            )


class LogOutApiView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    @handle_custom_exceptions
    def post(self, request: Request) -> Response:
        refresh_token = request.COOKIES.get("refresh")

        if not refresh_token:
            return CustomResponse.error(
                message="Refresh token not found",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return CustomResponse.error(
                message="Invalid or expired refresh token",
                err_code=ErrorCode.UNAUTHORIZED,
                status_code=401,
            )
        except Exception as e:
            # Optional: log exception
            return CustomResponse.error(
                message="Logout failed",
                err_code=ErrorCode.INTERNAL_SERVER_ERROR,
                status_code=500,
            )

        response = CustomResponse.success(
            message="Logout successful", status_code=200)
        response.delete_cookie("refresh")
        response.delete_cookie("access")

        return response


class ForgotPasswordView(APIView):
    account_activation_token = PasswordResetTokenGenerator()

    def post(self, request):
        payload = {}
        email = request.data.get("email")
        if not email:
            return Response(
                {"success": False, "message": "Email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user = User.objects.get(email=email)

            reset_password_token = {
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": self.account_activation_token.make_token(user),
            }
            reset_url = f"{settings.FRONT_END_BASE_URL}reset-password?uid={reset_password_token['uid']}&token={reset_password_token['token']}"

            EmailUtil.send_reset_password_email_link(user, reset_url)
            payload = {
                "success": True,
                "message": "Password reset link has been sent to your email",
                "reset_url": reset_url,
            }
            return Response(payload, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(
                {"success": False, "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )


class ResetPasswordView(APIView):
    account_activation_token = PasswordResetTokenGenerator()

    # serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        new_password = request.data.get('password')
        uid = request.data.get('uid')
        token = request.data.get('token')

        if len(new_password) < 8:
            return Response({"msg": "At least enter 8 Character"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_uppercase(new_password):
            return Response({"msg": "One Uppercase Letter (A-Z)"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_lowercase(new_password):
            return Response({"msg": "One Lowercase Letter (A-Z)"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_number(new_password):
            return Response({"msg": "One Number (0-9)"}, status=status.HTTP_400_BAD_REQUEST)
        elif not has_special_character(new_password):
            return Response({"msg": "One Special Character (!@#$%^&*)"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                user_id = force_str(urlsafe_base64_decode(
                    uid))
                user = User.objects.get(pk=user_id)
                if not self.account_activation_token.check_token(user, token):
                    return Response({"msg": "Password link invalid, Pls request for a new one"}, status=status.HTTP_400_BAD_REQUEST)

                user.set_password(new_password)
                user.save()

                return Response(
                    {"msg": "Password Reset Successfully"}, status=status.HTTP_200_OK
                )
            except User.DoesNotExist:
                return Response({"msg": "User Does not exist"})


class AcceptInvitationView(GenericAPIView):
    serializer_class = SetPasswordWithInvitationSerializer

    def get(self, request):
        """Handle the invitation link click - validate token and return user email"""
        token = request.GET.get('token')
        if not token:
            return CustomResponse.error(
                message="Missing invitation token",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400
            )

        try:
            invitation = UserInvitation.objects.get(
                token=token,
                is_used=False
            )
        except UserInvitation.DoesNotExist:
            return CustomResponse.error(
                message="Invalid or expired invitation token",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400
            )

        if invitation.is_expired():
            return CustomResponse.error(
                message="Invitation token has expired",
                err_code=ErrorCode.EXPIRED_TOKEN,
                status_code=400
            )

        user = invitation.user
        if user.status != User.STATUS.INVITED:
            return CustomResponse.error(
                message="User already registered",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400
            )

        return CustomResponse.success(
            data={
                'email': user.email,
                'token': token
            },
            message="Invitation token is valid",
            status_code=200
        )

    @handle_custom_exceptions
    def post(self, request):
        """Handle password submission"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        password = serializer.validated_data["password"]
        password2 = serializer.validated_data["password2"]

        if password != password2:
            return CustomResponse.error(
                message="Passwords do not match",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400,
            )

        try:
            invitation = UserInvitation.objects.get(
                token=token,
                is_used=False
            )

        except UserInvitation.DoesNotExist:
            return CustomResponse.error(
                message="Invalid or expired invitation token",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400,
            )

        if invitation.is_expired():
            return CustomResponse.error(
                message="Invitation token has expired",
                err_code=ErrorCode.EXPIRED_TOKEN,
                status_code=400,
            )

        user = invitation.user
        if user.status != User.STATUS.INVITED:
            return CustomResponse.error(
                message="User already registered",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )

        # Set password and update status
        user.set_password(password)
        user.status = User.STATUS.REGISTERED
        user.created_password = True
        user.save()

        # Mark invitation as used
        invitation.is_used = True
        invitation.save()

        # Return tokens
        token = user.tokens()

        return CustomResponse.success(
            data={
                "user": ReturnUserSerializer(user).data,
                "token": token["access"],
                "refresh": token["refresh"],
            },
            message="Account activated successfully",

            status_code=200,
        )

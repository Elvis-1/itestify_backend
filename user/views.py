#import string
#from django.urls import reverse
import string
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework.decorators import action
from .models import EntryCode, Otp, User
from .utils import Util
from .serializers import LoginCodeEntrySerialiazer, LoginPasswordSerialiazer, ResendEntryCodeSerializer, SetPasswordSerializer, ReturnUserSerializer, ResendOtpSerializer, SetNewPasswordSerializer
from common.exceptions import handle_custom_exceptions
from common.responses import CustomResponse
from rest_framework.generics import GenericAPIView
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str



def has_uppercase(s):
    return any(char.isupper() for char in s)


def has_lowercase(s):
    return any(char.islower() for char in s)


def has_number(s):
    return any(char.isdigit() for char in s)


def has_special_character(s):
    special_char = string.punctuation
    return any(char in special_char for char in s)

# Create your views here.


class LoginViewSet(viewsets.ViewSet):

    serializer_class = LoginCodeEntrySerialiazer
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

            response = Response(
                {
                    'user': serializer.data,
                    "token": token["access"],
                    "refresh": token["refresh"]
                }
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

        return Response({'error': 'Invalid entry code'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"])
    def password(self, request):
        # serializer_class = LoginPasswordSerialiazer
        serializer = LoginPasswordSerialiazer(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        try:
            # Retrieve user by email
            user = User.objects.get(email=email)
            token = user.tokens()
        except User.DoesNotExist:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the password is correct
        if user.check_password(password):
            serializer = ReturnUserSerializer(user, many=False)

            response = Response(
                {
                    'user': serializer.data,
                    "token": token["access"],
                    "refresh": token["refresh"]
                }
            )

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
            return Response(
                {'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

    @action(detail=False, methods=["post"])
    def resend_entry_code(self, request):

        serializer = ResendEntryCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        # check if email and code exist in the database
        try:
            user = EntryCode.objects.get_or_none(user__email=email)
        except EntryCode.DoesNotExist:
            return Response({'success': False, "message": "User email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Generate a new entry code and update the user's entry code record
        if not user.code:
            return Response({"success": False, "message": "User is not an admin"}, status=status.HTTP_400_BAD_REQUEST)
        user.code = Util.generate_entry_code()
        user.is_used = False
        user.save()

        # Prepare email data and send the email
        email_data = {
            'to_email': email,
            'email_subject': "Request For a New Entry Code",
            'email_body': f"Your new entry code: {user.code}"
        }
        Util.send_email(email_data)

        return Response({'success': True, "message": f"A new entry code has been sent to your email {email}"}, status=status.HTTP_200_OK)




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
            return Response({"success": False, "message": "Passwords does not match"}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        user.created_password = True
        user.set_password(password)
        user.save()

        return Response({"success": True, "message": "Passwords change Successfully"}, status=status.HTTP_200_OK)

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

        Util.send_password_reset_email(user)

        return CustomResponse.success(
            message="Password reset otp has been sent",
            status_code=200
        )


class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    @handle_custom_exceptions
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


class UsersViewSet(viewsets.ViewSet):
    serializer_class = ReturnUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    # gets the list of registered users
    @action(detail=False, methods=["get"])
    def registered(self, request):
        try:
            registered_users = User.objects.filter(status="registered")
            serializer = self.serializer_class(registered_users, many=True)
            return CustomResponse.success(
                message="Registered users retrieved successfully",
                data=serializer.data,
                status_code=200
            )
        except User.DoesNotExist or registered_users == []:
            return CustomResponse.error(
                message="No deleted users",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404
            )

    # gets the list of deleted users

    @action(detail=False, methods=["get"])
    def deleted(self, request):
        try:
            deleted_users = User.objects.filter(status="deleted")
            serializer = self.serializer_class(deleted_users, many=True)
            return CustomResponse.success(
                message="Deleted users retrieved successfully",
                data=serializer.data,
                status_code=200
            )
        except User.DoesNotExist or deleted_users == []:
            return CustomResponse.error(
                message="No deleted users",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404
            )

    def destroy(self, request, pk=None):
        try:
            user = User.objects.get_or_none(id=pk)

            if user.status == "registered":
                return CustomResponse.error(
                    message="Cannot delete a registered user."
                )

            user.delete()
            return CustomResponse.success(
                message="User deleted successfully",
                status_code=200
            )
        except User.DoesNotExists or user is None:
            return CustomResponse.error(
                message="User not found.",
                err_code=ErrCode.NOT_FOUND,
                status_code=404
            )


class ForgotPasswordView(APIView):
    account_activation_token = PasswordResetTokenGenerator()

    def post(self, request):
        payload = {}
        email = request.data.get("email")
        if not email:
            return Response({"success": False, "message": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            Util.send_password_reset_email(user)
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
        otp = request.data.get('otp')
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
                otp_code = Otp.objects.get(user=user, code=int(otp))
                print(otp_code)
                if otp_code is None or otp_code.code != int(otp):
                    return Response({"msg": "Otp is not correct"}, status=status.HTTP_400_BAD_REQUEST)
                if otp_code.check_expiration():
                    return Response({"msg": "Otp has expired"}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(password)
                user.save()
                otp_code.delete()

                return Response({"msg": "Password Reset Successfully"}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"msg": "User Does not exist"})

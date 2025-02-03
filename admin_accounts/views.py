from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .models import AdminInvitationCode
import random
import string
from django.core.mail import send_mail

class AdminLoginView(APIView):
    """
    Handles admin login using email and password. Returns JWT tokens.
    """
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if not user.is_superuser:
                return Response({"error": "Only admin users can log in."}, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(username=user.username, password=password)
        if not user:
            return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)
        return Response({"refresh": str(refresh), "access": str(refresh.access_token)}, status=status.HTTP_200_OK)
    
    
class AdminLogoutView(APIView):
    """
    Logs out the admin by blacklisting the refresh token.
    """
    def post(self, request):
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"error": "Invalid token or logout failed."}, status=status.HTTP_400_BAD_REQUEST)
        

class SendInvitationCode(APIView):
    """
    Allows the initial admin to send a one-time invitation code to a new admin.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not request.user.is_superuser:
            return Response({"error": "Only superusers can send invitation codes."}, status=status.HTTP_403_FORBIDDEN)

        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        code = ''.join(random.choices(string.digits, k=6))
        invitation, created = AdminInvitationCode.objects.get_or_create(email=email)
        invitation.code = code
        invitation.created_at = now()
        invitation.is_used = False
        invitation.save()

        # Send email
        send_mail(
            subject="Admin Invitation Code",
            message=f"Your invitation code is {code}. It is valid for 24 hours.",
            from_email="yourapp@example.com",
            recipient_list=[email],
        )
        return Response({"message": f"Invitation code sent to {email}."}, status=status.HTTP_200_OK)
    
class ValidateInvitationCode(APIView):
    """
    Validates the invitation code sent to a new admin.
    """
    def post(self, request):
        email = request.data.get("email")
        code = request.data.get("code")

        try:
            invitation = AdminInvitationCode.objects.get(email=email)
        except AdminInvitationCode.DoesNotExist:
            return Response({"error": "Invalid email or code."}, status=status.HTTP_404_NOT_FOUND)

        if invitation.is_used:
            return Response({"error": "Code has already been used."}, status=status.HTTP_400_BAD_REQUEST)

        if invitation.is_expired():
            return Response({"error": "Code has expired."}, status=status.HTTP_400_BAD_REQUEST)

        if invitation.code != code:
            return Response({"error": "Invalid code."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Code is valid."}, status=status.HTTP_200_OK)


class CreatePassword(APIView):
    """
    Allows the new admin to create a password after validating the invitation code.
    """
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        if password != confirm_password:
            return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            invitation = AdminInvitationCode.objects.get(email=email, is_used=False)
        except AdminInvitationCode.DoesNotExist:
            return Response({"error": "Invalid email or code. Please validate first."}, status=status.HTTP_404_NOT_FOUND)

        # Create new admin user
        User.objects.create(
            email=email,
            username=email.split('@')[0],
            is_superuser=True,
            is_staff=True,
            password=make_password(password),
        )

        invitation.is_used = True
        invitation.save()
        return Response({"message": "Admin account created successfully."}, status=status.HTTP_201_CREATED)        
            
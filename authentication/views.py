# views.py
from django.shortcuts import render
from django.utils import timezone
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
import uuid
import time

from .models import CustomUser, Tokens


class SignupView(APIView):
    """
    View for user signup. Accepts email and sends a verification code.
    - Check if the email is already registered
    - Generate a verification code and it expires in 1 hour
    - Send the verification code to the user's email
    
    """
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": "Email is already in use"}, status=status.HTTP_400_BAD_REQUEST)

        
        token = str(uuid.uuid4())
        exp_date = time.time() + 3600

        Tokens.objects.create(
            email=email,
            action="signup",
            token=token,
            exp_date=exp_date
        )

        send_mail(
            subject="Your Signup Verification Code",
            message=f"Your verification code is: {token}",
            from_email="no-reply@example.com",
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({"message": "Verification email sent. Please check your inbox."}, status=status.HTTP_200_OK)


class VerifyTokenView(APIView):
    """
    View for verifying the token sent to the user's email.
    - Check if the token is valid
    - Check if the token has expired
    - Mark the token as used and confirm the user's signup
    - Create the user account
    """
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        token = request.data.get("token")

        if not email or not token:
            return Response({"error": "Email and token are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token_obj = Tokens.objects.get(email=email, token=token, action="signup")
        except Tokens.DoesNotExist:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        if token_obj.exp_date < time.time():
            return Response({"error": "Token has expired"}, status=status.HTTP_400_BAD_REQUEST)

        token_obj.used = True
        token_obj.confirmed = True
        token_obj.date_used = timezone.now()
        token_obj.save()

        user = CustomUser.objects.create_user(email=email, password=None)
        user.verified = True
        user.is_active = True
        user.save()

        return Response({"message": "Signup verified. Account created successfully."}, status=status.HTTP_201_CREATED)

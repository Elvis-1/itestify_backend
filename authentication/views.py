# views.py
import random
from django.core.mail import send_mail
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import OTP
from .serializers import OTPRequestSerializer, OTPVerifySerializer

class RequestOTPView(APIView):
    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        otp_code = str(random.randint(100000, 999999))
        OTP.objects.create(user=user, otp_code=otp_code)

        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp_code}. It is valid for 10 minutes.',
            'your-email@gmail.com',
            [email],
            fail_silently=False,
        )
        return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']

        try:
            user = User.objects.get(email=email)
            otp_obj = OTP.objects.filter(user=user, otp_code=otp).first()

            if otp_obj and otp_obj.is_valid():
                otp_obj.delete()  # Invalidate the OTP after successful verification
                return Response({"message": "OTP verified. Login successful."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

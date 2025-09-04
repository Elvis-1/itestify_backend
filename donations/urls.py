from django.urls import path

from .views import PaymentAPIView, UpdateChargeWithOTPView, UpdateChargeWithPINView


urlpatterns = [
    path("payments/initiate/", PaymentAPIView.as_view(), name="update-pin"),
    path("payments/update-pin/", UpdateChargeWithPINView.as_view(), name="update-pin"),
    path("payments/update-OTP/", UpdateChargeWithOTPView.as_view(), name="update-OTP")
]

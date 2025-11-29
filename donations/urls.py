from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import PaymentAPIView, VerifyPaymentView, TransactionViewSet, DonationStatsView
from .webhooks import FlutterwaveWebhookView, GeneralWebhookView

router = DefaultRouter()
router.register(r'transactions', TransactionViewSet, basename='transactions')

urlpatterns = [
    path("payments/initiate/", PaymentAPIView.as_view(), name="initiate-payment"),
    path("payments/verify/", VerifyPaymentView.as_view(), name="verify-payment"),
    path("stats/", DonationStatsView.as_view(), name="donation-stats"),
    path("webhooks/<str:provider>/", GeneralWebhookView.as_view(), name="general-webhook"),
    path("webhooks/flutterwave/", FlutterwaveWebhookView.as_view(), name="flutterwave-webhook"),
    path("", include(router.urls)),
]

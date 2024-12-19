from django.urls import path
from .views import SignupView, VerifyTokenView

urlpatterns = [
    path('signup', SignupView.as_view(), name='signup'),
    path('verify-token', VerifyTokenView.as_view(), name='verify_token'),
]

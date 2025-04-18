from django.urls import path
from .views import UserRegisterAPIView, LoginAPIView, SendPasswordResetOtpView, SetNewPasswordView, GetRegisteredUsers, VerifyOtpView, DeleteUserAccount


urlpatterns = [
    path('register', UserRegisterAPIView.as_view()),
    path('login', LoginAPIView.as_view()),
    path('password-reset-otp', SendPasswordResetOtpView.as_view()),
    path("verify-otp", VerifyOtpView.as_view()),
    path('reset-password', SetNewPasswordView.as_view()),
    path("get_users", GetRegisteredUsers.as_view()),
    path("delete", DeleteUserAccount.as_view()),
]
from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import (
    DashboardViewSet,
    AcceptInvitationView,
    LoginViewSet,
    UsersViewSet,
    SendPasswordResetOtpView,
    ForgotPasswordView,
    ResetPasswordView,
    VerifyOtpView,
    SetNewPasswordView,
    RegisterViewSet,
    LogOutApiView,
    SendOtpCodeView,
)

router = DefaultRouter()
router.register(r"mobile-login", LoginViewSet, basename="mobile-login")
router.register(r"admin-login", LoginViewSet, basename="admin-login")
router.register(r"dashboard", DashboardViewSet, basename="dashboard")
router.register(r"users", UsersViewSet, basename="users")

urlpatterns = [
    path("register", RegisterViewSet.as_view({"post": "register"}), name="register"),
    path(
        "resend-email-verification-token",
        RegisterViewSet.as_view({"post": "resend_verification_token"}),
        name="resend-email-token",
    ),
    path(
        "password-reset-otp",
        SendPasswordResetOtpView.as_view(),
        name="send-password-reset-otp",
    ),
    path("verify-email", VerifyOtpView.as_view(), name="verify-email"),
    path("verify-otp", VerifyOtpView.as_view(), name="verify-otp"),
    path("reset-password", SetNewPasswordView.as_view(), name="reset-password"),
    path("logout", LogOutApiView.as_view(), name="logout"),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/',
     ResetPasswordView.as_view(), name='reset-user-pass'),
    path(
        "accept-invitation/", AcceptInvitationView.as_view(), name="accept-invitation"
    ),
    path("send-otp/", SendOtpCodeView.as_view(), name="send-otp"),
]

urlpatterns += router.urls

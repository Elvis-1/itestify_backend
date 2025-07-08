from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import (
    DashboardViewSet,
    MemberManagementViewSet,
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

    PermissionViewSet,
    RoleViewSet,
    SuperAdminManagementViewSet,
    AdminManagementViewSet,

)

router = DefaultRouter()
router.register(r"login", LoginViewSet, basename="login")
router.register(r"dashboard", DashboardViewSet, basename="dashboard")
router.register(r"users", UsersViewSet, basename="users")
router.register(r"members", MemberManagementViewSet, basename="members")
router.register(r"permissions", PermissionViewSet, basename="permission")
router.register(r"roles", RoleViewSet, basename="role")

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


    path('super-admin/', SuperAdminManagementViewSet.as_view({
        'post': 'transfer_super_admin',
        'get': 'get_eligible_users'
    }), name='super-admin-management'),
    
    path('admin-management/', AdminManagementViewSet.as_view({
        'post': 'manage_admin',
        'get': 'get_eligible_admins'
    }), name='admin-management'),

]

urlpatterns += router.urls

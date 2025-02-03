from django.urls import path
from .views import (
    AdminLoginView, AdminLogoutView, SendInvitationCode,
    ValidateInvitationCode, CreatePassword
)

urlpatterns = [
    path('login/', AdminLoginView.as_view(), name='admin-login'),
    path('logout/', AdminLogoutView.as_view(), name='admin-logout'),
    path('send-invitation-code/', SendInvitationCode.as_view(), name='send-invitation-code'),
    path('validate-invitation-code/', ValidateInvitationCode.as_view(), name='validate-invitation-code'),
    path('create-password/', CreatePassword.as_view(), name='create-password'),
]
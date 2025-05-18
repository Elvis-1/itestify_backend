from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import DashboardViewSet, LoginViewSet, UsersViewSet, ForgotPasswordView, ResetPasswordView


router = DefaultRouter()
router.register(r'login', LoginViewSet, basename="login")
router.register(r'dashboard', DashboardViewSet, basename="dashboard")
router.register(r'users', UsersViewSet, basename="users")


urlpatterns = [
    path('', include(router.urls)),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/<str:uidb64>/<str:token>/',
         ResetPasswordView.as_view(), name='reset-user-pass'),
]

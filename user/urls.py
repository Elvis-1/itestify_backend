from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import DashboardViewSet, LoginViewSet, UsersViewSet, ForgotPasswordViewSet


router = DefaultRouter()
router.register(r'login', LoginViewSet, basename="login")
router.register(r'dashboard', DashboardViewSet, basename="dashboard")
router.register(r'users', UsersViewSet, basename="users")
router.register(r'login', ForgotPasswordViewSet, basename="forgot_pass")

urlpatterns = router.urls

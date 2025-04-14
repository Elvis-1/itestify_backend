from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import DashboardViewSet, LoginViewSet, UsersViewSet


router = DefaultRouter()
router.register(r'login', LoginViewSet, basename="login")
router.register(r'dashboard', DashboardViewSet, basename="dashboard")
router.register(r"users", UsersViewSet, basename="users")

urlpatterns = router.urls
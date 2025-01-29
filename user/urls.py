from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import DashboardViewSet, LoginViewSet


router = DefaultRouter()
router.register(r'login', LoginViewSet, basename="login")
router.register(r'dashboard', DashboardViewSet, basename="dashboard")

urlpatterns = router.urls
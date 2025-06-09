"""
URL configuration for itestify_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
# from user.views import GoogleLoginCallback


def home(request):
    return JsonResponse(
        {
            "message": "Welcome to the Itestify API",
            "data": {
                "version": "1.0.0",
                "docs": "https://documenter.getpostman.com/view/25513956/2sAYX6pMfe",
            },
        }
    )


urlpatterns = [
    path('admin/', admin.site.urls),  # Django admin
    path("", home),  # Home page
    path('', include('testimonies.urls')),
    path('auths/', include('user.urls')),
    path('', include('donations.urls')),
    path('', include("scriptures.urls")),
    path('review/', include('reviews.urls')),
    path("api/v1/auth/", include("dj_rest_auth.urls")),
    path('api/v1/auth/accounts/', include('allauth.urls')),
    path("common/", include("common.urls")),
    # path("api/v1/auth/registration/", include("dj_rest_auth.registration.urls")),
    # path("api/v1/auth/google/", GoogleLogin.as_view(), name="google_login"),


]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)

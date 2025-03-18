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
    path('', include('user.urls')),
    path('', include('donations.urls')),
    path("mobile/auth/", include("mobile_user_auth.urls")),
    path("mobile/", include("mobile_user_testimonies.urls"))
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

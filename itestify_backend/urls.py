from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from user.views import GoogleLoginAPIView


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
    path('notifications/', include('notifications.urls')),
    path('auths/', include('user.urls')),
    path('', include('donations.urls')),
    path('', include("scriptures.urls")),
    path('review/', include('reviews.urls')),
    path("auths/auth/", include("dj_rest_auth.urls")),
    path('auths/accounts/', include('allauth.urls')),
    path("auths/google-login/", GoogleLoginAPIView.as_view(), name="google_login"),
    #path("api/v1/auth/registration/", include("dj_rest_auth.registration.urls")),
    path("common/", include("common.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)

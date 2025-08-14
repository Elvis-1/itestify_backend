"""
ASGI config for itestify_backend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator
from django.urls import path
from scriptures.consumers import ScheduleScriptureConsumer
from notifications.consumers import NotificationConsumer
import os
from .jwt_auth_middleware import JWTAuthMiddlewareStack


from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'itestify_backend.settings')

django_asgi_app = get_asgi_application()
# print(django_asgi_app)

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AllowedHostsOriginValidator(
        JWTAuthMiddlewareStack(
            URLRouter([
                path('ws/scripture_room_name/',
                     ScheduleScriptureConsumer.as_asgi()),
                path('ws/notification/',
                     NotificationConsumer.as_asgi()),

            ])
        )
    ),

})

print(application)

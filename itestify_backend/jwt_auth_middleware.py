"""Authentication classes for channels."""
from urllib.parse import parse_qs
from channels.auth import AuthMiddlewareStack  # type: ignore
from channels.db import database_sync_to_async  # type: ignore
from django.conf import settings
from django.db import close_old_connections
from jwt import InvalidSignatureError, ExpiredSignatureError, DecodeError  # type: ignore
from jwt import decode as jwt_decode  # type: ignore


class JWTAuthMiddleware:
    """Middleware to authenticate user for channels"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        """Authenticate the user based on jwt."""
        close_old_connections()

        # import AFTER Django apps are ready
        from django.contrib.auth.models import AnonymousUser  

        try:
            # Extract token from query string
            token = parse_qs(scope["query_string"].decode("utf8")).get("token", None)[0]

            # Decode token
            data = jwt_decode(token, settings.SECRET_KEY, algorithms=["HS256"])

            # Get user from DB
            scope["user"] = await self.get_user(data["user_id"])
        except (TypeError, KeyError, InvalidSignatureError, ExpiredSignatureError, DecodeError):
            scope["user"] = AnonymousUser()

        return await self.app(scope, receive, send)

    @database_sync_to_async
    def get_user(self, user_id):
        """Return the user based on user id."""
        from django.contrib.auth import get_user_model
        from django.contrib.auth.models import AnonymousUser

        User = get_user_model()
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return AnonymousUser()


def JWTAuthMiddlewareStack(app):
    """Wrap channels authentication stack with JWTAuthMiddleware."""
    return JWTAuthMiddleware(AuthMiddlewareStack(app))

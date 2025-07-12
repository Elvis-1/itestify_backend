import jwt
import logging
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from user.models import User

logger = logging.getLogger(__name__)

class JWTUserMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.headers.get('Authorization')

        # Default to None if no token provided
        request.user_data = None

        if not auth_header or not auth_header.startswith('Bearer '):
            return  # No token, continue request

        token = auth_header.split(' ')[1]

        try:
            # Decode token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id') or payload.get('id')

            if not user_id:
                logger.warning("JWT token decoded but no user_id found")
                return JsonResponse({'detail': 'Invalid token structure'}, status=401)

            try:
                user = User.objects.get(id=user_id)
                request.user_data = {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "is_verified": user.is_verified,
                    "role": user.role,
                }
            except User.DoesNotExist:
                logger.warning(f"User with ID {user_id} not found from JWT")
                return JsonResponse({'detail': 'User not found'}, status=404)

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return JsonResponse({'detail': 'Token expired'}, status=401)

        except jwt.DecodeError:
            logger.error("JWT decode error")
            return JsonResponse({'detail': 'Invalid token'}, status=401)

        except Exception as e:
            logger.exception("Unexpected error in JWT middleware")
            return JsonResponse({'detail': 'Internal server error'}, status=500)

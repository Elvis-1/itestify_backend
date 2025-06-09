import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from user.models import User 

class JWTUserMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

            try:
                # Decode token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

                # Optionally: attach the full user
                user_id = payload.get('user_id') or payload.get('id')
                if user_id:
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
                        request.user_data = None
                else:
                    request.user_data = None

            except jwt.ExpiredSignatureError:
                return JsonResponse({'detail': 'Token expired'}, status=401)
            except jwt.DecodeError:
                return JsonResponse({'detail': 'Invalid token'}, status=401)
        else:
            request.user_data = None

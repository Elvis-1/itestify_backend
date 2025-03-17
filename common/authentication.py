from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
import jwt

User = get_user_model()

class CustomJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return None  # No credentials provided, let other auth methods handle it
        
        try:
            # Expecting "Bearer <token>"
            prefix, token = auth_header.split(' ')
            if prefix.lower() != 'bearer':
                raise AuthenticationFailed('Invalid token header. Must start with Bearer.')
        except ValueError:
            raise AuthenticationFailed('Invalid token header. No token provided.')

        try:
            # Decode the token
            decoded_token = AccessToken(token)
            user_id = decoded_token['user_id']
            user = User.objects.get(id=user_id)
            
            if not user.is_active:
                raise AuthenticationFailed('User account is disabled.')
            
            return (user, token)  # Return user and token
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired.')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token.')
        except User.DoesNotExist:
            raise AuthenticationFailed('No user matching this token.')
        except Exception as e:
            raise AuthenticationFailed(f'Authentication error: {str(e)}')

    def authenticate_header(self, request):
        return 'Bearer'
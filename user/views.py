from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from user.models import User
from django.contrib.auth import authenticate, login

from user.serializers import LoginCodeEntrySerialiazer, SetPasswordSerializer, ReturnUserSerializer

# Create your views here.

class LoginViewSet(viewsets.ViewSet):
    
    serializer_class = LoginCodeEntrySerialiazer
    permission_classes = [permissions.AllowAny]
    
    @action(detail=False, methods=["post"])
    def entry_code(self, request):
        
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        entry_code = serializer.validated_data["entry_code"]

        try:
            user = User.objects.get(email=email)
            entry_code_obj = user.entry_code.all().first()
            token = user.tokens()

            if entry_code_obj.code == entry_code and not entry_code_obj.is_used:
                login(request, user)
                entry_code_obj.is_used = True
                entry_code_obj.save()
                
                serializer = ReturnUserSerializer(user, many=False)

                response = Response(
                        {
                            'user': serializer.data, 
                            "token": token["access"],
                            "refresh": token["refresh"],
                        }
                    )
                
                response.set_cookie(
                    key="refresh",
                    value=token["refresh"],
                    httponly=True,  # Set HttpOnly flag
                )
                response.set_cookie(
                    key="access", value=token["access"], httponly=True  # Set HttpOnly flag
                )
                
                return response
            else:
                return Response({'error': 'Invalid entry code'}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        

class DashboardViewSet(viewsets.ViewSet):
    
    serializer_class = SetPasswordSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=["post"])
    def create_password(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        password = serializer.validated_data.get("password")
        confirm_password = serializer.validated_data.get("confirm_password")
        
        if password != confirm_password:
            return Response({"success": False, "message": "Passwords does not match"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        user.set_password(password)
        user.save()
    
        return Response({"success": True, "message": "Passwords change Successfully"}, status=status.HTTP_200_OK)

        
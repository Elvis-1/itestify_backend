from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from user.models import EntryCode, User
from .utils import Util
from .serializers import LoginCodeEntrySerialiazer, LoginPasswordSerialiazer, ResendEntryCodeSerializer, SetPasswordSerializer, ReturnUserSerializer

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
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        
        entry_code_obj = user.entry_code.all().first()
        token = user.tokens()

        if entry_code_obj.code == entry_code and not entry_code_obj.is_used:
            entry_code_obj.is_used = True
            entry_code_obj.save()
            
            serializer = ReturnUserSerializer(user, many=False)

            response = Response(
                    {
                        'user': serializer.data, 
                        "token": token["access"],
                        "refresh": token["refresh"]
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
        
        return Response({'error': 'Invalid entry code'}, status=status.HTTP_400_BAD_REQUEST)
    
    
    @action(detail=False, methods=["post"])
    def password(self, request):
        # serializer_class = LoginPasswordSerialiazer
        serializer = LoginPasswordSerialiazer(data=request.data)
        if not serializer.is_valid(raise_exception=True):
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        
        try:
            # Retrieve user by email
            user = User.objects.get(email=email)
            token = user.tokens()
        except User.DoesNotExist:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)


        # Check if the password is correct
        if user.check_password(password):
            serializer = ReturnUserSerializer(user, many=False)

            response = Response(
                    {
                        'user': serializer.data, 
                        "token": token["access"],
                        "refresh": token["refresh"]
                    }
                )
            
            response.set_cookie(
                key="refresh",
                value=token["refresh"],
                httponly=True,  # Set HttpOnly flag
            )
            response.set_cookie(
                key="access",
                value=token["access"],
                httponly=True,  # Set HttpOnly flag
            )
            
            return response
            
        else:
            return Response(
                {'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
            
    
    @action(detail=False, methods=["post"])
    def resend_entry_code(self, request):
        
        serializer = ResendEntryCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        
        # check if email exist in the datsbase
        try:
            user = EntryCode.objects.get(user__email=email)
        except EntryCode.DoesNotExist:
            return Response({'success': False, "message": "User email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        
        # Generate a new entry code and update the user's entry code record
        user.code = Util.generate_entry_code()
        user.is_used = False
        user.save()
        
        # Prepare email data and send the email
        email_data = {
            'to_email': email,
            'email_subject': "Request For a New Entry Code",
            'email_body': f"Your new entry code: {user.code}"
        }
        Util.send_email(email_data)
        
        return Response({'success': True, "message": f"A new entry code has been sent to your email {email}"}, status=status.HTTP_200_OK)
    

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
        user.created_password = True
        user.set_password(password)
        user.save()
    
        return Response({"success": True, "message": "Passwords change Successfully"}, status=status.HTTP_200_OK)



    @action(detail=False, methods=['get'])
    def stats(self, request):
        pass
        
from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsAuthenticated(BasePermission):
    # Custom Permissions: Allows guest to read but restrict modifications to authenticated users
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_authenticated and (request.user.role == "super_admin" or request.user.role == "admin"))
    
    
    
    
    
    

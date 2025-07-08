from rest_framework.permissions import BasePermission

class IsSuperAdmin(BasePermission):
    """
    Allows access only to super admin users.
    """
    def has_permission(self, request, view):
        return request.user.is_super_admin

class IsAdmin(BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        return request.user.role and request.user.role.name == 'Admin'

class IsViewer(BasePermission):
    """
    Allows access only to viewer users.
    """
    def has_permission(self, request, view):
        return request.user.role and request.user.role.name == 'Viewer'

class HasPermission(BasePermission):
    """
    Checks if user has specific permission.
    """
    def __init__(self, permission_codename):
        self.permission_codename = permission_codename

    def has_permission(self, request, view):
        return request.user.has_perm(self.permission_codename)
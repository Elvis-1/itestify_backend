# permissions.py
from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.exceptions import PermissionDenied

class RolePermission(BasePermission):
    def __init__(self, required_permission=None):
        self.required_permission = required_permission

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True

        if not request.user or not request.user.is_authenticated:
            return False

        user_role = getattr(request.user, "role", None)

        if user_role.name == "Super Admin":
            return True

        user_permissions = getattr(user_role, "permissions", [])
        if self.required_permission in user_permissions:
            return True

        raise PermissionDenied(f"Missing permission: {self.required_permission}")
        # return False



def make_permission(permission_name):
    return type(
        f"{permission_name.replace(' ', '')}Permission",
        (RolePermission,),
        {"__init__": lambda self: super(type(self), self).__init__(required_permission=permission_name)}
    )


class Perm:
    TESTIMONY_MANAGEMENT = make_permission("Testimony Management")
    USER_MANAGEMENT = make_permission("User Management")
    PRIVACY_MANAGEMENT = make_permission("Privacy and Security Management")







# from rest_framework.permissions import BasePermission, SAFE_METHODS

# class UserManagementPermission(BasePermission):
#     def has_permission(self, request, view):
#         if request.method in SAFE_METHODS:
#             return True

#         if not request.user.is_authenticated:
#             return False

#         return bool((request.user and "User Management" in request.user.role.permissions) or request.user.role.name == "Super Admin")


# class TestimonyManagementPermisson(BasePermission):
#     def has_permission(self, request, view):
#         if request.method in SAFE_METHODS:
#             return True

#         return bool(request.user and "Testimony Management" in request.user.role.permissions)

    
# class DonationManagementPermisson(BasePermission):
#     def has_permission(self, request, view):
#         if request.method in SAFE_METHODS:
#             return True

#         return bool(request.user and "Donation Management" in request.user.role.permissions)


# class ReviewManagementPermisson(BasePermission):
#     def has_permission(self, request, view):
#         if request.method in SAFE_METHODS:
#             return True

#         return bool(request.user and "Review Management" in request.user.role.permissions)



# class PrivacyAndSecurityManagementPermisson(BasePermission):
#     def has_permission(self, request, view):
#         if request.method in SAFE_METHODS:
#             return True

#         return bool(request.user and "Privacy and Security Management" in request.user.role.permissions)


# class AdminManagementPermisson(BasePermission):
#     def has_permission(self, request, view):
#         if request.method in SAFE_METHODS:
#             return True

#         return bool(request.user and "Admin Management" in request.user.role.permissions)

    

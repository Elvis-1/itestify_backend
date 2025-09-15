from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from user.models import Otp, SendOtp, User, EntryCode, UserInvitation, Role

# Register your models here.



class UserAdmin(BaseUserAdmin):
    ordering = ['email']
    list_display = ['email', 'full_name', 'is_staff', 'is_superuser']
    search_fields = ['email', 'full_name']
    readonly_fields = ['last_login']
    list_filter = ['is_staff', 'is_superuser']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('full_name',)}),
        (_('Permissions'), {
            'fields': ('is_staff', 'is_superuser', 'role', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'full_name', 'password1', 'password2', 'role', 'is_staff', 'is_superuser'),
        }),
    )

    

# Register all models you want visible in the admin
admin.site.register(User, UserAdmin)
admin.site.register(EntryCode)
admin.site.register(Otp)
admin.site.register(SendOtp)
admin.site.register(UserInvitation)
admin.site.register(Role)
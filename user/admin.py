from django.contrib import admin

from user.models import User, EntryCode, SendOtp2

# Register your models here.

admin.site.register(User)
admin.site.register(EntryCode)
admin.site.register(SendOtp2)

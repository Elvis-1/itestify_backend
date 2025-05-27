from django.contrib import admin

from user.models import User, EntryCode#, Otp

# Register your models here.

admin.site.register(User)
admin.site.register(EntryCode)
#admin.site.register(Otp)
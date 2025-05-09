from django.contrib import admin
from .models import ScriptureComment, Scriptures

# Register your models here.
admin.site.register([ScriptureComment, Scriptures])

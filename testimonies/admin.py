from django.contrib import admin
from .models import TextTestimony

@admin.register(TextTestimony)
class TextTestimonyAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'date_submitted', 'status', 'likes', 'comments', 'shares')

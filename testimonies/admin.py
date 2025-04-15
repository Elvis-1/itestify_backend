from django.contrib import admin
from .models import InspirationalPictures, TextTestimony, VideoTestimony, Comment, Like, Share, TestimonySettings

@admin.register(TextTestimony)
class TextTestimonyAdmin(admin.ModelAdmin):
    pass


@admin.register(TestimonySettings)
class TestimonySettingsAdmin(admin.ModelAdmin):
    pass


@admin.register(VideoTestimony)
class VideoTestimonyAdmin(admin.ModelAdmin):
    pass

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    pass

@admin.register(Like)
class LikeAdmin(admin.ModelAdmin):
    pass

@admin.register(Share)
class ShareAdmin(admin.ModelAdmin):
    pass

@admin.register(InspirationalPictures)
class InspirationalPicturesAdmin(admin.ModelAdmin):
    pass

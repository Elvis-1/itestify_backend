from django.urls import include, path
from .views import (InspirationalPicturesViewSet, ShowAllInspirationalPicturesStatus, TextTestimonyApprovalView,
                    TextTestimonyListView, TestimonySettingsView, TextTestimonyViewSet, VideoTestimonyViewSet,
                    TextTestimonyByCategoryView, TextTestimonyCommentsView, TextTestimonyLikesView,
                    VideoTestimonyByCategoryView, ShowAllUplaodedInspirationalPictures, VideoTestimonyCommentsView, VideoTestimonyLikesView, TextTestimonyDetailView, VideoTestimonyDetailView, InpirationalPicturesSharesCount, DownloadedInspirationalPictureCountView)
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r'testimonies/texts', TextTestimonyViewSet,
                basename="text-testimonies")
router.register(r'testimonies/videos', VideoTestimonyViewSet,
                basename="video-testimonies")
router.register(r'inspirational', InspirationalPicturesViewSet,
                basename="inspirational")

urlpatterns = [
    path('', include(router.urls)),
    path('text-testimonies/', TextTestimonyListView.as_view(),
         name='text-testimonies'),
    path('text-testimonies-detail/<id>/', TextTestimonyDetailView.as_view(),
         name='text-testimonies-detail'),
    path('video-testimonies-detail/<id>/', VideoTestimonyDetailView.as_view(),
         name='text-testimonies-detail'),
    path('text-testimonies/<str:pk>/review/',
         TextTestimonyApprovalView.as_view(), name='text-testimony-review'),
    path('testimonies/settings/', TestimonySettingsView.as_view(),
         name='testimony-settings'),
    path('testimonies/<str:category>/',
         TextTestimonyByCategoryView.as_view(), name='testimony-by-category'),
    path('testimonies/comment/<id>/',
         TextTestimonyCommentsView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/all-comment/<id>/',
         TextTestimonyCommentsView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/like/<id>/',
         TextTestimonyLikesView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/all-like/<id>/',
         TextTestimonyLikesView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/video/<str:category>/',
         VideoTestimonyByCategoryView.as_view(), name='testimony-by-category'),
    path('testimonies/video-comment/<id>/',
         VideoTestimonyCommentsView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/video-comment-all/<id>/',
         VideoTestimonyCommentsView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/video-like/<id>/',
         VideoTestimonyLikesView.as_view(), name='testimony-by-category-comment'),
    path('testimonies/all-liked-video/<id>/',
         VideoTestimonyLikesView.as_view(), name='testimony-by-category-comment'),
    path('get-all-inspirational-status/',
         ShowAllInspirationalPicturesStatus.as_view()),
    path('inspirational-pictures-shares-count/<id>/',
         InpirationalPicturesSharesCount.as_view(), name='inspirational-pictures-shares-count'),
    path('inspirational-pictures-download-count/<id>/',
         DownloadedInspirationalPictureCountView.as_view(), name='inspirational-pictures-download-count'),
    path('get-all-uplaoded-inspirational-pictures/',
         ShowAllUplaodedInspirationalPictures.as_view(), name='inspirational-pictures-download-count'),
]

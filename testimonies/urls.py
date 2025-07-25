from django.urls import include, path
from .views import (
    InspirationalPicturesViewSet,
    ShowAllInspirationalPicturesStatus,
    TextTestimonyApprovalView,
    TextTestimonyListView,
    TestimonySettingsView,
    TextTestimonyViewSet,
    VideoTestimonyDeleteSelected,
    VideoTestimonyViewSet,
    TextTestimonyByCategoryView,
    TextTestimonyCommentsView,
    TextTestimonyLikesView,
    VideoTestimonyByCategoryView,
    ShowAllUplaodedInspirationalPictures,
    TextTestimonyReplyComment,
    VideoTestimonyCommentsView,
    VideoTestimonyLikesView,
    TextTestimonyDetailView,
    VideoTestimonyDetailView,
    InpirationalPicturesSharesCount,
    UserLikeInspirationalPicture,
    VideoTestimonyLikeUserComment,
    TextTestimonyDeleteSelected,
    TextTestimonyLikeUserComment,
    ShowAllUplaodInspirationalPicturesByStatus,
    DownloadedInspirationalPictureCountView,
    GetCommentFromATextTestimony,
    VideoTestimonyReplyComment,
    editTextTestimonyComment,
)
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r"testimonies/texts", TextTestimonyViewSet, basename="text-testimonies")
router.register(
    r"testimonies/videos", VideoTestimonyViewSet, basename="video-testimonies"
)
router.register(
    r"inspirational", InspirationalPicturesViewSet, basename="inspirational"
)

urlpatterns = [
    path("", include(router.urls)),
    path("text-testimonies/", TextTestimonyListView.as_view(), name="text-testimonies"),
    path(
        "delete-selected-videotestimony/",
        VideoTestimonyDeleteSelected.as_view(),
        name="hello",
    ),
    path(
        "delete-selected-texttestimony/",
        TextTestimonyDeleteSelected.as_view(),
        name="hello",
    ),
    path(
        "get-a-commenttexttestimony/<id>/",
        GetCommentFromATextTestimony.as_view(),
        name="",
    ),
    path(
        "text-testimonies-detail/<id>/",
        TextTestimonyDetailView.as_view(),
        name="text-testimonies-detail",
    ),
    path("edit-text-testimonies/<id>/", TextTestimonyDetailView.as_view(), name=""),
    path(
        "video-testimonies-detail/<id>/",
        VideoTestimonyDetailView.as_view(),
        name="text-testimonies-detail",
    ),
    path(
        "text-testimonies/<str:pk>/review/",
        TextTestimonyApprovalView.as_view(),
        name="text-testimony-review",
    ),
    path(
        "testimonies/settings/",
        TestimonySettingsView.as_view(),
        name="testimony-settings",
    ),
    path(
        "testimonies/<str:category>/",
        TextTestimonyByCategoryView.as_view(),
        name="testimony-by-category",
    ),
    path(
        "testimonies/comment/<id>/",
        TextTestimonyCommentsView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/comment-reply/<id>/",
        TextTestimonyReplyComment.as_view(),
        name="testimony-text-reply",
    ),
    path(
        "testimonies/get-comment-reply/<id>/",
        TextTestimonyReplyComment.as_view(),
        name="testimony-text-reply",
    ),
    path(
        "testimonies/all-comment/<id>/",
        TextTestimonyCommentsView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/edit-texttestimony-comment/<id>/",
        editTextTestimonyComment.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/text-testimony-like-user-comment/<id>/",
        TextTestimonyLikeUserComment.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/get-text-testimony-like-user-comment-count/<id>/",
        TextTestimonyLikeUserComment.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/like/<id>/",
        TextTestimonyLikesView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/all-like/<id>/",
        TextTestimonyLikesView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/video/<str:category>/",
        VideoTestimonyByCategoryView.as_view(),
        name="testimony-by-category",
    ),
    path(
        "testimonies/video-comment/<id>/",
        VideoTestimonyCommentsView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/reply-video-comment/<id>/",
        VideoTestimonyReplyComment.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/video-comment-all/<id>/",
        VideoTestimonyCommentsView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/video-like/<id>/",
        VideoTestimonyLikesView.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/video-testimony-like-user-comment/<id>/",
        VideoTestimonyLikeUserComment.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/get-video-testimony-like-user-comment-count/<id>/",
        VideoTestimonyLikeUserComment.as_view(),
        name="testimony-by-category-comment",
    ),
    path(
        "testimonies/all-liked-video/<id>/",
        VideoTestimonyLikesView.as_view(),
        name="testimony-by-category-comment",
    ),
    path("get-all-inspirational-status/", ShowAllInspirationalPicturesStatus.as_view()),
    path(
        "get-inspirational-by-status/",
        ShowAllUplaodInspirationalPicturesByStatus.as_view(),
    ),
    path(
        "inspirational-pictures-shares-count/<id>/",
        InpirationalPicturesSharesCount.as_view(),
        name="inspirational-pictures-shares-count",
    ),
    path(
        "inspirational-pictures-download-count/<id>/",
        DownloadedInspirationalPictureCountView.as_view(),
        name="inspirational-pictures-download-count",
    ),
    path(
        "get-all-uplaoded-inspirational-pictures/",
        ShowAllUplaodedInspirationalPictures.as_view(),
        name="inspirational-pictures-download-count",
    ),
    path(
        "inspirational-pictures-like/<id>/",
        UserLikeInspirationalPicture.as_view(),
        name="inspirational-pictures-like",
    ),
    path(
        "inspirational-pictures-count/<id>/",
        UserLikeInspirationalPicture.as_view(),
        name="inspirational-pictures-count",
    ),
]

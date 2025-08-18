from django.urls import include, path
from .views import (
    InspirationalPicturesViewSet,
    ShowAllInspirationalPicturesStatus,
    TextTestimonyListView,
    TestimonySettingsView,
    TextTestimonyViewSet,
    VideoTestimonyDeleteSelected,
    VideoTestimonyViewSet,
    # VideoTestimonyByCategoryView,
    ShowAllUplaodedInspirationalPictures,
    VideoTestimonyLikesView,
    TextTestimonyDetailView,
    InpirationalPicturesSharesCount,
    UserLikeInspirationalPicture,
    TextTestimonyDeleteSelected,
    ShowAllUplaodInspirationalPicturesByStatus,
    DownloadedInspirationalPictureCountView,
    VideoTestimonyReplyComment,
    CommentViewSet,
    LikeViewset
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
router.register(
    r"testimony", CommentViewSet, basename="comment",
)
router.register(
    r"testimonies", LikeViewset, basename="like",
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
        "text-testimonies-detail/<id>/",
        TextTestimonyDetailView.as_view(),
        name="text-testimonies-detail",
    ),
    path("edit-text-testimonies/<id>/", TextTestimonyDetailView.as_view(), name=""),
    # path(
    #     "text-testimonies/<str:pk>/review/",
    #     TextTestimonyApprovalView.as_view(),
    #     name="text-testimony-review",
    # ),
    path(
        "testimonies/settings/",
        TestimonySettingsView.as_view(),
        name="testimony-settings",
    ),
    # path(
    #     "testimonies/<str:category>/",
    #     TextTestimonyByCategoryView.as_view(),
    #     name="testimony-by-category",
    # ),
    #  path(
    #      "testimonies/comment/<id>/",
    #      TextTestimonyCommentsView.as_view(),
    #      name="testimony-by-category-comment",
    # ),
    # path(
    #     "testimonies/video/<str:category>/",
    #     VideoTestimonyByCategoryView.as_view(),
    #     name="testimony-by-category",
    # ),
    path(
        "testimonies/reply-video-comment/<id>/",
        VideoTestimonyReplyComment.as_view(),
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

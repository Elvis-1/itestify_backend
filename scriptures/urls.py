from django.urls import path
from .views import (CreateAndGetScriptures, UserCommentOnScripture,
                    UserLikeAndUnlikeScripture, GetOrCreateIntervalScheduleInstance, FilterScripture, GetScheduleScripture, SearchForScripures)

urlpatterns = [
    path('create-or-get-scripture/', CreateAndGetScriptures.as_view()),
    path('get-scripture-byId/<id>/', CreateAndGetScriptures.as_view()),
    path('edit-scripture/<id>/', CreateAndGetScriptures.as_view()),
    path('delete-scripture/<id>/', CreateAndGetScriptures.as_view()),



    path('user-comment-scripture/<id>/', UserCommentOnScripture.as_view()),
    path('user-like-and-unlike-scripture/<id>/',
         UserLikeAndUnlikeScripture.as_view()),
    path('get-schedule-scripture/<id>/', GetScheduleScripture.as_view(),
         ),
    path('search-scriptures/', SearchForScripures.as_view(),
         ),
    path('filter-scriptures/', FilterScripture.as_view(),
         ),
    path('get-or-create-schedule/', GetOrCreateIntervalScheduleInstance.as_view(),
         ),

]

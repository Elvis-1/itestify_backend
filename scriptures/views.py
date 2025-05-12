import json
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from support.helpers import StandardResultsSetPagination
from .models import ScriptureComment, Scriptures
from .serializers import IntervalScheduleSerializer, ScriptureCommentSerializer, ScripturesSerializer
from user.models import User
from rest_framework import status
from django.db.models import Q
from testimonies.models import UPLOAD_STATUS

from django_celery_beat.models import PeriodicTask, IntervalSchedule


# Create your views here.

# --------------------------START ADMIN---------------------------------

# CREATE AND GET SCRIPTURE API
class CreateAndGetScriptures(APIView):
    permission_classes = (IsAuthenticated, )
    pagination_class = StandardResultsSetPagination

    # Create Scripture Api By Upload now or Schedule for the future or Draft
    def post(self, request):
        payload = {}
        upload_now = request.data.get("upload_now")
        schedule_later = request.data.get("schedule_later")
        schedule_date = request.data.get("schedule_date")
        draft = request.data.get("draft")
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:

                if upload_now:
                    serializer = ScripturesSerializer(
                        data=request.data or None)
                    if serializer.is_valid():
                        serializer.save()
                        scripture_id = serializer.data["pk"]
                        get_scripture = Scriptures.objects.get(id=scripture_id)
                        get_scripture.uploaded_by = get_user
                        get_scripture.status = UPLOAD_STATUS.UPLOAD_NOW.value
                        get_scripture.save()
                        payload["msg"] = "Scripture Created And Uploaded Successfully"
                        return Response(payload, status=status.HTTP_201_CREATED)

                elif schedule_later and schedule_date:
                    serializer = ScripturesSerializer(
                        data=request.data or None)
                    if serializer.is_valid():
                        serializer.validated_data["schedule_date"] = schedule_date
                        serializer.save()
                        scripture_id = serializer.data["pk"]
                        get_scripture = Scriptures.objects.get(id=scripture_id)
                        get_scripture.uploaded_by = get_user
                        get_scripture.status = UPLOAD_STATUS.SCHEDULE_LATER.value
                        # get_scripture.schedule_date = schedule_date
                        get_scripture.save()
                        payload["msg"] = "Scripture Created And Scheduled Successfully"
                        return Response(payload, status=status.HTTP_201_CREATED)

                elif draft:
                    serializer = ScripturesSerializer(
                        data=request.data or None)
                    if serializer.is_valid():
                        serializer.save()
                        scripture_id = serializer.data["pk"]
                        get_scripture = Scriptures.objects.get(id=scripture_id)
                        get_scripture.uploaded_by = get_user
                        get_scripture.status = UPLOAD_STATUS.DRAFT.value
                        get_scripture.save()
                        payload["msg"] = "Scripture Created And Drafted Successfully"
                        return Response(payload, status=status.HTTP_201_CREATED)

                else:
                    payload["msg"] = "Nofhing to upload"
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload["msg"] = "User Not Authorised"
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            payload["msg"] = "User Not Authorised"
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

    # Get Scripture Api (Get all scriptures or get one scripture by ID)
    def get(self, request, id=None):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            # Get by ID
            if get_user.role == role or get_user.is_superuser == True:
                if id:
                    scripture_id = Scriptures.objects.get(id=id)
                    print(scripture_id)
                    serializer = ScripturesSerializer(scripture_id, many=False)
                    if serializer:
                        payload = {
                            'msg': serializer.data
                        }
                        return Response(payload, status=status.HTTP_200_OK)
                    else:
                        payload = {
                            'msg': serializer.errors
                        }
                        return Response(payload, status=status.HTTP_404_NOT_FOUND)

                # Get all Scriptures
                else:
                    scripture_list = Scriptures.objects.all()
                    paginator = self.pagination_class()
                    paginated_queryset = paginator.paginate_queryset(
                        scripture_list, request)
                    serializer = ScripturesSerializer(
                        paginated_queryset, many=True)
                    if serializer:
                        return paginator.get_paginated_response(serializer.data)
                    else:
                        payload = {
                            'msg': serializer.errors
                        }
                        return Response(payload, status=status.HTTP_404_NOT_FOUND)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    # Edit a scripture by ID

    def put(self, request, id):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id, role=role)
            # Get by ID
            if get_user.role == role or get_user.is_superuser == True:
                scripture_id = Scriptures.objects.get(id=id)
                serializer = ScripturesSerializer(
                    data=request.data or None, instance=scripture_id)
                if serializer.is_valid():
                    serializer.save()
                    payload['msg'] = "Scripture Edited Successfully"
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    payload["msg"] = serializer.errors
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    # Delete a Scripture by ID

    def delete(self, request, id):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id, role=role)
            # Get by ID
            if get_user.role == role or get_user.is_superuser == True:
                scripture_id = Scriptures.objects.get(id=id)
                if scripture_id:
                    scripture_id.delete()
                    payload['msg'] = "Scripture Deleted Successfully"
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    payload["msg"] = "Error In deleting"
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)


class SearchForScripures(APIView):
    permission_classes = (IsAuthenticated, )
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:
                search_query = request.GET.get("search")
                print(search_query)
                search = Scriptures.objects.filter(Q(bible_text__icontains=search_query) | Q(
                    scripture__icontains=search_query) | Q(bible_version__icontains=search_query) | Q(prayer__icontains=search_query))
                paginator = self.pagination_class()
                paginated_queryset = paginator.paginate_queryset(
                    search, request)
                serializer = ScripturesSerializer(
                    paginated_queryset, many=True)
                if serializer:
                    return paginator.get_paginated_response(serializer.data)
                else:
                    payload["msg"] = serializer.errors
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)


class FilterScripture(APIView):
    permission_classes = (IsAuthenticated,)
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:
                scripture = Scriptures.objects.all()
                status_text = request.data.get("status")

                # schedule_later = request.data.get("schedule_later")
                # draft = request.data.get("draft")
                start_date = request.data.get("start_date")
                end_date = request.data.get("end_date")
                # print(start_date, end_date)

                if status_text:
                    scripture = scripture.filter(status=status_text)
                elif start_date:
                    scripture = scripture.filter(
                        created_at__gte=start_date)
                elif end_date:
                    scripture = scripture.filter(
                        created_at__lte=end_date)
                elif start_date and end_date:
                    scripture = scripture.filter(
                        created_at__range=[start_date, end_date])

                paginator = self.pagination_class()
                paginated_queryset = paginator.paginate_queryset(
                    scripture, request)
                serializer = ScripturesSerializer(
                    paginated_queryset, many=True)
                if serializer:
                    return paginator.get_paginated_response(serializer.data)
                else:
                    payload["msg"] = "No Data Found"
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)


class GetOrCreateIntervalScheduleInstance(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:
                serializer = IntervalScheduleSerializer(
                    data=request.data or None)
                if serializer.is_valid():
                    serializer.save()
                    payload = {
                        'msg': "Interval Schedule Created Successfully",
                        'data': serializer.data
                    }
                    return Response(payload, status=status.HTTP_201_CREATED)
                else:
                    payload = {
                        'msg': serializer.errors
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    def get(self, request):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:
                schedule = IntervalSchedule.objects.all()
                serializer = IntervalScheduleSerializer(
                    schedule, many=True)
                if serializer:
                    payload = {
                        'msg': serializer.data
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    payload = {"msg": "No Data Found"}
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, id):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:
                schedule = IntervalSchedule.objects.get(id=id)
                serializer = IntervalScheduleSerializer(
                    data=request.data or None, instance=schedule)
                if serializer.is_valid():
                    serializer.save()
                    payload = {
                        'msg': "Interval Schedule Edited Successfully",
                        'data': serializer.data
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    payload = {
                        'msg': serializer.errors
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, id):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.ADMIN.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser == True:
                schedule = IntervalSchedule.objects.get(id=id)
                if schedule:
                    schedule.delete()
                    payload = {
                        'msg': "Interval Schedule Deleted Successfully"
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    payload = {
                        'msg': "Error In Deleting"
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)


class GetScheduleScripture(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request, id):
        user_id = request.user.id
        role = User.Roles.ADMIN.value
        get_user = User.objects.get(id=user_id, role=role)
        if get_user.role == role or get_user.is_superuser == True:
            data = []
            payload = {}
            testimonyList = Scriptures.objects.all()
            serializer = ScripturesSerializer(testimonyList, many=True)
            schedule_id = IntervalSchedule.objects.get(pk=id)
            task = PeriodicTask.objects.filter(interval=schedule_id)
            for i in task:
                i.delete()
            if len(task) > 0:
                task = task.first()
                args = json.loads(task.args)
                args = args[0]

                if len(serializer.data) > 0:
                    for i in serializer.data:
                        if i["pk"] not in args:
                            args.append(i["pk"])
                    task.args = json.dumps([args])
                    task.save()
                    payload = {
                        'msg': 'Scriptures gotten'
                    }
                    return Response(payload, status=status.HTTP_200_OK)
            else:
                if len(serializer.data) > 0:
                    for i in serializer.data:
                        data.append(i["pk"])

                task = PeriodicTask.objects.get_or_create(
                    interval=schedule_id, name=f'every-{schedule_id.every}-{schedule_id.period}', task="scriptures.tasks.get_scripture_periodically", args=json.dumps([data]))
                payload = {
                    'msg': 'Scriptures gotten'
                }
                return Response(payload, status=status.HTTP_200_OK)
        else:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)


# ---------------------------------END ADMIN---------------------------------------------


# USER COMMENT ON SCRIPTURE API FOR MOBILE
class UserCommentOnScripture(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request, id):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.VIEWER.value
            get_user = User.objects.get(id=user_id)
            if get_user.role == role or get_user.is_superuser:
                scripture_id = Scriptures.objects.get(id=id)
                serializer = ScriptureCommentSerializer(
                    data=request.data or None)
                if serializer.is_valid():
                    serializer.save()
                    get_comment_id = serializer.data["pk"]
                    print(get_comment_id)
                    comment = ScriptureComment.objects.get(id=get_comment_id)
                    comment.scripture = scripture_id
                    comment.commented_by = get_user
                    comment.save()
                    payload = {
                        "msg": serializer.data
                    }
                    return Response(payload, status=status.HTTP_201_CREATED)
                else:
                    payload = {
                        "msg": serializer.errors
                    }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    # def get()


# USER LIKE SCRIPTURE API FOR MOBILE
class UserLikeAndUnlikeScripture(APIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request, id):
        payload = {}
        user_id = request.user.id
        try:
            role = User.Roles.VIEWER.value
            get_user = User.objects.get(id=user_id, role=role)
            if get_user.role == role or get_user.is_superuser == True:
                scripture_id = Scriptures.objects.get(id=id)
                if scripture_id.like_scripture.filter(id=user_id.id).exists():
                    scripture_id.like_scripture.remove(user_id)
                    serializer = ScripturesSerializer(
                        instance=scripture_id)
                    payload['msg'] = serializer.data
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    scripture_id.like_scripture.add(user_id)
                    serializer = ScripturesSerializer(
                        instance=scripture_id)
                    payload['msg'] = serializer.data
                    return Response(payload, status=status.HTTP_200_OK)
            else:
                payload = {
                    'msg': "User is not Authorised"
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            payload = {
                'msg': "User is not Authorised"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

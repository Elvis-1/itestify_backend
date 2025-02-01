from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from .models import TextTestimony
from .serializers import TextTestimonySerializer

class TextTestimonyListView(APIView):
    """Fetch all testimonies with filtering and search."""

    def get(self, request):
        testimonies = TextTestimony.objects.all()
        # Filters
        category = request.query_params.get('category')
        status_filter = request.query_params.get('status')
        search = request.query_params.get('search')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        if category:
            testimonies = testimonies.filter(category=category)
        if status_filter:
            testimonies = testimonies.filter(status=status_filter)
        if search:
            testimonies = testimonies.filter(name__icontains=search)
        if start_date and end_date:
            testimonies = testimonies.filter(date_submitted__range=[start_date, end_date])

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10
        paginated_testimonies = paginator.paginate_queryset(testimonies, request)

        # Serialize and return
        serializer = TextTestimonySerializer(paginated_testimonies, many=True)
        return paginator.get_paginated_response(serializer.data)


class TextTestimonyApprovalView(APIView):
    """Approve or reject testimonies."""

    def post(self, request, pk):
        try:
            testimony = TextTestimony.objects.get(pk=pk)
        except TextTestimony.DoesNotExist:
            return Response({"error": "Testimony not found"}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')  # 'approve' or 'reject'
        rejection_reason = request.data.get('rejection_reason', '')

        if action == 'approve':
            testimony.status = 'Approved'
            testimony.rejection_reason = ''
        elif action == 'reject':
            testimony.status = 'Rejected'
            testimony.rejection_reason = rejection_reason
        else:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        testimony.save()
        return Response({"message": "Testimony updated successfully"})


class TestimonySettingsView(APIView):
    """Manage global settings."""

    def get(self, request):
        settings = {
            "likes_enabled": True,
            "comments_enabled": True,
            "shares_enabled": True
        }
        return Response(settings)

    def post(self, request):
        # Update settings logic here
        return Response({"message": "Settings updated successfully"})
    


class TestimonyViewSet(viewsets.ViewSet):
    
    permission_classes = [permissions.IsAuthenticated]
    
    pass
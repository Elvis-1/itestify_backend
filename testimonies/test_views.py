# views.py
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

class VideoTestimonyViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["post"])
    def create_video(self, request):
        video_testimonies = request.data.getlist("video_testimonies") if isinstance(request.data, QueryDict) else request.data.get("video_testimonies", [])

        if not video_testimonies:
            return Response({"detail": "No video testimonies provided."}, status=status.HTTP_400_BAD_REQUEST)

        total_response_data = []

        for i, video_data in enumerate(video_testimonies):
            # Build keys for files
            prefix = f"video_testimonies[{i}]"
            video_data["video_file"] = request.FILES.get(f"{prefix}[video_file]")
            video_data["thumbnail"] = request.FILES.get(f"{prefix}[thumbnail]")

            serializer = VideoTestimonySerializer(
                data=video_data,
                context={"request": request}
            )

            serializer.is_valid(raise_exception=True)
            testimony = serializer.save()

            return_serializer = ReturnVideoTestimonySerializer(
                testimony, context={"request": request}
            )
            total_response_data.append(return_serializer.data)

        return Response(
            {"message": "Success.", "data": total_response_data},
            status=status.HTTP_201_CREATED
        )

from rest_framework import serializers
from .models import ScriptureComment, Scriptures


# SCRIPTURES COMMENT SERIALIZER
class ScriptureCommentSerializer(serializers.ModelSerializer):
    commented_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = ScriptureComment
        fields = ['pk', 'commented_by', 'comment']

# SCRIPTURE SERIALIZER WHICH INCLUDE FIELDS TO DISPLAY LIST OF PEOPLE THAT COMMENTED


class ScripturesSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.StringRelatedField(read_only=True)
    comment = ScriptureCommentSerializer(many=True, read_only=True)

    class Meta:
        model = Scriptures
        fields = ['pk', 'comment', 'uploaded_by', 'bible_text', 'scripture',
                  'bible_version', 'prayer', 'status', 'schedule_date', 'like_scripture', 'created_at', "updated_at"]

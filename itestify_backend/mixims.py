import uuid
from django.db import models


class TouchDatesMixim(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField("Date Created", auto_now_add=True, null=True)
    updated_at = models.DateTimeField("Date Updated", auto_now=True, null=True)

    # class Meta(auto_prefetch.Model.Meta):
    #     abstract = True
    class Meta:
        """meta class"""

        abstract = True
import uuid
from django.db import models


class GetOrNoneQuerySet(models.QuerySet):
    """Custom Queryset that supports get_or_none()"""

    def get_or_none(self, **kwargs):
        try:
            return self.get(**kwargs)
        except self.model.DoesNotExist:
            return None
        
        
class GetOrNoneManager(models.Manager):
    """Adds get_or_none method to objects"""

    def get_queryset(self):
        return GetOrNoneQuerySet(self.model, using=self._db)
    
    def get_or_none(self,**kwargs):
        return self.get_queryset().get_or_none(**kwargs)


class TouchDatesMixim(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField("Date Created", auto_now_add=True, null=True)
    updated_at = models.DateTimeField("Date Updated", auto_now=True, null=True)

    # class Meta(auto_prefetch.Model.Meta):
    #     abstract = True
    
    objects = GetOrNoneManager()
    
    class Meta:
        """meta class"""

        abstract = True
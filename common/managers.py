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
    
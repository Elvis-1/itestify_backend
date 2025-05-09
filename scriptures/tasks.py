from datetime import datetime
import math
import uuid
from channels.layers import get_channel_layer
import json
from celery import shared_task
from django.core.cache import cache
from asgiref.sync import async_to_sync
from scriptures.models import Scriptures
from testimonies.models import UPLOAD_STATUS
from celery.exceptions import Ignore
from django.db.models.fields.related import ForeignKey, OneToOneField, ManyToManyField



def clean_and_serialize(obj):
    """
    Converts a Django model instance to a serializable dict.
    Handles datetime, floats (NaN, inf), UUIDs, FK, M2M, etc.
    """
    def clean_value(v):
        if isinstance(v, float):
            return None if math.isnan(v) or math.isinf(v) else v
        elif isinstance(v, datetime):
            return v.isoformat()
        elif isinstance(v, uuid.UUID):
            return str(v)
        elif hasattr(v, '__dict__'):  # fallback for unexpected objects
            return str(v)
        elif isinstance(v, dict):
            return {k: clean_value(val) for k, val in v.items()}
        elif isinstance(v, list):
            return [clean_value(i) for i in v]
        return v

    data = {}

    # Handle standard fields and FK/OneToOne
    for field in obj._meta.fields:
        try:
            value = getattr(obj, field.name)
            if isinstance(field, (ForeignKey, OneToOneField)):
                data[field.name] = str(value.id) if value else None
            else:
                data[field.name] = clean_value(value)
        except Exception as e:
            data[field.name] = f"Error: {str(e)}"

    # Handle ManyToMany fields (manually)
    for field in obj._meta.many_to_many:
        try:
            value = getattr(obj, field.name)
            data[field.name] = [str(v.id) for v in value.all()] if value else []
        except Exception as e:
            data[field.name] = f"Error: {str(e)}"

    return data


# TASK TO SCHEDULE INDIVIDUAL SCRIPTURE PERIODICALLY EVERY 24HRS
@shared_task(bind=True)
def get_scripture_periodically(self, scripture_data):
    index = cache.get("scripture_index", 0)

    if index >= len(scripture_data):
        index = 0  # reset to start

    try:
        nid = scripture_data[index]
        test_obj = Scriptures.objects.get(id=nid)
        serialized = clean_and_serialize(test_obj)
    except Exception as e:
        serialized = {nid: {'error': str(e)}}

    # Send to channel
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)("scripture_room_name", {
        'type': 'get_schedule_scripture',
        'scripture_data': {str(nid): serialized},
    })

    # Update the cache index
    cache.set("scripture_index", index + 1)

    return "done"


# TASK TO SCHEDULE A SCRIPTURE
@shared_task(bind=True)
def schedule_scripture(self, data):
    try:
        get_scripture = Scriptures.objects.get(id=data)
        if get_scripture:
            get_scripture.status = UPLOAD_STATUS.UPLOAD_NOW.value
            get_scripture.save()
            return "Done"
        else:
            self.update_state(state='FAILURE', meta={'exe': 'Not Found'})
            raise Ignore()
    except:
        self.update_state(state='FAILURE', meta={'exe': 'Not Found'})
        raise Ignore()

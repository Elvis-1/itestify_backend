from channels.generic.websocket import AsyncJsonWebsocketConsumer
import redis.asyncio as aioredis
from django.conf import settings
from django.core.cache import cache

REDIS_PREFIX = "user_channel"
admin_user = None



class NotificationUserConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        global admin_user
        user = self.scope['user']
        if user.is_authenticated:
            self.user_id = str(user.id)
            admin_user = self.user_id
            await self.accept()
            self.channel = aioredis.from_url(settings.REDIS_URL)
            await self.channel.set(f"{REDIS_PREFIX}:{self.user_id}", self.channel_name)
            cache.set("admin_user", self.user_id)
            
        else:
            await self.close()

    async def disconnect(self, close_code):
        if hasattr(self, 'user_id'):
            await self.channel.delete(f"{REDIS_PREFIX}:{self.user_id}")
            cache.delete("admin_user")
            await self.channel.close()

    # Notification Response for User Like Text Testimony
    async def get_user_unread_notification(self, message):
        await self.send_json({
            'message': message
        })

    async def get_user_unread_notification_count(self, count):
        await self.send_json({
            'count': count
        })



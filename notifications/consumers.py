from channels.generic.websocket import AsyncJsonWebsocketConsumer
import redis.asyncio as aioredis
from django.conf import settings

REDIS_PREFIX = "user_channel"


class NotificationConsumer(AsyncJsonWebsocketConsumer):

    async def connect(self):
        user = self.scope['user']
        if user.is_authenticated:
            self.user_id = str(user.id)
            self.channel = aioredis.from_url("redis://:xaJg9XJIDBNFbxUZtz73KFhkOMu4EJHt@redis-13061.crce197.us-east-2-1.ec2.redns.redis-cloud.com:13061")
            print(self.channel)
            await self.channel.set(f"{REDIS_PREFIX}:{self.user_id}", self.channel_name)
            print(
                f"Connected socket for user {self.user_id} to channel: {self.channel_name}")
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, close_code):
        if hasattr(self, 'user_id'):
            await self.channel.delete(f"{REDIS_PREFIX}:{self.user_id}")
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


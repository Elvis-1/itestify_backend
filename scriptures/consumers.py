from channels.generic.websocket import AsyncWebsocketConsumer
import json
#from channels.db import database_sync_to_async

# SCHEDULE OF SCRIPTURE BY REALTIME USING WEBSOCKET
class ScheduleScriptureConsumer(AsyncWebsocketConsumer):
    # Connect to the group name
    async def connect(self):
        self.room_group_name = "scripture_room_name"

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        print("Connected to the group")
        await self.accept()

    # Get schedule via consumer
    async def get_schedule_scripture(self, event):
        await self.send(text_data=json.dumps(event["scripture_data"]))

    async def disconnect(self, close_code):
        # Leave room group
        print("Disconnected from the group")
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        await super().disconnect(close_code)

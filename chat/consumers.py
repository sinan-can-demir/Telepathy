from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from .auth import hash_token
from .models import ChatParticipant


class ChatConsumer(AsyncJsonWebsocketConsumer):
    """Server-push notification channel for one chat. Carries no message
    content -- just a signal ("new_message"/"roster_changed") telling the
    client to immediately re-run its existing HTTP fetch (which already does
    all the actual decrypt/TOFU/chain-verification work), so this consumer
    never needs to duplicate any of that. See docs/ARCHITECTURE.md and
    issue #37: HTTP polling stays as the initial-load/fallback path, this is
    purely additive.

    Auth: browsers can't set custom headers on `new WebSocket(...)`, so the
    bearer token travels via query string (?token=...) instead of the
    Authorization header ParticipantTokenAuthentication expects over HTTP --
    same hash-and-lookup, different transport.
    """

    async def connect(self):
        chat_id = self.scope["url_route"]["kwargs"]["chat_id"]
        query = parse_qs(self.scope["query_string"].decode())
        raw_token = (query.get("token") or [None])[0]

        participant = await self._authenticate(chat_id, raw_token)
        if participant is None:
            await self.close(code=4001)
            return

        self.group_name = f"chat_{chat_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        if getattr(self, "group_name", None):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    @database_sync_to_async
    def _authenticate(self, chat_id, raw_token):
        if not raw_token:
            return None
        try:
            return ChatParticipant.objects.select_related("chat").get(
                auth_token_hash=hash_token(raw_token),
                left_at__isnull=True,
                chat__pin=chat_id,
            )
        except ChatParticipant.DoesNotExist:
            return None

    # Group-sent event; "type": "chat.notify" maps to this method name.
    async def chat_notify(self, event):
        await self.send_json({"type": event["event_type"]})

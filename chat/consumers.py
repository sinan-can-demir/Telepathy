from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from .auth import authenticate_participant


class ChatConsumer(AsyncJsonWebsocketConsumer):
    """Server-push notification channel for one chat. Carries no message
    content -- just a signal ("new_message"/"roster_changed") telling the
    client to immediately re-run its existing HTTP fetch (which already does
    all the actual decrypt/TOFU/chain-verification work), so this consumer
    never needs to duplicate any of that. See docs/ARCHITECTURE.md and
    issue #37: HTTP polling stays as the initial-load/fallback path, this is
    purely additive.

    Auth: browsers can't set custom headers on `new WebSocket(...)`, so the
    bearer token travels as a Sec-WebSocket-Protocol value (the second
    argument to `new WebSocket(url, [token])`) instead of the Authorization
    header ParticipantTokenAuthentication expects over HTTP -- same
    hash-and-lookup, different transport. This deliberately avoids putting
    the token in the URL (see issue #57): a query string ends up in access
    logs, proxy logs, and browser history; a request header field doesn't.
    """

    async def connect(self):
        chat_id = self.scope["url_route"]["kwargs"]["chat_id"]
        raw_token = (self.scope.get("subprotocols") or [None])[0]

        participant = await self._authenticate(chat_id, raw_token)
        if participant is None:
            await self.close(code=4001)
            return

        self.group_name = f"chat_{chat_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        # Echoing the subprotocol back is required by the WebSocket spec for
        # the client to consider one "selected" -- without it some clients
        # treat the handshake as not having agreed on a subprotocol at all.
        await self.accept(subprotocol=raw_token)

    async def disconnect(self, close_code):
        if getattr(self, "group_name", None):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    @database_sync_to_async
    def _authenticate(self, chat_id, raw_token):
        return authenticate_participant(raw_token, chat_id=chat_id)

    # Group-sent event; "type": "chat.notify" maps to this method name.
    async def chat_notify(self, event):
        await self.send_json({"type": event["event_type"]})

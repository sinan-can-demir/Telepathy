from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


def notify_chat(chat_pin, event_type):
    """Pushes a lightweight signal to every websocket connected to this chat
    (see chat/consumers.py) so clients refetch immediately instead of
    waiting for their fallback poll. A no-op if the channel layer isn't
    configured -- callers don't need to guard this themselves."""
    layer = get_channel_layer()
    if layer is not None:
        async_to_sync(layer.group_send)(
            f"chat_{chat_pin}", {"type": "chat.notify", "event_type": event_type}
        )

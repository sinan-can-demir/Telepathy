import hashlib
from datetime import timedelta

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ChatParticipant

# How long a participant can go without a successful authentication before
# they're treated as abandoned and reclaimed. This is the actual fix for "a
# closed tab's token stays valid forever" (issue #71) -- there is no
# reliable way to tell a genuine tab close apart from a page refresh from
# beforeunload/sendBeacon (and this app deliberately supports resuming a
# chat after a refresh, see ensureParticipation in chatbox.html), so acting
# on that event at all risks ending a session the user never meant to end.
# A tab that's actually still open re-authenticates at least every 15s via
# its polling fallback (see fetchNewMessages in chatbox.html), so this
# timeout is effectively "how long a closed tab's session survives," not a
# limit on an active conversation.
IDLE_TIMEOUT = timedelta(minutes=30)


def hash_token(raw_token):
    return hashlib.sha256(raw_token.encode()).hexdigest()


def authenticate_participant(raw_token, chat_pin=None):
    """Shared lookup for both HTTP (ParticipantTokenAuthentication) and
    WebSocket (chat.consumers.ChatConsumer) auth. Returns the matching
    ChatParticipant, or None if the token is invalid/unknown, already
    left, or has been idle past IDLE_TIMEOUT.

    An idle-expired participant is marked left here, lazily, through the
    same services.mark_left an explicit leave uses, so a chat this empties
    is deleted too. The reaper (services.reap_idle_chats) does the same for
    participants who never come back at all (#97).
    """
    if not raw_token:
        return None

    qs = ChatParticipant.objects.select_related("chat").filter(
        auth_token_hash=hash_token(raw_token),
        left_at__isnull=True,
    )
    if chat_pin is not None:
        qs = qs.filter(chat__pin=chat_pin)
    try:
        participant = qs.get()
    except ChatParticipant.DoesNotExist:
        return None

    now = timezone.now()
    if participant.last_seen < now - IDLE_TIMEOUT:
        from .services import mark_left  # services imports this module
        mark_left(participant, now)
        return None

    ChatParticipant.objects.filter(pk=participant.pk).update(last_seen=now)
    return participant


class ParticipantTokenAuthentication(authentication.BaseAuthentication):
    """
    Authenticates a request as a ChatParticipant (not a django.contrib.auth
    User -- there is no persistent, cross-chat account in this app). Expects
    `Authorization: Token <raw token>`, the same header shape the app used
    with DRF's TokenAuthentication before, so the frontend didn't need to
    change how it sends the header -- just what the token means.

    The raw token is never stored; only its SHA-256 hash is compared against
    ChatParticipant.auth_token_hash. A token stops authenticating the moment
    its participant leaves (left_at is set) or goes idle past IDLE_TIMEOUT,
    which are the two points a chat-scoped identity should stop being usable.
    """

    keyword = "Token"

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).split()
        if not auth_header or auth_header[0].decode().lower() != self.keyword.lower():
            return None
        if len(auth_header) != 2:
            raise exceptions.AuthenticationFailed("Invalid token header.")

        participant = authenticate_participant(auth_header[1].decode())
        if participant is None:
            raise exceptions.AuthenticationFailed("Invalid or expired token.")

        return (participant, None)

    def authenticate_header(self, request):
        # Without this, DRF has no authenticator willing to "challenge" the
        # request, so it falls back to 403 for missing/invalid credentials
        # instead of the correct 401.
        return self.keyword

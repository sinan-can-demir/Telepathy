import hashlib

from rest_framework import authentication, exceptions

from .models import ChatParticipant


def hash_token(raw_token):
    return hashlib.sha256(raw_token.encode()).hexdigest()


class ParticipantTokenAuthentication(authentication.BaseAuthentication):
    """
    Authenticates a request as a ChatParticipant (not a django.contrib.auth
    User -- there is no persistent, cross-chat account in this app). Expects
    `Authorization: Token <raw token>`, the same header shape the app used
    with DRF's TokenAuthentication before, so the frontend didn't need to
    change how it sends the header -- just what the token means.

    The raw token is never stored; only its SHA-256 hash is compared against
    ChatParticipant.auth_token_hash. A token stops authenticating the moment
    its participant leaves (left_at is set), which is the natural point a
    chat-scoped identity should stop being usable.
    """

    keyword = "Token"

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).split()
        if not auth_header or auth_header[0].decode().lower() != self.keyword.lower():
            return None
        if len(auth_header) != 2:
            raise exceptions.AuthenticationFailed("Invalid token header.")

        raw_token = auth_header[1].decode()
        try:
            participant = ChatParticipant.objects.select_related("chat").get(
                auth_token_hash=hash_token(raw_token),
                left_at__isnull=True,
            )
        except ChatParticipant.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid or expired token.")

        return (participant, None)

    def authenticate_header(self, request):
        # Without this, DRF has no authenticator willing to "challenge" the
        # request, so it falls back to 403 for missing/invalid credentials
        # instead of the correct 401.
        return self.keyword

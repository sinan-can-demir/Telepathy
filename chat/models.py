from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import uuid
from django.conf import settings


class User(AbstractUser):
    """Exists solely so Django's own admin/staff login keeps working. No
    end-user chat functionality authenticates against this model anymore --
    see ChatParticipant, which is a free-standing, per-chat identity with its
    own keys and bearer token, precisely so one person's participation in
    different chats can never be correlated through a shared account row."""
    pass


class Chat(models.Model):
    # A Chat row's existence *is* its "active" flag now (see #35):
    # LeaveChatView hard-deletes the row once every participant has left,
    # which is what actually frees the PIN for reuse -- a soft is_active=False
    # flag would leave the PIN permanently retired against the unique
    # constraint below, and there are only 10,000 possible 4-digit PINs.
    pin = models.CharField(max_length=4, unique=True, db_index=True)
    is_group = models.BooleanField(default=False)
    max_participants = models.IntegerField(default=2)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Chat {self.pin}"


class ChatParticipant(models.Model):
    """A participant's entire identity for exactly one chat: a self-chosen
    display name, this-chat-only encryption/signing keys, and a hashed
    bearer token issued at creation/join time. Nothing here links back to
    any other chat the same person may have joined."""
    # DRF's IsAuthenticated permission checks request.user.is_authenticated;
    # that attribute only exists on django.contrib.auth's User/AnonymousUser
    # by convention, not on plain models, so it's shimmed here as a constant.
    is_authenticated = True

    chat = models.ForeignKey(Chat, related_name="participants", on_delete=models.CASCADE)
    display_name = models.CharField(max_length=32)
    public_key = models.TextField()
    signing_public_key = models.TextField(null=True, blank=True)
    # SHA-256 hex digest of the bearer token; the raw token is returned to the
    # client exactly once (at creation/join time) and never stored or logged.
    auth_token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    joined_at = models.DateTimeField(auto_now_add=True)
    left_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.display_name} in {self.chat}"


class Message(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    chat = models.ForeignKey(
        Chat,
        related_name="messages",
        on_delete=models.CASCADE,
        db_index=True,
    )
    sender = models.ForeignKey(
        ChatParticipant,
        on_delete=models.CASCADE,
        related_name="sent_messages",
        db_index=True,
    )
    encrypted_text = models.TextField()
    aes_nonce = models.TextField(null=True, blank=True)
    aes_tag = models.TextField(null=True, blank=True)
    signature = models.TextField(null=True, blank=True)

    # Transcript tamper-evidence: seq is assigned atomically per chat
    # (SendMessageView, under a row lock) so gaps/duplicates are impossible
    # at the DB level, and prev_hash is the client's claim about the hash of
    # the message immediately before this one (see chat/chain.py). Neither
    # field is trusted on its own -- it's the client-side verification walk
    # in chatbox.html, recomputing the chain from what's stored, that
    # actually catches a dropped/reordered/replayed message.
    seq = models.PositiveIntegerField(default=0)
    prev_hash = models.CharField(max_length=64, default="0" * 64)

    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        indexes = [
            models.Index(
                fields=['chat', '-timestamp'],
                name='msg_chat_time_idx'
            ),
        ]
        unique_together = [("chat", "seq")]

    def __str__(self):
        return f"From {self.sender} at {self.timestamp}"


class MessageKey(models.Model):
    message = models.ForeignKey(Message, related_name="wrapped_keys", on_delete=models.CASCADE)
    recipient = models.ForeignKey(
        ChatParticipant,
        related_name="message_keys",
        on_delete=models.CASCADE,
    )
    encrypted_symmetric_key = models.TextField()

    class Meta:
        unique_together = [("message", "recipient")]

    def __str__(self):
        return f"Key for {self.recipient} on {self.message_id}"

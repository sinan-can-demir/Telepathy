from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import uuid
from django.conf import settings


class User(AbstractUser):
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)
    public_key = models.TextField(null=True, blank=True)
    signing_public_key = models.TextField(null=True, blank=True)


class Chat(models.Model):
    pin = models.CharField(max_length=4, unique=True, db_index=True)
    is_group = models.BooleanField(default=False)
    max_participants = models.IntegerField(default=2)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Chat {self.pin}"


class ChatParticipant(models.Model):
    chat = models.ForeignKey(Chat, related_name="participants", on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="chat_memberships",
        on_delete=models.CASCADE,
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    left_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("chat", "user")]

    def __str__(self):
        return f"{self.user} in {self.chat}"


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
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sent_messages",
        db_index=True,
    )
    encrypted_text = models.TextField()
    aes_nonce = models.TextField(null=True, blank=True)
    aes_tag = models.TextField(null=True, blank=True)
    signature = models.TextField(null=True, blank=True)

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

    def __str__(self):
        return f"From {self.sender} at {self.timestamp}"


class MessageKey(models.Model):
    message = models.ForeignKey(Message, related_name="wrapped_keys", on_delete=models.CASCADE)
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="message_keys",
        on_delete=models.CASCADE,
    )
    encrypted_symmetric_key = models.TextField()

    class Meta:
        unique_together = [("message", "recipient")]

    def __str__(self):
        return f"Key for {self.recipient} on {self.message_id}"

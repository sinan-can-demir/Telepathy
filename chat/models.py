from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid


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
    display name, a this-chat-only encryption key, and a hashed bearer token
    issued at creation/join time. Nothing here links back to any other chat
    the same person may have joined.

    No signing key: per-message authentication is a MAC derived from the
    forward-secrecy ratchet (see ChainKey, docs/FORWARD_SECRECY.md), not an
    RSA-PSS signature -- deliberately deniable rather than provable to a
    third party. See docs/DENIABLE_AUTH.md (issue #61)."""
    # DRF's IsAuthenticated permission checks request.user.is_authenticated;
    # that attribute only exists on django.contrib.auth's User/AnonymousUser
    # by convention, not on plain models, so it's shimmed here as a constant.
    is_authenticated = True

    chat = models.ForeignKey(Chat, related_name="participants", on_delete=models.CASCADE)
    display_name = models.CharField(max_length=32)
    public_key = models.TextField()
    # SHA-256 hex digest of the bearer token; the raw token is returned to the
    # client exactly once (at creation/join time) and never stored or logged.
    auth_token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    joined_at = models.DateTimeField(auto_now_add=True)
    left_at = models.DateTimeField(null=True, blank=True)
    # Touched on every successful authentication (see auth.authenticate_participant).
    # A tab that's actually closed stops re-authenticating entirely -- no
    # beforeunload/sendBeacon hook can reliably tell a real close apart from
    # a page refresh (which this app deliberately supports resuming from,
    # see ensureParticipation in chatbox.html), so idle time is what lets a
    # closed tab's token/key material eventually get reclaimed instead of
    # staying valid forever. See issue #71.
    last_seen = models.DateTimeField(default=timezone.now)

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
    # Nullable so a tombstoned (expired, see ttl_seconds below) message can
    # have its actual content wiped while the row itself survives, keeping
    # the chain intact -- see tombstone_hash.
    encrypted_text = models.TextField(null=True, blank=True)
    aes_nonce = models.TextField(null=True, blank=True)
    aes_tag = models.TextField(null=True, blank=True)
    # HMAC-SHA256 tag (Base64) over seq|prev_hash|chat_id|plaintext, keyed by
    # a value derived from the sender's own ratchet -- verifiable by anyone
    # who independently derives that same chain (i.e. the chat's other
    # participants), but not provable to a third party the way an RSA-PSS
    # signature would be. See docs/DENIABLE_AUTH.md (issue #61).
    mac = models.TextField(null=True, blank=True)

    # Per-message disappearing-messages TTL (issue #64), in seconds from
    # when a given reader first reads this message -- null means "never
    # expires". "Read" is tracked per participant in MessageReadReceipt
    # below; see services.sweep_expired_messages for when a message
    # actually gets wiped. Deliberately per-message (Signal-style), not
    # per-chat -- see docs/MESSAGE_EXPIRY.md for why that's a materially
    # bigger design than it sounds, and how it interacts with the
    # transcript tamper-evidence chain below.
    ttl_seconds = models.PositiveIntegerField(null=True, blank=True)

    # Set exactly once, the moment this message becomes eligible for
    # content wipe (services.sweep_expired_messages) -- compute_chain_hash's
    # result for this message AT THAT MOMENT, preserved so every later
    # message's prev_hash (computed against this message before it was
    # wiped) stays verifiable forever after. Without this, wiping
    # encrypted_text/aes_nonce/aes_tag/mac below would change what
    # compute_chain_hash(this message) returns, breaking the chain for
    # every message that came after it -- a false tamper signal caused by
    # expiry working as designed, not an attack. See docs/MESSAGE_EXPIRY.md.
    tombstone_hash = models.CharField(max_length=64, null=True, blank=True)
    tombstoned_at = models.DateTimeField(null=True, blank=True)

    # Transcript tamper-evidence: seq is assigned atomically per chat
    # (SendMessageView, under a row lock) so gaps/duplicates are impossible
    # at the DB level, and prev_hash is the client's claim about the hash of
    # the message immediately before this one (see chat/chain.py). Neither
    # field is trusted on its own -- it's the client-side verification walk
    # in chatbox.html, recomputing the chain from what's stored, that
    # actually catches a dropped/reordered/replayed message.
    seq = models.PositiveIntegerField(default=0)
    prev_hash = models.CharField(max_length=64, default="0" * 64)

    # Forward secrecy: which epoch of the SENDER's own sending chain (see
    # ChainKey) this message's AES key was ratcheted from. Recipients other
    # than the sender derive the key locally by advancing their cached copy
    # of that chain rather than unwrapping a per-message key -- see
    # docs/FORWARD_SECRECY.md.
    sender_chain_epoch = models.PositiveIntegerField(default=0)
    # This message's position within that epoch's chain (0 = the epoch's
    # first message). A receiver advances its copy of the sender's ratchet
    # to exactly this index before deriving the key, so a message that never
    # arrived (dropped, or aged out of the relay -- see issue #90 /
    # docs/EPHEMERAL_RELAY.md) costs only itself: later messages still
    # decrypt, instead of every subsequent key being off by one forever.
    # Not separately MAC'd: it selects which ratchet key decrypts the message,
    # so a lie about it just fails AES-GCM decryption.
    chain_index = models.PositiveIntegerField(default=0)

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


class MessageReadReceipt(models.Model):
    """Records that `participant` has fetched (and so, in this app's only
    available signal -- the server never sees plaintext or a client-side
    decrypt-success confirmation -- is treated as having read) `message`.
    Exists purely to drive disappearing-messages expiry (issue #64):
    `read_at + message.ttl_seconds` is when this specific participant's own
    reading window on this message ends. See services.mark_messages_read
    and services.sweep_expired_messages. Deleted once its message is
    tombstoned -- a read receipt for content that no longer exists has no
    further purpose."""
    message = models.ForeignKey(Message, related_name="read_receipts", on_delete=models.CASCADE)
    participant = models.ForeignKey(ChatParticipant, related_name="message_reads", on_delete=models.CASCADE)
    read_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("message", "participant")]

    def __str__(self):
        return f"{self.participant} read {self.message_id} at {self.read_at}"


class MessageKey(models.Model):
    """As of forward secrecy (Phase 2), only ever holds the SENDER's own
    self-wrapped copy of a message's AES key (so they can always redisplay
    their own sent history) -- other participants derive the key locally
    from their cached copy of the sender's chain instead of unwrapping a
    per-message key. See docs/FORWARD_SECRECY.md."""
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


class ChainKey(models.Model):
    """One epoch of a participant's own sending-chain seed. A participant
    issues a new epoch (fanned out, wrapped per current other participant)
    before their first send in a chat, and again any time the roster has
    changed since they last issued one -- re-keying on membership change
    bounds a leaver's/new-joiner's exposure to messages sent under an epoch
    they were actually part of. See docs/FORWARD_SECRECY.md."""
    chat = models.ForeignKey(Chat, related_name="chain_keys", on_delete=models.CASCADE)
    sender = models.ForeignKey(ChatParticipant, related_name="issued_chain_keys", on_delete=models.CASCADE)
    epoch = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("sender", "epoch")]

    def __str__(self):
        return f"{self.sender}'s chain epoch {self.epoch}"


class ChainKeyWrap(models.Model):
    """The chain seed for one ChainKey epoch, RSA-OAEP-wrapped for one
    recipient. Only the sender ever generates the raw seed; the server only
    ever sees/stores it encrypted."""
    chain_key = models.ForeignKey(ChainKey, related_name="wraps", on_delete=models.CASCADE)
    recipient = models.ForeignKey(ChatParticipant, related_name="chain_key_wraps", on_delete=models.CASCADE)
    encrypted_seed = models.TextField()

    class Meta:
        unique_together = [("chain_key", "recipient")]

    def __str__(self):
        return f"Seed for {self.recipient} on {self.chain_key}"

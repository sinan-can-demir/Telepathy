"""Domain logic for chat creation/join/leave, the forward-secrecy chain-key
protocol, and message visibility -- kept independent of DRF's request/
response cycle. See ARCHITECTURE.md #6 / issue #39: this used to live
directly inside APIView.post/get methods, mixing HTTP status-code decisions
with the actual chat rules, so testing pairing/leave/visibility logic meant
going through a full APIClient HTTP round trip every time.

Every function here takes and returns plain Python/model values and raises
one of the exceptions below for a domain-rule violation -- never a DRF
Response. chat/views.py is the only place that knows about HTTP status
codes; it catches these and maps them. That split is what lets these rules
be unit-tested directly against the test database in milliseconds, with no
request/response plumbing involved.
"""

import re
import secrets
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db import IntegrityError, transaction
from django.db.models import Max
from django.utils import timezone

from .auth import hash_token
from .chain import GENESIS_HASH, compute_chain_hash
from .models import Chat, ChainKey, ChainKeyWrap, ChatParticipant, Message, MessageKey, MessageReadReceipt


class ChatServiceError(Exception):
    """Base class for every domain-rule violation this module raises."""


class ChatNotFound(ChatServiceError):
    pass


class ChatFull(ChatServiceError):
    pass


class NotAParticipant(ChatServiceError):
    """The caller isn't an active participant of the chat they're acting on."""


class UnknownChainEpoch(ChatServiceError):
    """Caller has never issued a chain key in this chat."""


class StaleChainEpoch(ChatServiceError):
    """sender_chain_epoch names an epoch that isn't the sender's current one."""


class StaleTranscript(ChatServiceError):
    """prev_hash doesn't match the chat's actual current tip."""

    def __init__(self, expected_prev_hash):
        super().__init__("prev_hash does not match the chat's current tip")
        self.expected_prev_hash = expected_prev_hash


class MissingSelfWrap(ChatServiceError):
    """wrapped_keys didn't include the sender's own self-wrapped copy."""


class RosterMismatch(ChatServiceError):
    """A chain-key issuance's wraps don't cover exactly the current roster."""


class NoFreePin(ChatServiceError):
    """Every one of the PIN_SPACE PINs is held by a live chat."""


class InvalidTTL(ChatServiceError):
    """A submitted ttl_seconds is out of the allowed range."""


# ── Validation ────────────────────────────────────────────────────────────

def is_valid_display_name(name):
    return bool(name) and re.match(r'^[a-zA-Z0-9_ -]{1,32}$', name) is not None


# A 2048-bit RSA SPKI PEM is well under 1KB; capping length before ever
# parsing it keeps a hostile/malformed value from being an amplification
# vector (see issue #72) and gives load_pem_public_key a bounded input.
_MAX_PUBLIC_KEY_PEM_LEN = 2000


# Disappearing-messages TTL bounds (issue #64). Floor keeps a message from
# vanishing before anyone could plausibly have opened it; ceiling is just a
# sanity cap, not a security boundary -- ttl_seconds=None (no cap at all)
# remains the default for an ordinary, non-expiring message.
MIN_TTL_SECONDS = 5
MAX_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days


def is_valid_rsa_public_key_pem(pem):
    """Every client-side importKey call assumes a 2048-bit RSA SPKI PEM
    (see generateFreshKeys in chatbox.html) -- this checks a submitted key
    actually is one, rather than only checking it's non-empty. The server
    still can't (and shouldn't try to) vouch for a key being honestly
    generated in an E2EE design; this only rules out malformed/wrong-type/
    oversized values that would otherwise silently break every other
    participant's crypto calls against this one."""
    if not pem or len(pem) > _MAX_PUBLIC_KEY_PEM_LEN:
        return False
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except ValueError:
        return False
    return isinstance(key, rsa.RSAPublicKey) and key.key_size == 2048


# ── Participant issuance ─────────────────────────────────────────────────

def issue_participant(chat, display_name, public_key):
    """Creates a ChatParticipant with a fresh bearer token and returns
    (participant, raw_token). The raw token is never stored -- only its hash
    is -- and this is the only place in the app it's ever computed."""
    raw_token = secrets.token_urlsafe(32)
    participant = ChatParticipant.objects.create(
        chat=chat,
        display_name=display_name,
        public_key=public_key,
        auth_token_hash=hash_token(raw_token),
    )
    return participant, raw_token


# ── Chat creation / joining / leaving ────────────────────────────────────

PIN_SPACE = 10_000
# Random draws before falling back to picking from the free PINs directly.
# While the space is mostly empty the first draw almost always hits; the
# fallback only runs when it's nearly full.
_PIN_RANDOM_DRAWS = 20


def _pick_free_pin():
    """Returns a PIN no live chat holds, drawn with `secrets` -- the PIN is
    a join secret, so a predictable generator (it used to be
    random.randint, threat-model T-32) has no place here. Raises NoFreePin.

    This used to be an unbounded `while True` loop: once every PIN was
    taken (anyone can create chats anonymously), every create request
    spun forever and pinned a worker (issue #98)."""
    for _ in range(_PIN_RANDOM_DRAWS):
        pin = f"{secrets.randbelow(PIN_SPACE):04d}"
        if not Chat.objects.filter(pin=pin).exists():
            return pin
    used = set(Chat.objects.values_list("pin", flat=True))
    free = [pin for pin in (f"{i:04d}" for i in range(PIN_SPACE)) if pin not in used]
    if not free:
        raise NoFreePin()
    return secrets.choice(free)


def create_chat(display_name, public_key, max_participants):
    """Picks a free 4-digit PIN and creates a new Chat plus its first
    participant. Returns (chat, participant, raw_token). Raises NoFreePin."""
    for _ in range(3):
        pin = _pick_free_pin()
        try:
            with transaction.atomic():
                chat = Chat.objects.create(
                    pin=pin,
                    max_participants=max_participants,
                    is_group=max_participants > 2,
                )
                participant, raw_token = issue_participant(chat, display_name, public_key)
            return chat, participant, raw_token
        except IntegrityError:
            # A concurrent create took the same PIN between the check and
            # the insert (Chat.pin is unique); pick again.
            continue
    raise NoFreePin()


def get_chat(chat_id):
    """Raises ChatNotFound."""
    try:
        return Chat.objects.get(pin=chat_id)
    except Chat.DoesNotExist:
        raise ChatNotFound()


def join_chat(chat, display_name, public_key):
    """Raises ChatFull. Returns (participant, raw_token)."""
    active_participants = chat.participants.filter(left_at__isnull=True)
    if active_participants.count() >= chat.max_participants:
        raise ChatFull()
    return issue_participant(chat, display_name, public_key)


def leave_chat(participant, chat_id):
    """Marks participant as left; hard-deletes the chat if that empties it
    -- see #35, this is what actually frees the PIN for reuse (a
    permanently-retired-but-flagged row would make the PIN unavailable
    forever, a hard ceiling given there are only 10,000 possible PINs).
    Returns (chat_deleted: bool, remaining_count: int). Raises
    ChatNotFound, NotAParticipant."""
    chat = get_chat(chat_id)
    if participant.chat_id != chat.pk:
        raise NotAParticipant()

    participant.left_at = timezone.now()
    participant.save(update_fields=["left_at"])

    remaining = chat.participants.filter(left_at__isnull=True).count()
    if remaining == 0:
        chat.delete()
        return True, 0
    return False, remaining


# ── Messaging / forward-secrecy ratchet ──────────────────────────────────

def send_message(chat_id, sender, *, encrypted_text, aes_nonce, aes_tag, mac,
                  wrapped_keys, prev_hash, sender_chain_epoch, chain_index, ttl_seconds=None):
    """Validates and appends one message under a row lock -- assigning seq
    here (not client-side) and rejecting a stale prev_hash both prevent two
    concurrent sends from landing on the same chain position. Raises
    ChatNotFound, NotAParticipant, UnknownChainEpoch, StaleChainEpoch,
    StaleTranscript, MissingSelfWrap, InvalidTTL. Returns the created
    Message.

    The `sender.left_at is not None` check below can never actually trigger
    today -- ParticipantTokenAuthentication only ever authenticates a
    participant whose left_at is still null (see chat/auth.py) -- but it's
    kept as cheap defense-in-depth against that invariant changing later,
    rather than relying solely on the auth layer to enforce it.

    ttl_seconds (issue #64): if set, the sender's own read receipt is
    created immediately below -- they've necessarily "read" a message they
    just composed and sent, the same way isMine skips signature/MAC
    verification client-side in chatbox.html's renderMsg. Their own copy's
    expiry window starts now, same as everyone else's starts when they
    first fetch it (see mark_messages_read)."""
    if ttl_seconds is not None and not (MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS):
        raise InvalidTTL()

    with transaction.atomic():
        try:
            chat = Chat.objects.select_for_update().get(pin=chat_id)
        except Chat.DoesNotExist:
            raise ChatNotFound()
        if sender.chat_id != chat.pk or sender.left_at is not None:
            raise NotAParticipant()

        # Must be the sender's CURRENT epoch, not merely one that once
        # existed -- re-keying on roster change (see ChainKey's docstring)
        # only bounds a leaver's exposure if the server actually refuses a
        # stale epoch a departed participant could still hold the seed for.
        # See issue #69.
        latest_epoch = ChainKey.objects.filter(sender=sender).aggregate(Max("epoch"))["epoch__max"]
        if latest_epoch is None:
            raise UnknownChainEpoch()
        if sender_chain_epoch != latest_epoch:
            raise StaleChainEpoch()

        tip = chat.messages.order_by("-seq").first()
        expected_prev_hash = compute_chain_hash(tip) if tip else GENESIS_HASH
        if prev_hash != expected_prev_hash:
            raise StaleTranscript(expected_prev_hash)

        self_wrap = next(
            (wk.get("encrypted_symmetric_key") for wk in wrapped_keys
             if wk.get("recipient_id") == sender.pk and wk.get("encrypted_symmetric_key")),
            None,
        )
        if not self_wrap:
            raise MissingSelfWrap()

        msg = Message.objects.create(
            chat=chat,
            sender=sender,
            encrypted_text=encrypted_text,
            aes_nonce=aes_nonce,
            aes_tag=aes_tag,
            mac=mac,
            seq=(tip.seq + 1) if tip else 0,
            prev_hash=prev_hash,
            sender_chain_epoch=sender_chain_epoch,
            chain_index=chain_index,
            ttl_seconds=ttl_seconds,
        )
        MessageKey.objects.create(message=msg, recipient=sender, encrypted_symmetric_key=self_wrap)
        if ttl_seconds is not None:
            MessageReadReceipt.objects.create(message=msg, participant=sender)

    return msg


# ── Disappearing messages (issue #64) ────────────────────────────────────

def mark_messages_read(chat, participant, messages):
    """Records that participant has just fetched each expiring, not-yet-
    tombstoned message in `messages` -- this app's only available "read"
    signal, since the server never sees plaintext or a client-side
    decrypt-success confirmation. Idempotent (ignore_conflicts against the
    (message, participant) unique constraint), so calling this on every
    poll/fetch is cheap and safe."""
    expiring_ids = [m.id for m in messages if m.ttl_seconds is not None and m.tombstone_hash is None]
    if not expiring_ids:
        return
    MessageReadReceipt.objects.bulk_create(
        [MessageReadReceipt(message_id=mid, participant=participant) for mid in expiring_ids],
        ignore_conflicts=True,
    )


def _tombstone(msg):
    """Wipes msg's actual content, preserving compute_chain_hash's result
    from the moment before the wipe so later messages' prev_hash stays
    verifiable -- see Message.tombstone_hash. Both the sender's self-wrap
    and everyone's read receipts are deleted along with it; neither has any
    remaining purpose once the content they refer to is gone."""
    msg.tombstone_hash = compute_chain_hash(msg)
    msg.encrypted_text = None
    msg.aes_nonce = None
    msg.aes_tag = None
    msg.mac = None
    msg.tombstoned_at = timezone.now()
    msg.save(update_fields=["tombstone_hash", "encrypted_text", "aes_nonce", "aes_tag", "mac", "tombstoned_at"])
    MessageKey.objects.filter(message=msg).delete()
    MessageReadReceipt.objects.filter(message=msg).delete()


def sweep_expired_messages(chat):
    """Tombstones every message in chat whose TTL has fully elapsed for
    everyone who could still legitimately need to read it. Called lazily on
    every message fetch (see views.GetMessagesView) -- this app has no
    scheduled/cron job anywhere, consistent with how idle-token reclaim
    (chat/auth.py) and empty-chat deletion (leave_chat above) already work.

    "Could still legitimately need to read it" means: currently active
    (not left) AND was already in the chat when the message was sent. The
    second clause matters -- per forward secrecy, a participant who joined
    afterward can never derive that epoch's key at all (see
    docs/FORWARD_SECRECY.md), so waiting on a read receipt from them would
    be waiting forever; their absence can't be what blocks expiry.

    If nobody who was present at send time is still active, the message is
    already permanently undecryptable to everyone remaining regardless of
    ttl_seconds -- tombstoned immediately rather than waited out, since
    keeping unreachable ciphertext around serves no purpose."""
    now = timezone.now()
    candidates = chat.messages.filter(ttl_seconds__isnull=False, tombstone_hash__isnull=True)

    for msg in candidates:
        required_ids = set(
            chat.participants.filter(left_at__isnull=True, joined_at__lte=msg.timestamp)
            .values_list("id", flat=True)
        )
        if not required_ids:
            _tombstone(msg)
            continue

        read_at_by_participant = dict(
            MessageReadReceipt.objects
            .filter(message=msg, participant_id__in=required_ids)
            .values_list("participant_id", "read_at")
        )
        if len(read_at_by_participant) < len(required_ids):
            continue  # someone who's required to has not read it at all yet

        cutoff = timedelta(seconds=msg.ttl_seconds)
        if all(now - read_at >= cutoff for read_at in read_at_by_participant.values()):
            _tombstone(msg)


def issue_chain_key(chat_id, sender, wraps):
    """Issues a new epoch of sender's sending-chain seed, RSA-OAEP-wrapped
    for every currently active *other* participant; wraps must cover
    exactly that set. Raises ChatNotFound, NotAParticipant, RosterMismatch.
    Returns the new epoch number."""
    with transaction.atomic():
        try:
            chat = Chat.objects.select_for_update().get(pin=chat_id)
        except Chat.DoesNotExist:
            raise ChatNotFound()
        participant = ChatParticipant.objects.select_for_update().get(pk=sender.pk)
        if participant.chat_id != chat.pk or participant.left_at is not None:
            raise NotAParticipant()

        active_other_ids = set(
            chat.participants.filter(left_at__isnull=True).exclude(pk=participant.pk)
            .values_list("id", flat=True)
        )
        submitted = {
            w.get("recipient_id"): w.get("encrypted_seed")
            for w in wraps
            if w.get("recipient_id") is not None and w.get("encrypted_seed")
        }
        if set(submitted.keys()) != active_other_ids:
            raise RosterMismatch()

        last = ChainKey.objects.filter(sender=participant).order_by("-epoch").first()
        next_epoch = (last.epoch + 1) if last else 0
        chain_key = ChainKey.objects.create(chat=chat, sender=participant, epoch=next_epoch)
        ChainKeyWrap.objects.bulk_create([
            ChainKeyWrap(chain_key=chain_key, recipient_id=recipient_id, encrypted_seed=seed)
            for recipient_id, seed in submitted.items()
        ])

    return next_epoch


def get_latest_chain_keys_for_recipient(chat, recipient):
    """For every sender who has issued at least one chain-key epoch
    addressed to recipient, returns the LATEST such epoch's wrapped seed --
    what recipient needs to (re-)seed their receiving-side ratchet for that
    sender. Returns a list of {"sender_id", "epoch", "encrypted_seed"}."""
    wraps = (
        ChainKeyWrap.objects
        .filter(recipient=recipient, chain_key__chat=chat)
        .select_related("chain_key")
        .order_by("chain_key__sender_id", "-chain_key__epoch")
    )
    seen_senders = set()
    result = []
    for w in wraps:
        sender_id = w.chain_key.sender_id
        if sender_id in seen_senders:
            continue
        seen_senders.add(sender_id)
        result.append({
            "sender_id": sender_id,
            "epoch": w.chain_key.epoch,
            "encrypted_seed": w.encrypted_seed,
        })
    return result


# ── Roster / message visibility ──────────────────────────────────────────

def require_same_chat(chat, participant):
    """Raises NotAParticipant unless participant belongs to chat at all
    (their ChatParticipant.chat FK), regardless of active/left status."""
    if participant.chat_id != chat.pk:
        raise NotAParticipant()


def require_active_participant(chat, participant, active=None):
    """Raises NotAParticipant unless participant is a currently-active
    (not left) member of chat. Pass an already-fetched `active` list (from
    get_active_participants) to avoid a redundant query when the caller
    needs that list anyway."""
    if active is None:
        active = get_active_participants(chat)
    if not any(p.pk == participant.pk for p in active):
        raise NotAParticipant()


def get_active_participants(chat):
    return list(chat.participants.filter(left_at__isnull=True))

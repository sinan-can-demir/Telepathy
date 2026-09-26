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

import hashlib
import hmac
import re
import secrets
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Max
from django.utils import timezone

from .auth import IDLE_TIMEOUT, hash_token
from .chain import GENESIS_HASH, compute_chain_hash
from .models import Chat, ChainKey, ChainKeyWrap, ChatInvite, ChatParticipant, Message, MessageReadReceipt


class ChatServiceError(Exception):
    """Base class for every domain-rule violation this module raises."""


class ChatNotFound(ChatServiceError):
    pass


class ChatFull(ChatServiceError):
    pass


class DisplayNameTaken(ChatServiceError):
    """Another active participant already goes by this name (issue #100)."""


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


class RosterMismatch(ChatServiceError):
    """A chain-key issuance's wraps don't cover exactly the current roster."""


class NoFreeHandle(ChatServiceError):
    """No open-invite handle could be allocated (the space is ~1M)."""


class InvalidInvite(ChatServiceError):
    """Deliberately one error for every way an invite can fail -- malformed,
    unknown, expired, burned, used, wrong code -- so a probe can't tell a
    live handle from a dead one (docs/DESIGN_JOIN_SECRET.md)."""


class InviteLimit(ChatServiceError):
    """Open invites would outnumber the chat's free seats."""


class InvalidTTL(ChatServiceError):
    """A submitted ttl_seconds is out of the allowed range."""


# ── Validation ────────────────────────────────────────────────────────────

def is_valid_display_name(name):
    # fullmatch, not match with '$': '$' also matches before a trailing
    # newline, so "alice\n" used to validate (threat-model T-22).
    return (isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9_ -]{1,32}', name) is not None
            and not name.isspace())


def display_name_key(name):
    """What two display names are compared by: "Alice", "alice" and
    "alice  " render as the same person to a reader, so they count as the
    same name."""
    return " ".join(name.split()).casefold()


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

# ── Invites (docs/DESIGN_JOIN_SECRET.md, #101 stage 2) ───────────────────

# Crockford base32: no I, L, O or U, so what's read aloud or typed is hard
# to get wrong, and lookalikes can be mapped back when decoding.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# Crockford's check alphabet: the 32 digits plus five symbols for mod 37.
CHECK_SYMBOLS = CROCKFORD + "*~$=U"
HANDLE_DIGITS = 6
CODE_LENGTH = 6            # 30 bits
MAX_WRONG_ATTEMPTS = 3
INVITE_LIFETIME = timedelta(minutes=15)
_HANDLE_DRAWS = 20


def invite_check_symbol(handle, code):
    """Crockford's mod-37 check symbol over the whole handle+code value.
    It exists to catch typos before they cost a strike (a mistyped handle
    could otherwise spend one of a stranger's three), not for security:
    it's computed from what the user typed."""
    value = int(handle)
    for ch in code:
        value = value * 32 + CROCKFORD.index(ch)
    return CHECK_SYMBOLS[value % 37]


def format_invite(handle, code):
    return f"{handle}-{code}-{invite_check_symbol(handle, code)}"


def parse_invite(raw):
    """Returns (handle, code), or None if malformed or the check symbol is
    wrong. Case-insensitive; ignores spaces and hyphens; reads I/L as 1 and
    O as 0, as Crockford specifies."""
    if not isinstance(raw, str) or len(raw) > 40:
        return None
    s = raw.upper().replace("-", "").replace(" ", "")
    s = s.translate(str.maketrans({"I": "1", "L": "1", "O": "0"}))
    if len(s) != HANDLE_DIGITS + CODE_LENGTH + 1:
        return None
    handle, code, check = s[:HANDLE_DIGITS], s[HANDLE_DIGITS:-1], s[-1]
    if not handle.isdigit() or any(ch not in CROCKFORD for ch in code):
        return None
    if invite_check_symbol(handle, code) != check:
        return None
    return handle, code


def _code_hmac(code):
    """Keyed, so a copy of the database alone can't brute-force a live
    30-bit code (an unkeyed hash of one falls in seconds). The key is
    derived from SECRET_KEY, which lives outside the database and which the
    app refuses to run without (T-20)."""
    key = hashlib.sha256(b"telepathy-invite-code:" + settings.SECRET_KEY.encode()).digest()
    return hmac.new(key, code.encode(), hashlib.sha256).hexdigest()


def _open_invites(chat=None):
    qs = ChatInvite.objects.filter(state=ChatInvite.OPEN, expires_at__gt=timezone.now())
    return qs.filter(chat=chat) if chat is not None else qs


def issue_invite(chat, issuer):
    """Any active member may invite (decision 3); the roster sees it via
    get-messages. Issuing revokes the issuer's own earlier open invites for
    this chat: the code is shown once and never stored in plaintext, so a
    reload loses it, and without this a 1:1 creator couldn't issue a
    replacement while the lost one held the only free seat. Returns
    (invite, "handle-code-check"). Raises NotAParticipant, InviteLimit,
    NoFreeHandle."""
    with transaction.atomic():
        chat = Chat.objects.select_for_update().get(pk=chat.pk)
        if issuer.chat_id != chat.pk or issuer.left_at is not None:
            raise NotAParticipant()
        _open_invites(chat).filter(issued_by=issuer).update(state=ChatInvite.REVOKED)
        free_seats = chat.max_participants - chat.participants.filter(left_at__isnull=True).count()
        if _open_invites(chat).count() >= free_seats:
            raise InviteLimit()
        # Expired invites still marked open would hold their handles.
        ChatInvite.objects.filter(state=ChatInvite.OPEN, expires_at__lte=timezone.now()) \
            .update(state=ChatInvite.REVOKED)
        code = "".join(secrets.choice(CROCKFORD) for _ in range(CODE_LENGTH))
        for _ in range(_HANDLE_DRAWS):
            handle = f"{secrets.randbelow(10 ** HANDLE_DIGITS):0{HANDLE_DIGITS}d}"
            try:
                with transaction.atomic():
                    invite = ChatInvite.objects.create(
                        chat=chat, issued_by=issuer, handle=handle, code_hmac=_code_hmac(code),
                        expires_at=timezone.now() + INVITE_LIFETIME,
                    )
                return invite, format_invite(handle, code)
            except IntegrityError:
                continue  # that handle is on another open invite
        raise NoFreeHandle()


def redeem_invite(raw, display_name, public_key):
    """Joins the chat an invite belongs to. Returns (chat, participant,
    raw_token). Raises InvalidInvite (for everything the invitee gets
    wrong), ChatFull, DisplayNameTaken.

    A malformed string or bad check symbol costs no strike. A wrong code is
    charged to the invite -- never to a source address, so nothing depends
    on X-Forwarded-For or on Tor's shared address (#95) -- inside the same
    row lock as the comparison, so parallel guesses can't all be evaluated
    before the counter moves. The strike is committed even though the call
    then fails; a correct code that can't be used (name taken, chat full)
    leaves the invite open."""
    parsed = parse_invite(raw)
    if parsed is None:
        raise InvalidInvite()
    handle, code = parsed
    guess = _code_hmac(code)

    with transaction.atomic():
        invite = (_open_invites().select_for_update().select_related("chat")
                  .filter(handle=handle).first())
        if invite is None:
            hmac.compare_digest(guess, guess)  # same work as a real compare
            wrong = True
        elif not hmac.compare_digest(guess, invite.code_hmac):
            invite.failed_attempts += 1
            if invite.failed_attempts >= MAX_WRONG_ATTEMPTS:
                invite.state = ChatInvite.BURNED
            invite.save(update_fields=["failed_attempts", "state"])
            wrong = True
        else:
            wrong = False
    if wrong:
        raise InvalidInvite()

    with transaction.atomic():
        invite = ChatInvite.objects.select_for_update().select_related("chat").get(pk=invite.pk)
        if invite.state != ChatInvite.OPEN or invite.expires_at <= timezone.now():
            raise InvalidInvite()  # consumed by a concurrent redeem of the same code
        participant, raw_token = join_chat(invite.chat, display_name, public_key)
        invite.state = ChatInvite.CONSUMED
        invite.save(update_fields=["state"])
    return invite.chat, participant, raw_token


def invites_for_roster(chat, viewer):
    """What members see about invites: who issued one and what became of
    it, never a code. Issuance is announced to everyone (decision 3) and a
    burn to its issuer, who then knows to issue another."""
    now = timezone.now()
    out = []
    for inv in chat.invites.select_related("issued_by").order_by("created_at"):
        state = inv.state
        if state == ChatInvite.OPEN and inv.expires_at <= now:
            state = "expired"
        out.append({
            "id": inv.pk,
            "handle": inv.handle,
            "issued_by": inv.issued_by.display_name if inv.issued_by else None,
            "mine": inv.issued_by_id == viewer.pk,
            "state": state,
            "expires_at": inv.expires_at.isoformat(),
        })
    return out


def create_chat(display_name, public_key, max_participants):
    """Creates a new Chat, its first participant and a first invite.
    Returns (chat, participant, raw_token, invite_string)."""
    with transaction.atomic():
        chat = Chat.objects.create(
            max_participants=max_participants,
            is_group=max_participants > 2,
        )
        participant, raw_token = issue_participant(chat, display_name, public_key)
        _, invite_string = issue_invite(chat, participant)
    return chat, participant, raw_token, invite_string


def get_chat(chat_id):
    """Looks a chat up by its public id, its address everywhere after the
    join. Raises ChatNotFound."""
    try:
        return Chat.objects.get(public_id=chat_id)
    except Chat.DoesNotExist:
        raise ChatNotFound()



def join_chat(chat, display_name, public_key):
    """Raises ChatFull, DisplayNameTaken. Returns (participant, raw_token).

    Names must be unique among the chat's active participants (#100):
    otherwise an intruder can join as a second "alice" and be read as the
    real one. The chat row is locked so two concurrent joins can't both
    pass the name or capacity check (the latter could overfill a group)."""
    with transaction.atomic():
        chat = Chat.objects.select_for_update().get(pk=chat.pk)
        active_participants = list(chat.participants.filter(left_at__isnull=True))
        if len(active_participants) >= chat.max_participants:
            raise ChatFull()
        key = display_name_key(display_name)
        if any(display_name_key(p.display_name) == key for p in active_participants):
            raise DisplayNameTaken()
        return issue_participant(chat, display_name, public_key)


def mark_left(participant, now=None):
    """Marks participant as left and hard-deletes their chat if that empties
    it (#35), cascading to its messages, keys and invites.
    Every way out of a chat goes through here: an explicit leave, idle
    expiry on the participant's own next request (chat/auth.py) and the
    reaper (reap_idle_chats). Idle expiry used to only set left_at, so a
    chat emptied that way kept its row and ciphertext forever (#97).
    Returns (chat_deleted: bool, remaining_count: int)."""
    participant.left_at = now or timezone.now()
    participant.save(update_fields=["left_at"])

    chat = participant.chat
    remaining = chat.participants.filter(left_at__isnull=True).count()
    if remaining == 0:
        chat.delete()
        return True, 0
    return False, remaining


def leave_chat(participant, chat_id):
    """Explicit leave. Returns (chat_deleted: bool, remaining_count: int).
    Raises ChatNotFound, NotAParticipant."""
    chat = get_chat(chat_id)
    if participant.chat_id != chat.pk:
        raise NotAParticipant()
    return mark_left(participant)


def reap_idle_chats(now=None):
    """Expires every participant idle past IDLE_TIMEOUT and deletes every
    chat left with no active participant, without waiting for anyone to
    come back. Idle expiry otherwise only happens lazily, when that same
    participant next authenticates, which an abandoned chat never does
    (#97). Run on a schedule by `manage.py reap_idle_chats` (the `reaper`
    service in compose.yaml).

    Returns (participants_expired, chats_deleted, public ids of chats still
    live whose roster changed) -- the caller notifies those so remaining members
    see the departure and re-key on their next send."""
    now = now or timezone.now()
    expired = 0
    deleted = 0
    changed_ids = set()
    idle = (ChatParticipant.objects.select_related("chat")
            .filter(left_at__isnull=True, last_seen__lt=now - IDLE_TIMEOUT))
    for participant in idle:
        chat_id = participant.chat.public_id
        chat_deleted, _ = mark_left(participant, now)
        expired += 1
        if chat_deleted:
            deleted += 1
            changed_ids.discard(chat_id)
        else:
            changed_ids.add(chat_id)

    # Chats already emptied before idle expiry deleted them (anything
    # idle-expired before #97), or by any other path that set left_at alone.
    orphaned = Chat.objects.exclude(
        pk__in=ChatParticipant.objects.filter(left_at__isnull=True).values("chat_id")
    )
    deleted += orphaned.count()
    orphaned.delete()
    # Invite rows only matter while live, plus a while after so an issuer
    # still sees that theirs was burned or used.
    ChatInvite.objects.filter(expires_at__lt=now - timedelta(hours=1)).delete()
    return expired, deleted, changed_ids


# ── Messaging / forward-secrecy ratchet ──────────────────────────────────

def send_message(chat_id, sender, *, encrypted_text, aes_nonce, aes_tag, mac,
                  prev_hash, sender_chain_epoch, chain_index, ttl_seconds=None):
    """Validates and appends one message under a row lock -- assigning seq
    here (not client-side) and rejecting a stale prev_hash both prevent two
    concurrent sends from landing on the same chain position. Raises
    ChatNotFound, NotAParticipant, UnknownChainEpoch, StaleChainEpoch,
    StaleTranscript, InvalidTTL. Returns the created
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
            chat = Chat.objects.select_for_update().get(public_id=chat_id)
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
    verifiable -- see Message.tombstone_hash. Everyone's read receipts are
    deleted along with it; they have no purpose once the content is gone."""
    msg.tombstone_hash = compute_chain_hash(msg)
    msg.encrypted_text = None
    msg.aes_nonce = None
    msg.aes_tag = None
    msg.mac = None
    msg.tombstoned_at = timezone.now()
    msg.save(update_fields=["tombstone_hash", "encrypted_text", "aes_nonce", "aes_tag", "mac", "tombstoned_at"])
    MessageReadReceipt.objects.filter(message=msg).delete()


def sweep_expired_messages(chat):
    """Tombstones every message in chat whose TTL has fully elapsed for
    everyone who could still legitimately need to read it. Called lazily on
    every message fetch (see views.GetMessagesView). It only matters while
    someone is still fetching: once a chat is abandoned, reap_idle_chats
    deletes it, messages included.

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
            chat = Chat.objects.select_for_update().get(public_id=chat_id)
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


def ack_chain_key(chat, recipient, sender_id, epoch):
    """Deletes the wrapped seeds of sender_id's chain addressed to recipient,
    for `epoch` and every earlier epoch, once recipient has stored the seed
    locally (issue #99, option A). A wrapped seed kept on the server lets
    anyone who later gets both a copy of the database and recipient's RSA
    key re-derive every message key of that chain from index 0, no matter
    how far recipient's own ratchet has moved on -- which is exactly the
    compromise forward secrecy is meant to survive. Deleting on fetch
    would be simpler but unsafe: the client only commits a seed after a
    message under it decrypts (#94), so a fetch that doesn't end in a
    commit must be repeatable. Returns the number of wraps deleted."""
    deleted, _ = ChainKeyWrap.objects.filter(
        recipient=recipient,
        chain_key__chat=chat,
        chain_key__sender_id=sender_id,
        chain_key__epoch__lte=epoch,
    ).delete()
    return deleted


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

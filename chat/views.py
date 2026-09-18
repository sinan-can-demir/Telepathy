import secrets
from rest_framework.views import APIView
from rest_framework import status, permissions
from .serializers import MessageSerializer
from .models import Message, MessageKey
import logging
from collections import defaultdict
import re
import random
import time
from .models import Chat, ChatParticipant, ChainKey, ChainKeyWrap
from django.db import transaction
from django.db.models import Max
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from rest_framework.response import Response
from .auth import ParticipantTokenAuthentication, hash_token
from .chain import GENESIS_HASH, compute_chain_hash
from .realtime import notify_chat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Track failed chat-join attempts per source IP, to slow brute-forcing the
# 4-digit PIN space (10,000 values). This can no longer be keyed on an
# account -- CreateChatView/JoinChatView are unauthenticated entry points by
# design, since there's no account to log into before you have a PIN. Under
# a Tor hidden-service deployment this collapses to one shared bucket (every
# client shares the loopback address) -- see ARCHITECTURE.md for why that's
# an accepted tradeoff there, mitigated by Tor's own connection-level PoW
# defense rather than an app-level throttle.
failed_join_attempts = defaultdict(lambda: {'last_time': 0, 'wait_time': 0, 'fail_count': 0})

logger = logging.getLogger(__name__)


def _is_valid_display_name(name):
    return bool(name) and re.match(r'^[a-zA-Z0-9_ -]{1,32}$', name) is not None


# A 2048-bit RSA SPKI PEM is well under 1KB; capping length before ever
# parsing it keeps a hostile/malformed value from being an amplification
# vector (see issue #72) and gives load_pem_public_key a bounded input.
_MAX_PUBLIC_KEY_PEM_LEN = 2000


def _is_valid_rsa_public_key_pem(pem):
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


def _client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))


def _issue_participant(chat, display_name, public_key):
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


# Home Page View - renders index.html
def home(request):
    return render(request, "index.html")


# No login/registration step anymore -- /chat/ goes straight to the
# create/join dashboard. Kept as its own view (rather than changing the
# root urlconf) so index.html's existing "/chat/" link needs no edit.
def auth_page(request):
    return redirect("/chat/usermenu/")


def user_menu(request):
    return render(request, "usermenu.html")


# Chatbox Page View - renders chatbox.html
def chatbox(request):
    # No server-side session state here -- chatbox.html drives everything
    # itself client-side (create/join via ?action= query params, chat_id
    # and the bearer token kept in localStorage). Just render the shell.
    return render(request, "chatbox.html")


class CreateChatView(APIView):
    """
    POST /chat/create-chat/
    No account needed -- this *is* the entry point. Optionally accepts
    { "display_name": "...", "max_participants": <2-8>, "public_key": "..." }.
    Returns: { "chat_id": "<4-digit PIN>", "participant_token": "<raw token>" }
    (the token is shown exactly once and never recoverable afterward).
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        public_key = request.data.get("public_key")
        if not _is_valid_rsa_public_key_pem(public_key):
            return Response({"message": "public_key must be a 2048-bit RSA public key in SPKI PEM form."}, status=400)

        display_name = request.data.get("display_name") or f"Participant-{secrets.token_hex(2)}"
        if not _is_valid_display_name(display_name):
            return Response({"message": "Invalid display name."}, status=400)

        raw_max_participants = request.data.get("max_participants", 2)
        try:
            max_participants = int(raw_max_participants)
        except (TypeError, ValueError):
            return Response({"message": "max_participants must be an integer."}, status=400)
        if not (2 <= max_participants <= 8):
            return Response({"message": "max_participants must be between 2 and 8."}, status=400)

        while True:
            pin = f"{random.randint(0, 9999):04d}"
            if not Chat.objects.filter(pin=pin).exists():
                break

        chat = Chat.objects.create(
            pin=pin,
            max_participants=max_participants,
            is_group=max_participants > 2,
        )
        participant, raw_token = _issue_participant(
            chat, display_name, public_key
        )
        logger.info(f"[CREATE-CHAT] Created chat {chat}, PIN: {chat.pin}")

        return Response(
            {"chat_id": pin, "participant_token": raw_token, "participant_id": participant.pk},
            status=201,
        )


class JoinChatView(APIView):
    """
    POST /chat/join-chat/
    No account needed. Expects JSON: { "chat_id": "<4-digit-PIN>",
    "display_name": "...", "public_key": "..." }
    Returns: { "participant_token": "<raw token>", "participant_id": <int> }
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        chat_id = request.data.get("chat_id")
        if not chat_id:
            return Response({"message": "Chat ID is required."}, status=400)

        public_key = request.data.get("public_key")
        if not _is_valid_rsa_public_key_pem(public_key):
            return Response({"message": "public_key must be a 2048-bit RSA public key in SPKI PEM form."}, status=400)

        display_name = request.data.get("display_name") or f"Participant-{secrets.token_hex(2)}"
        if not _is_valid_display_name(display_name):
            return Response({"message": "Invalid display name."}, status=400)

        # -- Rate limiting by source IP -- the only signal available before a
        # participant token exists. See the failed_join_attempts comment above.
        ip = _client_ip(request)
        entry = failed_join_attempts[ip]
        now_time = time.time()
        if entry["fail_count"] >= 5 and now_time < entry["last_time"] + entry["wait_time"]:
            wait_remaining = int(entry["last_time"] + entry["wait_time"] - now_time)
            return Response(
                {"message": f"Too many failed join attempts. Try again in {wait_remaining} seconds."},
                status=429,
            )

        try:
            chat = Chat.objects.get(pin=chat_id)
        except Chat.DoesNotExist:
            entry["fail_count"] += 1
            if entry["fail_count"] >= 5:
                entry["wait_time"] = entry["wait_time"] * 2 if entry["wait_time"] else 10
                entry["last_time"] = now_time
                return Response(
                    {"message": f"Too many failed join attempts. Try again in {entry['wait_time']} seconds."},
                    status=429,
                )
            return Response({"message": "Chat not found."}, status=404)

        failed_join_attempts.pop(ip, None)

        active_participants = chat.participants.filter(left_at__isnull=True)
        if active_participants.count() >= chat.max_participants:
            return Response({"message": "Chat is full."}, status=400)

        participant, raw_token = _issue_participant(
            chat, display_name, public_key
        )
        logger.info(f"[JOIN-CHAT] '{display_name}' joined chat '{chat_id}'.")
        notify_chat(chat_id, "roster_changed")
        return Response(
            {"participant_token": raw_token, "participant_id": participant.pk},
            status=200,
        )


class CheckChatView(APIView):
    """GET /chat/check-chat/<chat_id>/ -- no account needed, same reasoning
    as CreateChatView/JoinChatView."""
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def get(self, request, chat_id):
        try:
            chat = Chat.objects.get(pin=chat_id)
            participants = list(
                chat.participants.filter(left_at__isnull=True)
                .order_by("joined_at")
                .values_list("display_name", flat=True)
            )
            return Response({"exists": True, "participants": participants}, status=status.HTTP_200_OK)
        except Chat.DoesNotExist:
            return Response({"exists": False}, status=status.HTTP_404_NOT_FOUND)


class LeaveChatView(APIView):
    """Marks the calling participant as left, hard-deleting the chat once it
    fully empties (cascades to its participants/messages/keys). request.user
    IS the participant (via ParticipantTokenAuthentication) -- no separate
    lookup needed.

    Deleting rather than soft-flagging the chat is what actually frees its
    4-digit PIN for reuse (see #35) -- a permanently-retired-but-flagged row
    would still make CreateChatView's pin=... uniqueness check treat that PIN
    as taken forever, which is a hard ceiling on lifetime chats given there
    are only 10,000 possible PINs."""
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        chat_id = request.data.get("chat_id", None)
        participant = request.user

        try:
            chat = Chat.objects.get(pin=chat_id)
        except Chat.DoesNotExist:
            return Response({"message": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        if participant.chat_id != chat.pk:
            return Response({"message": "Not in this chat."}, status=status.HTTP_400_BAD_REQUEST)

        participant.left_at = timezone.now()
        participant.save(update_fields=["left_at"])

        remaining = chat.participants.filter(left_at__isnull=True).count()
        if remaining == 0:
            chat.delete()
            logger.info(f"[LEAVE-CHAT] Chat '{chat_id}' emptied; deleted, freeing its PIN.")
        else:
            logger.info(f"[LEAVE-CHAT] A participant left chat '{chat_id}'; {remaining} remain.")
            notify_chat(chat_id, "roster_changed")

        return Response({"message": "Left chat."}, status=status.HTTP_200_OK)


class SendMessageView(APIView):
    """
    Requires prev_hash: the client's claim about the chain hash (see
    chat/chain.py) of the message immediately before this one, or
    GENESIS_HASH if this is the chat's first message. Assigning seq under a
    row lock and rejecting a stale prev_hash with 409 both prevents two
    concurrent sends from landing on the same position and gives every
    later reader a verifiable chain -- see chatbox.html's verification walk
    for what actually catches a dropped/reordered/replayed message.

    Forward secrecy (see docs/FORWARD_SECRECY.md): the AES key for this
    message comes from the sender's own sending-chain ratchet, seeded via
    IssueChainKeyView/ChainKey. wrapped_keys now only ever needs to contain
    the sender's own self-wrapped copy (so they can redisplay their own sent
    history) -- other participants derive the same key locally by advancing
    their cached copy of the sender's chain, so no per-recipient wrap is
    transmitted or stored for them anymore. sender_chain_epoch records which
    epoch that derivation used, for recipients to know whether to keep
    advancing their cached state or fetch a newer epoch's seed first.
    """
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, chat_id=None):
        me = request.user

        encrypted_text = request.data.get("encrypted_text")
        aes_nonce = request.data.get("aes_nonce")
        aes_tag = request.data.get("aes_tag")
        mac = request.data.get("mac")
        wrapped_keys = request.data.get("wrapped_keys")
        prev_hash = request.data.get("prev_hash")
        sender_chain_epoch = request.data.get("sender_chain_epoch")

        if not all([encrypted_text, aes_nonce, aes_tag, mac, prev_hash]) or not wrapped_keys \
                or sender_chain_epoch is None:
            return Response({"message": "Missing required encryption fields."}, status=400)

        with transaction.atomic():
            chat = get_object_or_404(Chat.objects.select_for_update(), pin=chat_id)
            if me.chat_id != chat.pk or me.left_at is not None:
                return Response({"detail": "Forbidden"}, status=403)

            # Must be the sender's CURRENT epoch, not merely one that once
            # existed -- re-keying on roster change (see ChainKey's
            # docstring) only bounds a leaver's exposure if the server
            # actually refuses a stale epoch a departed participant could
            # still hold the seed for. See issue #69.
            latest_epoch = ChainKey.objects.filter(sender=me).aggregate(Max("epoch"))["epoch__max"]
            if latest_epoch is None:
                return Response({"message": "Unknown sender_chain_epoch; issue a chain key first."}, status=400)
            if sender_chain_epoch != latest_epoch:
                return Response(
                    {"message": "sender_chain_epoch is stale; issue a fresh chain key and resend."},
                    status=400,
                )

            tip = chat.messages.order_by("-seq").first()
            expected_prev_hash = compute_chain_hash(tip) if tip else GENESIS_HASH
            if prev_hash != expected_prev_hash:
                return Response(
                    {
                        "message": "Stale transcript; refresh and resend.",
                        "expected_prev_hash": expected_prev_hash,
                    },
                    status=409,
                )

            self_wrap = next(
                (wk.get("encrypted_symmetric_key") for wk in wrapped_keys
                 if wk.get("recipient_id") == me.pk and wk.get("encrypted_symmetric_key")),
                None,
            )
            if not self_wrap:
                return Response({"message": "Missing self-wrapped key."}, status=400)

            msg = Message.objects.create(
                chat=chat,
                sender=me,
                encrypted_text=encrypted_text,
                aes_nonce=aes_nonce,
                aes_tag=aes_tag,
                mac=mac,
                seq=(tip.seq + 1) if tip else 0,
                prev_hash=prev_hash,
                sender_chain_epoch=sender_chain_epoch,
            )
            MessageKey.objects.create(message=msg, recipient=me, encrypted_symmetric_key=self_wrap)

        notify_chat(chat_id, "new_message")
        return Response(MessageSerializer(msg, context={"request": request}).data, status=201)


class IssueChainKeyView(APIView):
    """
    POST /chat/issue-chain-key/<chat_id>/
    A participant issues a new epoch of their own sending-chain seed,
    wrapped (RSA-OAEP) for every currently active *other* participant.
    Called before a participant's first send in a chat, and again any time
    the roster has changed since they last issued one. Expects:
    { "wraps": [{"recipient_id": <id>, "encrypted_seed": "<b64>"}, ...] }
    covering exactly the chat's current other active participants.
    Returns: {"epoch": <int>}
    """
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, chat_id=None):
        me = request.user
        wraps = request.data.get("wraps")
        if not wraps:
            return Response({"message": "wraps is required."}, status=400)

        with transaction.atomic():
            chat = get_object_or_404(Chat.objects.select_for_update(), pin=chat_id)
            participant = ChatParticipant.objects.select_for_update().get(pk=me.pk)
            if participant.chat_id != chat.pk or participant.left_at is not None:
                return Response({"detail": "Forbidden"}, status=403)

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
                return Response(
                    {"message": "wraps must cover exactly the chat's current other active participants."},
                    status=400,
                )

            last = ChainKey.objects.filter(sender=participant).order_by("-epoch").first()
            next_epoch = (last.epoch + 1) if last else 0
            chain_key = ChainKey.objects.create(chat=chat, sender=participant, epoch=next_epoch)
            ChainKeyWrap.objects.bulk_create([
                ChainKeyWrap(chain_key=chain_key, recipient_id=recipient_id, encrypted_seed=seed)
                for recipient_id, seed in submitted.items()
            ])

        return Response({"epoch": next_epoch}, status=201)


class GetChainKeysView(APIView):
    """
    GET /chat/get-chain-keys/<chat_id>/
    Returns, for every sender who has issued at least one chain-key epoch
    addressed to the caller, the LATEST such epoch's wrapped seed -- what a
    recipient needs to (re-)seed their receiving-side ratchet for that
    sender. Returns: {"chain_keys": [{"sender_id", "epoch", "encrypted_seed"}, ...]}
    """
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        chat = get_object_or_404(Chat, pin=chat_id)
        me = request.user
        if me.chat_id != chat.pk:
            return Response({"detail": "Forbidden"}, status=403)

        wraps = (
            ChainKeyWrap.objects
            .filter(recipient=me, chain_key__chat=chat)
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
        return Response({"chain_keys": result}, status=200)


class GetChatParticipantsView(APIView):
    """
    GET /chat/get-chat-participants/<chat_id>/
    Returns every active participant's id/display_name/public key, so the
    sender can wrap the per-message AES key for each of them. Requires the
    caller to be an active participant themselves.
    """
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        chat = get_object_or_404(Chat, pin=chat_id)
        me = request.user
        active = list(chat.participants.filter(left_at__isnull=True))
        if not any(p.pk == me.pk for p in active):
            return Response({"detail": "Forbidden"}, status=403)
        return Response({
            "participants": [
                {
                    "id": p.pk,
                    "display_name": p.display_name,
                    "public_key": p.public_key,
                }
                for p in active
            ]
        }, status=200)


class GetMessagesView(APIView):
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        """
        GET /chat/get-messages/<chat_id>/
        Returns the encrypted messages visible to the requesting participant,
        plus roster/status metadata. Public keys are fetched separately via
        GetChatParticipantsView (needed fresh right before every send anyway,
        to include last-second joiners) rather than duplicated here.
        """
        chat = get_object_or_404(Chat, pin=chat_id)
        me = request.user
        if me.chat_id != chat.pk:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        active_participants = list(chat.participants.filter(left_at__isnull=True))
        if not any(p.pk == me.pk for p in active_participants):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        others = [p for p in active_participants if p.pk != me.pk]
        partner = others[0] if len(others) == 1 else None

        messages_qs = chat.messages.order_by("timestamp").prefetch_related("wrapped_keys")
        serializer_data = MessageSerializer(messages_qs, many=True, context={'request': request}).data

        return Response({
            "messages":                    serializer_data,
            "others":                      [{"id": p.pk, "display_name": p.display_name} for p in others],
            "partner":                     partner.display_name if partner else None,
            "partner_id":                  partner.pk if partner else None,
            "current_user":                me.display_name,
            "current_user_id":             me.pk,
            "both_joined":                 len(active_participants) >= 2,
            "is_group":                    chat.is_group,
            "max_participants":            chat.max_participants,
        }, status=status.HTTP_200_OK)

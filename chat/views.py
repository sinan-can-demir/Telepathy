import secrets
from rest_framework.views import APIView
from rest_framework import status, permissions
from .serializers import MessageSerializer
import logging
from collections import defaultdict
import time
from django.shortcuts import render, redirect
from rest_framework.response import Response
from .auth import ParticipantTokenAuthentication
from .realtime import notify_chat
from . import services


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


def _client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))


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
        if not services.is_valid_rsa_public_key_pem(public_key):
            return Response({"message": "public_key must be a 2048-bit RSA public key in SPKI PEM form."}, status=400)

        display_name = request.data.get("display_name") or f"Participant-{secrets.token_hex(2)}"
        if not services.is_valid_display_name(display_name):
            return Response({"message": "Invalid display name."}, status=400)

        raw_max_participants = request.data.get("max_participants", 2)
        try:
            max_participants = int(raw_max_participants)
        except (TypeError, ValueError):
            return Response({"message": "max_participants must be an integer."}, status=400)
        if not (2 <= max_participants <= 8):
            return Response({"message": "max_participants must be between 2 and 8."}, status=400)

        try:
            chat, participant, raw_token = services.create_chat(display_name, public_key, max_participants)
        except services.NoFreePin:
            return Response({"message": "No chat PINs are free right now. Try again later."}, status=503)
        # Logged by public id only: the PIN is the join secret (T-12).
        logger.info(f"[CREATE-CHAT] Created {chat}.")

        # chat_id is the address the client uses from here on; the PIN is
        # only for sharing with whoever should join (#101 stage 1).
        return Response(
            {"chat_id": chat.public_id, "pin": chat.pin, "participant_token": raw_token,
             "participant_id": participant.pk},
            status=201,
        )


class JoinChatView(APIView):
    """
    POST /chat/join-chat/
    No account needed. Expects JSON: { "pin": "<4-digit PIN>",
    "display_name": "...", "public_key": "..." }
    Returns: { "chat_id": "<public id>", "participant_token": "<raw token>",
    "participant_id": <int> } -- chat_id is the chat's address from then on.
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        pin = request.data.get("pin")
        if not pin:
            return Response({"message": "PIN is required."}, status=400)

        public_key = request.data.get("public_key")
        if not services.is_valid_rsa_public_key_pem(public_key):
            return Response({"message": "public_key must be a 2048-bit RSA public key in SPKI PEM form."}, status=400)

        display_name = request.data.get("display_name") or f"Participant-{secrets.token_hex(2)}"
        if not services.is_valid_display_name(display_name):
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
            chat = services.get_chat_by_pin(pin)
        except services.ChatNotFound:
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

        try:
            participant, raw_token = services.join_chat(chat, display_name, public_key)
        except services.ChatFull:
            return Response({"message": "Chat is full."}, status=400)
        except services.DisplayNameTaken:
            return Response({"message": "Someone in this chat already uses that name. Pick another."}, status=409)

        logger.info(f"[JOIN-CHAT] '{display_name}' joined chat '{chat.public_id}'.")
        notify_chat(chat.public_id, "roster_changed")
        return Response(
            {"chat_id": chat.public_id, "participant_token": raw_token, "participant_id": participant.pk},
            status=200,
        )


class LeaveChatView(APIView):
    """Marks the calling participant as left, hard-deleting the chat once it
    fully empties (cascades to its participants/messages/keys). request.user
    IS the participant (via ParticipantTokenAuthentication) -- no separate
    lookup needed."""
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        chat_id = request.data.get("chat_id", None)
        participant = request.user

        try:
            chat_deleted, remaining = services.leave_chat(participant, chat_id)
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)
        except services.NotAParticipant:
            return Response({"message": "Not in this chat."}, status=status.HTTP_400_BAD_REQUEST)

        if chat_deleted:
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
    IssueChainKeyView/ChainKey. No per-message key is sent or stored at all:
    other participants derive it by advancing their cached copy of the
    sender's chain, and the sender keeps its own copy locally to redisplay
    its sent history (issue #99 removed the RSA self-wrap the server used to
    keep for that, since it outlived the ratchet). sender_chain_epoch records which
    epoch that derivation used, for recipients to know whether to keep
    advancing their cached state or fetch a newer epoch's seed first.

    chain_index is this message's position within the sender's current
    epoch's chain (see Message.chain_index) -- required, so a receiver can
    skip ahead over a message that never reached them.

    ttl_seconds (issue #64) is optional -- omitted or null means the
    message never expires, matching every message before this feature
    existed. See docs/MESSAGE_EXPIRY.md.
    """
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, chat_id=None):
        me = request.user

        encrypted_text = request.data.get("encrypted_text")
        aes_nonce = request.data.get("aes_nonce")
        aes_tag = request.data.get("aes_tag")
        mac = request.data.get("mac")
        prev_hash = request.data.get("prev_hash")
        sender_chain_epoch = request.data.get("sender_chain_epoch")
        chain_index = request.data.get("chain_index")
        raw_ttl_seconds = request.data.get("ttl_seconds")

        if not all([encrypted_text, aes_nonce, aes_tag, mac, prev_hash]) \
                or sender_chain_epoch is None or chain_index is None:
            return Response({"message": "Missing required encryption fields."}, status=400)

        # bool is an int subclass; reject it explicitly so `true` isn't index 1.
        # 2**31-1 is PositiveIntegerField's ceiling -- past it the DB write
        # would 500 instead of this 400.
        if isinstance(chain_index, bool) or not isinstance(chain_index, int) \
                or not 0 <= chain_index <= 2**31 - 1:
            return Response({"message": "chain_index must be a non-negative integer."}, status=400)

        ttl_seconds = None
        if raw_ttl_seconds is not None:
            try:
                ttl_seconds = int(raw_ttl_seconds)
            except (TypeError, ValueError):
                return Response({"message": "ttl_seconds must be an integer."}, status=400)

        try:
            msg = services.send_message(
                chat_id, me,
                encrypted_text=encrypted_text, aes_nonce=aes_nonce, aes_tag=aes_tag, mac=mac,
                prev_hash=prev_hash, sender_chain_epoch=sender_chain_epoch,
                chain_index=chain_index, ttl_seconds=ttl_seconds,
            )
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=404)
        except services.NotAParticipant:
            return Response({"detail": "Forbidden"}, status=403)
        except services.UnknownChainEpoch:
            return Response({"message": "Unknown sender_chain_epoch; issue a chain key first."}, status=400)
        except services.StaleChainEpoch:
            return Response(
                {"message": "sender_chain_epoch is stale; issue a fresh chain key and resend."},
                status=400,
            )
        except services.StaleTranscript as e:
            return Response(
                {
                    "message": "Stale transcript; refresh and resend.",
                    "expected_prev_hash": e.expected_prev_hash,
                },
                status=409,
            )
        except services.InvalidTTL:
            return Response(
                {
                    "message": f"ttl_seconds must be between {services.MIN_TTL_SECONDS} and "
                               f"{services.MAX_TTL_SECONDS}.",
                },
                status=400,
            )

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

        try:
            next_epoch = services.issue_chain_key(chat_id, me, wraps)
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=404)
        except services.NotAParticipant:
            return Response({"detail": "Forbidden"}, status=403)
        except services.RosterMismatch:
            return Response(
                {"message": "wraps must cover exactly the chat's current other active participants."},
                status=400,
            )

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
        me = request.user
        try:
            chat = services.get_chat(chat_id)
            services.require_same_chat(chat, me)
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=404)
        except services.NotAParticipant:
            return Response({"detail": "Forbidden"}, status=403)

        chain_keys = services.get_latest_chain_keys_for_recipient(chat, me)
        return Response({"chain_keys": chain_keys}, status=200)


class AckChainKeyView(APIView):
    """
    POST /chat/ack-chain-key/<chat_id>/  {"sender_id": <int>, "epoch": <int>}
    The caller has stored sender_id's chain seed for `epoch` locally, so the
    server deletes its wrapped copy (and any older epoch's) -- see
    services.ack_chain_key and issue #99.
    """
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, chat_id):
        me = request.user
        sender_id = request.data.get("sender_id")
        epoch = request.data.get("epoch")
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (sender_id, epoch)):
            return Response({"message": "sender_id and epoch must be non-negative integers."}, status=400)
        try:
            chat = services.get_chat(chat_id)
            services.require_same_chat(chat, me)
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=404)
        except services.NotAParticipant:
            return Response({"detail": "Forbidden"}, status=403)

        deleted = services.ack_chain_key(chat, me, sender_id, epoch)
        return Response({"deleted": deleted}, status=200)


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
        me = request.user
        try:
            chat = services.get_chat(chat_id)
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=404)

        active = services.get_active_participants(chat)
        try:
            services.require_active_participant(chat, me, active=active)
        except services.NotAParticipant:
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
        me = request.user
        try:
            chat = services.get_chat(chat_id)
            services.require_same_chat(chat, me)
        except services.ChatNotFound:
            return Response({"message": "Chat not found."}, status=404)
        except services.NotAParticipant:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        active_participants = services.get_active_participants(chat)
        try:
            services.require_active_participant(chat, me, active=active_participants)
        except services.NotAParticipant:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        others = [p for p in active_participants if p.pk != me.pk]
        partner = others[0] if len(others) == 1 else None

        # Disappearing messages (issue #64): sweep first so a message that
        # just crossed its TTL for everyone is served already-tombstoned,
        # then record this fetch as *this* participant having read whatever
        # comes back -- see services.sweep_expired_messages/mark_messages_read.
        services.sweep_expired_messages(chat)
        messages = list(chat.messages.order_by("timestamp"))
        services.mark_messages_read(chat, me, messages)
        serializer_data = MessageSerializer(messages, many=True, context={'request': request}).data

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
            # Only for showing members what to share with someone joining.
            "pin":                         chat.pin,
        }, status=status.HTTP_200_OK)

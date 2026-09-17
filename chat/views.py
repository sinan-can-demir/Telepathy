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
from .models import Chat, ChatParticipant
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from rest_framework.response import Response
from .auth import ParticipantTokenAuthentication, hash_token


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


def _client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))


def _issue_participant(chat, display_name, public_key, signing_public_key):
    """Creates a ChatParticipant with a fresh bearer token and returns
    (participant, raw_token). The raw token is never stored -- only its hash
    is -- and this is the only place in the app it's ever computed."""
    raw_token = secrets.token_urlsafe(32)
    participant = ChatParticipant.objects.create(
        chat=chat,
        display_name=display_name,
        public_key=public_key,
        signing_public_key=signing_public_key,
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
    chat_id = request.session.get("chat_id")

    try:
        chat = Chat.objects.get(pin=chat_id)
    except Chat.DoesNotExist:
        return redirect("/chat/usermenu/")
    participants = list(
        chat.participants.filter(left_at__isnull=True)
        .order_by("joined_at")
        .values_list("display_name", flat=True)
    )

    context = {
        "chat_id": chat_id,
        "participants": participants,
    }
    return render(request, "chatbox.html", context)


class CreateChatView(APIView):
    """
    POST /chat/create-chat/
    No account needed -- this *is* the entry point. Optionally accepts
    { "display_name": "...", "max_participants": <2-8>, "public_key": "...",
      "signing_public_key": "..." }.
    Returns: { "chat_id": "<4-digit PIN>", "participant_token": "<raw token>" }
    (the token is shown exactly once and never recoverable afterward).
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        public_key = request.data.get("public_key")
        if not public_key:
            return Response({"message": "public_key is required."}, status=400)

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
            chat, display_name, public_key, request.data.get("signing_public_key")
        )
        logger.info(f"[CREATE-CHAT] Created chat {chat}, PIN: {chat.pin}")

        request.session["chat_id"] = chat.pin
        return Response(
            {"chat_id": pin, "participant_token": raw_token, "participant_id": participant.pk},
            status=201,
        )


class JoinChatView(APIView):
    """
    POST /chat/join-chat/
    No account needed. Expects JSON: { "chat_id": "<4-digit-PIN>",
    "display_name": "...", "public_key": "...", "signing_public_key": "..." }
    Returns: { "participant_token": "<raw token>", "participant_id": <int> }
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        chat_id = request.data.get("chat_id")
        if not chat_id:
            return Response({"message": "Chat ID is required."}, status=400)

        public_key = request.data.get("public_key")
        if not public_key:
            return Response({"message": "public_key is required."}, status=400)

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
            chat, display_name, public_key, request.data.get("signing_public_key")
        )
        request.session["chat_id"] = chat.pin
        logger.info(f"[JOIN-CHAT] '{display_name}' joined chat '{chat_id}'.")
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
    """Marks the calling participant as left, clearing history once the chat
    fully empties. request.user IS the participant (via
    ParticipantTokenAuthentication) -- no separate lookup needed."""
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
            chat.is_active = False
            chat.save(update_fields=["is_active"])
            chat.messages.all().delete()
            logger.info(f"[LEAVE-CHAT] Chat '{chat_id}' emptied; history cleared.")
        else:
            logger.info(f"[LEAVE-CHAT] A participant left chat '{chat_id}'; {remaining} remain.")

        return Response({"message": "Left chat."}, status=status.HTTP_200_OK)


class SendMessageView(APIView):
    authentication_classes = [ParticipantTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, chat_id=None):
        chat = get_object_or_404(Chat, pin=chat_id)
        me = request.user
        if me.chat_id != chat.pk or me.left_at is not None:
            return Response({"detail": "Forbidden"}, status=403)

        encrypted_text = request.data.get("encrypted_text")
        aes_nonce = request.data.get("aes_nonce")
        aes_tag = request.data.get("aes_tag")
        signature = request.data.get("signature")
        wrapped_keys = request.data.get("wrapped_keys")

        if not all([encrypted_text, aes_nonce, aes_tag, signature]) or not wrapped_keys:
            return Response({"message": "Missing required encryption fields."}, status=400)

        active_participant_ids = set(
            chat.participants.filter(left_at__isnull=True).values_list("id", flat=True)
        )
        submitted = {
            wk.get("recipient_id"): wk.get("encrypted_symmetric_key")
            for wk in wrapped_keys
            if wk.get("recipient_id") is not None and wk.get("encrypted_symmetric_key")
        }
        if not active_participant_ids.issubset(submitted.keys()):
            return Response({"message": "Missing wrapped key for a chat participant."}, status=400)

        msg = Message.objects.create(
            chat=chat,
            sender=me,
            encrypted_text=encrypted_text,
            aes_nonce=aes_nonce,
            aes_tag=aes_tag,
            signature=signature,
        )
        MessageKey.objects.bulk_create([
            MessageKey(message=msg, recipient_id=recipient_id, encrypted_symmetric_key=key)
            for recipient_id, key in submitted.items()
            if recipient_id in active_participant_ids
        ])

        return Response(MessageSerializer(msg, context={"request": request}).data, status=201)


class GetChatParticipantsView(APIView):
    """
    GET /chat/get-chat-participants/<chat_id>/
    Returns every active participant's id/display_name/public keys, so the
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
                    "signing_public_key": p.signing_public_key,
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
        plus the other participant's public keys inline (for a 1:1 chat) so
        the frontend needs no separate "get public key" call.
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
            "partner_public_key":          partner.public_key if partner else None,
            "partner_signing_public_key":  partner.signing_public_key if partner else None,
            "current_user":                me.display_name,
            "current_user_id":             me.pk,
            "both_joined":                 len(active_participants) >= 2,
            "is_group":                    chat.is_group,
            "max_participants":            chat.max_participants,
        }, status=status.HTTP_200_OK)

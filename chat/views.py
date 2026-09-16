from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView
from .serializers import UserSerializer, MessageSerializer
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from .models import Message, MessageKey
import logging
import pyotp
import qrcode
import io
import base64
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from collections import defaultdict
import re
import random
import time
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import Chat, ChatParticipant
from django.utils import timezone
from django.shortcuts import get_object_or_404
from .models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication
from rest_framework.authentication import TokenAuthentication


# Track failed login attempts per IP: {ip: (last_attempt_time, wait_time)}
failed_login_ips = defaultdict(lambda: {'last_time': 0, 'wait_time': 0, 'fail_count': 0})

# Track failed registration attempts per IP
failed_register_ips = defaultdict(lambda: {'last_time': 0, 'wait_time': 0, 'fail_count': 0})
# Track failed chat-join attempts per user, to slow brute-forcing the 4-digit PIN space
failed_join_attempts = defaultdict(lambda: {'last_time': 0, 'wait_time': 0, 'fail_count': 0})

logger = logging.getLogger(__name__)


def _record_registration_failure(entry, now_time, message, http_status):
    """Bumps the per-IP failure counter and returns the response to send:
    either the specific failure message, or a 429 once the threshold is crossed."""
    entry["fail_count"] += 1
    if entry["fail_count"] >= 5:
        entry["wait_time"] = entry["wait_time"] * 2 if entry["wait_time"] else 10
        entry["last_time"] = now_time
        return Response(
            {"message": f"Too many registration attempts. Try again in {entry['wait_time']} seconds."},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )
    return Response({"message": message}, status=http_status)


# Home Page View - renders index.html
def home(request):
    return render(request, "index.html")


# Authentication Page View (Login/Register UI) - renders auth.html
@ensure_csrf_cookie
def auth_page(request):
    return render(request, "auth.html")


def user_menu(request):
    return render(request, "usermenu.html")


# Chatbox Page View - renders chatbox.html
def chatbox(request):
    username = request.user.username
    chat_id = request.session.get("chat_id")

    try:
        chat = Chat.objects.get(pin=chat_id)
    except Chat.DoesNotExist:
        return redirect("/chat/usermenu/")
    participants = list(
        chat.participants.filter(left_at__isnull=True)
        .order_by("joined_at")
        .values_list("user__username", flat=True)
    )

    context = {
        "chat_id": chat_id,
        "username": username,
        "participants": participants,
    }
    return render(request, "chatbox.html", context)



class RegisterUserView(CreateAPIView):
    """
    Registration now *requires* the client to send their public_key PEM.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        public_key = request.data.get("public_key")
        signing_public_key = request.data.get("signing_public_key")

        # —— Rate limiting by IP ——
        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))
        now_time = time.time()
        entry = failed_register_ips[ip]
        if entry["fail_count"] >= 5 and now_time < entry["last_time"] + entry["wait_time"]:
            wait_remaining = int(entry["last_time"] + entry["wait_time"] - now_time)
            return Response(
                {"message": f"Too many registration attempts. Try again in {wait_remaining} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # Basic input validation
        if not username or not is_valid_username(username):
            return _record_registration_failure(
                entry, now_time, "Username contains invalid characters.", status.HTTP_400_BAD_REQUEST
            )
        if not password:
            return _record_registration_failure(
                entry, now_time, "Password cannot be empty.", status.HTTP_400_BAD_REQUEST
            )

        try:
            validate_password(password)
        except DjangoValidationError as e:
            return _record_registration_failure(
                entry, now_time, list(e.messages), status.HTTP_400_BAD_REQUEST
            )

        if not public_key:
            return _record_registration_failure(
                entry, now_time, "Public key is required.", status.HTTP_400_BAD_REQUEST
            )

        # Very basic PEM‐format validation
        if not public_key.startswith("-----BEGIN PUBLIC KEY-----") or not public_key.endswith(
                "-----END PUBLIC KEY-----"
        ):
            return _record_registration_failure(
                entry, now_time, "Invalid public key format.", status.HTTP_400_BAD_REQUEST
            )

        try:
            # Attempt to load it to confirm it's a valid PEM
            from cryptography.hazmat.primitives import serialization

            serialization.load_pem_public_key(public_key.encode())
        except Exception as e:
            logger.warning(f"[REGISTER] Invalid public key provided: {e}")
            return _record_registration_failure(
                entry, now_time, "Invalid public key.", status.HTTP_400_BAD_REQUEST
            )

        logger.info(f"[REGISTER] New registration request for username: {username}")
        if User.objects.filter(username=username).exists():
            return _record_registration_failure(
                entry, now_time, "Username already exists.", status.HTTP_400_BAD_REQUEST
            )

        # Reset the failure record for this IP on success
        failed_register_ips.pop(ip, None)

        user = User(
                username=username,
                public_key=public_key,
                signing_public_key=signing_public_key
        )
        user.set_password(password)
        user.save()
        logger.info(f"[REGISTER] User created with client‐provided public key: {username}")

        return Response({"message": "Registration successful!"}, status=status.HTTP_201_CREATED)


def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None


class LoginView(APIView):
    """
    Expects JSON body: { "username": "...", "password": "...", "otp_code": "..." (optional) }
    On success, calls django_login() → sets sessionid cookie, and returns a DRF token for future AJAX calls.
    """
    authentication_classes = [SessionAuthentication]
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        otp_code = request.data.get("otp_code", None)

        if not username or not password:
            return Response(
                {"message": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST
            )

        # —— Rate limiting by IP ——
        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown"))
        now_time = time.time()
        entry = failed_login_ips[ip]
        if entry["fail_count"] >= 3 and now_time < entry["last_time"] + entry["wait_time"]:
            wait_remaining = int(entry["last_time"] + entry["wait_time"] - now_time)
            return Response(
                {"message": f"Too many failed attempts. Try again in {wait_remaining} seconds."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        logger.info(f"[LOGIN] Attempt login for '{username}' from IP {ip}")
        user = authenticate(username=username, password=password)
        if not user:
            entry["fail_count"] += 1
            if entry["fail_count"] >= 3:
                entry["wait_time"] = entry["wait_time"] * 2 if entry["wait_time"] else 10
                entry["last_time"] = now_time
                logger.warning(f"[LOGIN] IP {ip} exceeded login attempts. Timeout started for {entry['wait_time']}s")
                return Response(
                    {"message": f"Too many failed attempts. Try again in {entry['wait_time']} seconds."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            remaining_attempts = max(0, 2 - entry["fail_count"])
            logger.warning(f"[LOGIN] Invalid credentials for '{username}'.")
            return Response(
                {"message": f"Invalid username or password. Remaining attempts before timeout: {remaining_attempts}"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # —— 2FA check, BEFORE establishing a session or issuing a token ——
        if getattr(user, "is_2fa_enabled", False):
            totp = pyotp.TOTP(user.totp_secret)
            if not otp_code or not totp.verify(otp_code):
                logger.warning(f"[LOGIN] Invalid or missing 2FA code for '{username}'.")
                return Response(
                    {"detail": "Invalid or missing 2FA code."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

        # Reset the failure record for this IP on full success
        failed_login_ips.pop(ip, None)

        django_login(request, user)

        # Issue (or retrieve) the DRF token
        token, _ = Token.objects.get_or_create(user=user)
        logger.info(f"[LOGIN] User '{username}' authenticated successfully.")
        return Response(
            {
                "token": token.key,
                "public_key_exists": bool(user.public_key),
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    """
    POST /chat/logout/
    Deletes the user's DRF token and clears the Django session,
    making the old token immediately invalid server-side.
    """
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Delete the DRF token so it can never be reused
            request.user.auth_token.delete()
        except Exception:
            pass
        # Also clear the Django session
        django_logout(request)
        logger.info(f"[LOGOUT] User '{request.user.username}' logged out.")
        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)

class UploadPublicKeyView(APIView):
    """
    Accepts a JSON body:
      {
         "public_key": "<PEM string for RSA-OAEP encryption>",
         "signing_public_key": "<PEM string for RSA-PSS signature verification>"
      }
    and updates the currently authenticated user's keys.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Extract both PEMs
        encryption_pem = request.data.get("public_key")
        signing_pem = request.data.get("signing_public_key")

        if not encryption_pem:
            return Response(
                {"detail": "Missing public_key in request body."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = request.user

        # Save the encryption key
        user.public_key = encryption_pem

        # Save the signing key if provided
        if signing_pem:
            user.signing_public_key = signing_pem

        user.save(update_fields=["public_key", "signing_public_key"])
        logger.info(f"[UPLOAD-KEY] Saved keys for user '{user.username}'.")
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


class UserMenuView(APIView):
    """
    Returns a small JSON object (or HTML template) listing user's options.
    Protected by session authentication.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response(
            {
                "message": f"Welcome, {user.username}!",
                "actions": {
                    "create_chat": "/chat/create-chat/",
                    "join_chat": "/chat/join-chat/",
                    "logout": "/chat/logout/",
                },
            }
        )


class CreateChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Create a new 4-digit PIN for a chat and save to database.
        Returns: { "chat_id": "<4-digit-string>" }
        """
        # Generate a unique 4-digit PIN
        while True:
            pin = f"{random.randint(0, 9999):04d}"
            if not Chat.objects.filter(pin=pin).exists():
                break

        # Create database record
        chat = Chat.objects.create(pin=pin)
        ChatParticipant.objects.create(chat=chat, user=request.user)
        logger.info(f"[CREATE-CHAT] Created chat {chat}, PIN: {chat.pin}")

        request.session["chat_id"] = chat.pin
        logger.info(f"[CREATE-CHAT] PIN '{pin}' created by '{request.user.username}'.")
        return Response({"chat_id": pin}, status=201)


class JoinChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Join an existing chat by PIN.
        Expects JSON: { "chat_id": "<4-digit-PIN>" }
        """
        chat_id = request.data.get("chat_id")
        logger.info(f"[JOIN-CHAT] Incoming join request for PIN: {chat_id!r}")
        if not chat_id:
            logger.warning("[JOIN-CHAT] No 'chat_id' provided in payload.")
            return Response({"message": "Chat ID is required."}, status=400)

        user = request.user

        # —— Rate limiting per user, to slow brute-forcing the 4-digit PIN space ——
        entry = failed_join_attempts[user.pk]
        now_time = time.time()
        if entry["fail_count"] >= 5 and now_time < entry["last_time"] + entry["wait_time"]:
            wait_remaining = int(entry["last_time"] + entry["wait_time"] - now_time)
            return Response(
                {"message": f"Too many failed join attempts. Try again in {wait_remaining} seconds."},
                status=429,
            )

        #  Look up the Chat
        try:
            chat = Chat.objects.get(pin=chat_id)
            logger.info(f"[JOIN-CHAT] Chat found: {chat} (id={chat.pk})")
        except Chat.DoesNotExist:
            entry["fail_count"] += 1
            if entry["fail_count"] >= 5:
                entry["wait_time"] = entry["wait_time"] * 2 if entry["wait_time"] else 10
                entry["last_time"] = now_time
                logger.warning(f"[JOIN-CHAT] User '{user.username}' exceeded join attempts. Timeout started for {entry['wait_time']}s")
                return Response(
                    {"message": f"Too many failed join attempts. Try again in {entry['wait_time']} seconds."},
                    status=429,
                )
            logger.warning(f"[JOIN-CHAT] No chat matching PIN={chat_id}")
            return Response({"message": "Chat not found."}, status=404)

        # Reset the failure record for this user on a successful PIN lookup
        failed_join_attempts.pop(user.pk, None)

        logger.debug(f"[JOIN-CHAT] Current user: {user.username} (id={user.pk})")

        #  Persist the user as a participant, respecting the chat's capacity
        active_participants = chat.participants.filter(left_at__isnull=True)
        if active_participants.filter(user=user).exists():
            logger.info(f"[JOIN-CHAT] '{user.username}' was already in this chat.")
        elif active_participants.count() >= chat.max_participants:
            logger.warning(f"[JOIN-CHAT] Chat {chat_id} is already full.")
            return Response({"message": "Chat is full."}, status=400)
        else:
            ChatParticipant.objects.create(chat=chat, user=user)
            logger.info(f"[JOIN-CHAT] Assigned '{user.username}' to chat '{chat_id}'.")

        #  Store chat_id in session so GetMessagesView sees it
        request.session["chat_id"] = chat.pin
        logger.debug(f"[JOIN-CHAT] chat_id stored in session.")

        logger.info(f"[JOIN-CHAT] User '{user.username}' successfully joined chat '{chat_id}'.")
        return Response({"message": "Joined chat successfully."}, status=200)


# Check Active Chat View
class CheckChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        try:
            chat = Chat.objects.get(pin=chat_id)
            participants = list(
                chat.participants.filter(left_at__isnull=True)
                .order_by("joined_at")
                .values_list("user__username", flat=True)
            )
            return Response({"exists": True, "participants": participants}, status=status.HTTP_200_OK)
        except Chat.DoesNotExist:
            return Response({"exists": False}, status=status.HTTP_404_NOT_FOUND)


# Leave Chat View - marks the participant as left, clearing history once the chat fully empties
class LeaveChatView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        chat_id = request.data.get("chat_id", None)

        try:
            chat = Chat.objects.get(pin=chat_id)
        except Chat.DoesNotExist:
            return Response({"message": "Chat not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            participant = chat.participants.get(user=request.user, left_at__isnull=True)
        except ChatParticipant.DoesNotExist:
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
            logger.info(
                f"[LEAVE-CHAT] User '{request.user.username}' left chat '{chat_id}'; "
                f"{remaining} participant(s) remain."
            )

        return Response({"message": "Left chat."}, status=status.HTTP_200_OK)


class GetPublicKeyView(APIView):
    """
    GET /chat/get-public-key/<user_id>/
    Returns JSON:
      {
        "public_key": "<PEM for RSA-OAEP encryption>",
        "signing_public_key": "<PEM for RSA-PSS verification>"
      }
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, user_id, *args, **kwargs):
        # Look up the target user
        target = get_object_or_404(User, pk=user_id)

        if not target.public_key:
            return Response(
                {"detail": "No encryption public_key stored for this user."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Build response with both keys (signing key may be None)
        response_data = {
            "public_key": target.public_key,
            "signing_public_key": target.signing_public_key
        }

        logger.debug(f"[GET-KEY] Returning keys for user_id={user_id}")
        return Response(response_data, status=status.HTTP_200_OK)


class SendMessageView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, chat_id=None):
        chat = get_object_or_404(Chat, pin=chat_id)
        me = request.user
        if not chat.participants.filter(user=me, left_at__isnull=True).exists():
            return Response({"detail": "Forbidden"}, status=403)

        # Extract ALL required cryptographic fields
        encrypted_text = request.data.get("encrypted_text")
        aes_nonce = request.data.get("aes_nonce")
        aes_tag = request.data.get("aes_tag")
        signature = request.data.get("signature")
        wrapped_keys = request.data.get("wrapped_keys")

        # Validate presence
        if not all([encrypted_text, aes_nonce, aes_tag, signature]) or not wrapped_keys:
            return Response(
                {"message": "Missing required encryption fields."},
                status=400
            )

        active_participant_ids = set(
            chat.participants.filter(left_at__isnull=True).values_list("user_id", flat=True)
        )
        submitted = {
            wk.get("recipient_id"): wk.get("encrypted_symmetric_key")
            for wk in wrapped_keys
            if wk.get("recipient_id") is not None and wk.get("encrypted_symmetric_key")
        }
        if not active_participant_ids.issubset(submitted.keys()):
            return Response(
                {"message": "Missing wrapped key for a chat participant."},
                status=400
            )

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


class GetMessagesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes= [permissions.IsAuthenticated]

    def get(self, request, chat_id):
        """
        GET /chat/get-messages/<chat_id>/
        Returns the encrypted messages visible to the requesting participant.
        """
        # 1) Load (or 404) the Chat by its 4-digit PIN
        chat = get_object_or_404(Chat, pin=chat_id)

        # 2) Verify the requesting user is an active participant
        me = request.user
        active_participants = list(
            chat.participants.filter(left_at__isnull=True).select_related("user")
        )
        if not any(p.user_id == me.id for p in active_participants):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # 3) Determine who the "partner" is (only meaningful for a 1:1 chat)
        others = [p.user for p in active_participants if p.user_id != me.id]
        partner = others[0] if len(others) == 1 else None

        # 4) Fetch every Message in this chat
        messages_qs = chat.messages.order_by("timestamp").prefetch_related("wrapped_keys")

        # 5) Serialize those messages
        serializer_data = MessageSerializer(messages_qs, many=True, context={'request': request}).data

        # 6) Return JSON (including partner's username/id and "both_joined" flag)
        return Response({
            "messages":        serializer_data,
            "partner":         partner.username if partner else None,
            "partner_id":      partner.id if partner else None,
            "current_user":    me.username,
            "current_user_id": me.id,
            "both_joined":     len(active_participants) >= 2,
        }, status=status.HTTP_200_OK)


@login_required
def setup_2fa(request):
    user = request.user

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save()

    totp = pyotp.TOTP(user.totp_secret)
    otp_uri = totp.provisioning_uri(name=user.username, issuer_name='Secure Chat')

    qr_img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    qr_data = base64.b64encode(buffer.getvalue()).decode()

    if request.method == 'POST':
        code = request.POST.get('otp_code')
        if totp.verify(code):
            user.is_2fa_enabled = True
            user.save()
            messages.success(request, '2FA activated successfully.')
            return redirect('usermenu')
        else:
            messages.error(request, 'Invalid code, please try again.')

    return render(request, 'chat/2fa_setup.html', {
        'qr_data': qr_data,
    })
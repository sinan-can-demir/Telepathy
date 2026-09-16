import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from rest_framework import status

from chat.views import failed_login_attempts, failed_register_ips, failed_join_attempts

User = get_user_model()


def _fake_public_key_pem():
    # .strip() matches the client's arrayBufferToPem(), which emits PEM with
    # no trailing newline -- RegisterUserView's format check is exact-match.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode().strip()


class LoginSecurityTests(TestCase):
    """Regression coverage for the 2FA-bypass and rate-limiting removal
    found in the final-clientside audit. Login throttling is keyed by the
    targeted username, not the client's source IP -- see failed_login_attempts
    in chat/views.py for why (a Tor hidden-service deployment collapses every
    client to the same source address)."""

    def setUp(self):
        failed_login_attempts.clear()
        self.client = APIClient()

    def test_login_without_2fa_works(self):
        User.objects.create_user(
            username="plainuser",
            password="a-strong-unguessable-pass1",
            public_key=_fake_public_key_pem(),
        )
        response = self.client.post(
            "/chat/login/",
            {"username": "plainuser", "password": "a-strong-unguessable-pass1"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)

    def test_missing_otp_rejected_for_2fa_user(self):
        secret = pyotp.random_base32()
        User.objects.create_user(
            username="twofauser",
            password="a-strong-unguessable-pass1",
            public_key=_fake_public_key_pem(),
            is_2fa_enabled=True,
            totp_secret=secret,
        )
        response = self.client.post(
            "/chat/login/",
            {"username": "twofauser", "password": "a-strong-unguessable-pass1"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("2fa", response.data["detail"].lower())

    def test_correct_otp_logs_in(self):
        secret = pyotp.random_base32()
        User.objects.create_user(
            username="twofauser2",
            password="a-strong-unguessable-pass1",
            public_key=_fake_public_key_pem(),
            is_2fa_enabled=True,
            totp_secret=secret,
        )
        code = pyotp.TOTP(secret).now()
        response = self.client.post(
            "/chat/login/",
            {"username": "twofauser2", "password": "a-strong-unguessable-pass1", "otp_code": code},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)

    def test_repeated_failed_logins_are_rate_limited(self):
        User.objects.create_user(
            username="ratetarget",
            password="a-strong-unguessable-pass1",
            public_key=_fake_public_key_pem(),
        )
        for _ in range(2):
            response = self.client.post(
                "/chat/login/",
                {"username": "ratetarget", "password": "wrong-password"},
                format="json",
            )
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # The 3rd failure crosses the threshold and starts the cooldown immediately.
        response = self.client.post(
            "/chat/login/",
            {"username": "ratetarget", "password": "wrong-password"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        # Even the correct password is throttled during the cooldown window.
        response = self.client.post(
            "/chat/login/",
            {"username": "ratetarget", "password": "a-strong-unguessable-pass1"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_throttle_is_keyed_per_username_not_per_source(self):
        """The Django test client always reports the same source address for
        every request; if throttling were still IP-keyed this test would fail
        because 'other_target's failures would already have tripped the
        cooldown. Proves the fix actually applies to a shared-source scenario
        (e.g. every client behind a Tor hidden service looking like one IP)."""
        for username in ("target_one", "target_two"):
            User.objects.create_user(
                username=username,
                password="a-strong-unguessable-pass1",
                public_key=_fake_public_key_pem(),
            )

        for _ in range(3):
            response = self.client.post(
                "/chat/login/",
                {"username": "target_one", "password": "wrong-password"},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        # target_two has had zero failed attempts of its own, so a correct
        # login for it must succeed even though target_one is cooling down.
        response = self.client.post(
            "/chat/login/",
            {"username": "target_two", "password": "a-strong-unguessable-pass1"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class RegistrationValidationTests(TestCase):
    """Regression coverage for #9/#10: registration must enforce Django's
    password validators and rate-limit repeated failures by IP."""

    def setUp(self):
        failed_register_ips.clear()
        self.client = APIClient()

    def _register(self, username="newuser", password="a-strong-unguessable-pass1"):
        return self.client.post(
            "/chat/register/",
            {"username": username, "password": password, "public_key": _fake_public_key_pem()},
            format="json",
        )

    def test_weak_password_rejected(self):
        response = self._register(password="123")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_strong_password_accepted(self):
        response = self._register()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_repeated_failed_registrations_are_rate_limited(self):
        for _ in range(4):
            response = self._register(username="rateuser", password="123")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # The 5th failure crosses the threshold and starts the cooldown immediately.
        response = self._register(username="rateuser", password="123")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        # Even a valid registration is throttled during the cooldown window.
        response = self._register(username="rateuser2")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        
        
class JoinChatRateLimitTests(TestCase):
    """Regression coverage for #20: brute-forcing the 4-digit chat PIN
    space via repeated JoinChatView calls must be throttled."""

    def setUp(self):
        failed_join_attempts.clear()
        user = User.objects.create_user(
            username="joiner",
            password="a-strong-unguessable-pass1",
            public_key=_fake_public_key_pem(),
        )
        token, _ = Token.objects.get_or_create(user=user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

    def test_repeated_wrong_pins_are_rate_limited(self):
        for _ in range(4):
            response = self.client.post("/chat/join-chat/", {"chat_id": "0000"}, format="json")
            self.assertEqual(response.status_code, 404)

        # The 5th failed guess crosses the threshold and starts the cooldown immediately.
        response = self.client.post("/chat/join-chat/", {"chat_id": "0000"}, format="json")
        self.assertEqual(response.status_code, 429)

        # Even a real PIN is throttled during the cooldown window.
        from chat.models import Chat
        other = User.objects.create_user(
            username="creator",
            password="a-strong-unguessable-pass1",
            public_key=_fake_public_key_pem(),
        )
        Chat.objects.create(pin="1234")
        response = self.client.post("/chat/join-chat/", {"chat_id": "1234"}, format="json")
        self.assertEqual(response.status_code, 429)


class GroupChatSchemaTests(TestCase):
    """Regression coverage for the Phase 1 ChatParticipant/MessageKey schema
    migration (#34/#38): a 1:1 chat must behave identically to the old
    user1/user2 + sender/receiver model from the caller's point of view."""

    def setUp(self):
        self.alice = APIClient()
        self.bob = APIClient()
        for username, client in (("alice", self.alice), ("bob", self.bob)):
            User.objects.create_user(
                username=username,
                password="a-strong-unguessable-pass1",
                public_key=_fake_public_key_pem(),
            )
            token, _ = Token.objects.get_or_create(user=User.objects.get(username=username))
            client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.alice_id = User.objects.get(username="alice").id
        self.bob_id = User.objects.get(username="bob").id

    def test_round_trip_creates_one_message_and_two_keys(self):
        from chat.models import Message, MessageKey

        create = self.alice.post("/chat/create-chat/", format="json")
        self.assertEqual(create.status_code, 201)
        chat_id = create.data["chat_id"]

        join = self.bob.post("/chat/join-chat/", {"chat_id": chat_id}, format="json")
        self.assertEqual(join.status_code, 200)

        send = self.alice.post(
            f"/chat/send-message/{chat_id}/",
            {
                "encrypted_text": "ciphertext",
                "aes_nonce": "nonce",
                "aes_tag": "tag",
                "signature": "sig",
                "wrapped_keys": [
                    {"recipient_id": self.alice_id, "encrypted_symmetric_key": "key-for-alice"},
                    {"recipient_id": self.bob_id, "encrypted_symmetric_key": "key-for-bob"},
                ],
            },
            format="json",
        )
        self.assertEqual(send.status_code, 201, send.data)
        self.assertEqual(Message.objects.count(), 1)
        self.assertEqual(MessageKey.objects.count(), 2)

        alice_view = self.alice.get(f"/chat/get-messages/{chat_id}/")
        self.assertEqual(alice_view.data["current_user_id"], self.alice_id)
        self.assertEqual(alice_view.data["messages"][0]["my_encrypted_symmetric_key"], "key-for-alice")

        bob_view = self.bob.get(f"/chat/get-messages/{chat_id}/")
        self.assertEqual(bob_view.data["current_user_id"], self.bob_id)
        self.assertEqual(bob_view.data["messages"][0]["my_encrypted_symmetric_key"], "key-for-bob")

    def test_leave_only_clears_history_once_chat_fully_empties(self):
        from chat.models import Chat, Message

        create = self.alice.post("/chat/create-chat/", format="json")
        chat_id = create.data["chat_id"]
        self.bob.post("/chat/join-chat/", {"chat_id": chat_id}, format="json")
        self.alice.post(
            f"/chat/send-message/{chat_id}/",
            {
                "encrypted_text": "ciphertext", "aes_nonce": "n", "aes_tag": "t", "signature": "s",
                "wrapped_keys": [
                    {"recipient_id": self.alice_id, "encrypted_symmetric_key": "a"},
                    {"recipient_id": self.bob_id, "encrypted_symmetric_key": "b"},
                ],
            },
            format="json",
        )
        self.assertEqual(Message.objects.count(), 1)

        # Alice leaves; Bob remains -- history must survive.
        leave = self.alice.post("/chat/leave-chat/", {"chat_id": chat_id}, format="json")
        self.assertEqual(leave.status_code, 200)
        self.assertEqual(Message.objects.count(), 1)
        self.assertTrue(Chat.objects.get(pin=chat_id).is_active)

        # Bob leaves too; chat is now fully empty -- history is cleared.
        leave2 = self.bob.post("/chat/leave-chat/", {"chat_id": chat_id}, format="json")
        self.assertEqual(leave2.status_code, 200)
        self.assertEqual(Message.objects.count(), 0)
        self.assertFalse(Chat.objects.get(pin=chat_id).is_active)

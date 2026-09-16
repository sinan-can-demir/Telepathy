import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from rest_framework import status

from chat.views import failed_login_ips, failed_join_attempts

User = get_user_model()


def _fake_public_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


class LoginSecurityTests(TestCase):
    """Regression coverage for the 2FA-bypass and rate-limiting removal
    found in the final-clientside audit."""

    def setUp(self):
        failed_login_ips.clear()
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
        Chat.objects.create(pin="1234", user1=other)
        response = self.client.post("/chat/join-chat/", {"chat_id": "1234"}, format="json")
        self.assertEqual(response.status_code, 429)

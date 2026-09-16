import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

from chat.views import failed_login_ips, failed_register_ips

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

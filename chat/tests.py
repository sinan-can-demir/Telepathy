import os
import pyotp
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

from chat.views import failed_login_ips, failed_register_ips

User = get_user_model()
KEY_DIR = os.path.join("chat", "client", "enc_test_keygen", "static", "keys")


def _key_path(username):
    return os.path.join(KEY_DIR, f"{username}_private_key.pem")


class TwoFactorLoginTests(TestCase):
    """Regression coverage for the fix where django_login() was called before
    the OTP code was verified, letting an unverified request keep an
    authenticated session."""

    def setUp(self):
        failed_login_ips.clear()
        failed_register_ips.clear()
        self.client = APIClient()
        self.totp_secret = pyotp.random_base32()
        self.user = User.objects.create(
            username="twofauser",
            is_2fa_enabled=True,
            totp_secret=self.totp_secret,
        )
        self.user.set_password("a-strong-unguessable-pass1")
        self.user.save()

    def test_missing_otp_does_not_establish_session(self):
        response = self.client.post(
            "/chat/login/",
            {"username": "twofauser", "password": "a-strong-unguessable-pass1"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # No session should have been established: a session-authenticated,
        # login_required view must redirect rather than serve content.
        setup_response = self.client.get("/chat/2fa/setup/")
        self.assertEqual(setup_response.status_code, 302)

    def test_correct_otp_logs_in(self):
        code = pyotp.TOTP(self.totp_secret).now()
        response = self.client.post(
            "/chat/login/",
            {"username": "twofauser", "password": "a-strong-unguessable-pass1", "otp_code": code},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)


class RegistrationValidationTests(TestCase):
    def setUp(self):
        failed_login_ips.clear()
        failed_register_ips.clear()
        self.client = APIClient()

    def tearDown(self):
        for username in ("weakpassuser", "rateuser"):
            path = _key_path(username)
            if os.path.exists(path):
                os.remove(path)

    def test_weak_password_rejected(self):
        response = self.client.post(
            "/chat/register/",
            {"username": "weakpassuser", "password": "123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="weakpassuser").exists())
        self.assertFalse(os.path.exists(_key_path("weakpassuser")))

    def test_registration_rate_limited_after_repeated_failures(self):
        for _ in range(3):
            response = self.client.post(
                "/chat/register/",
                {"username": "rateuser", "password": "123"},
                format="json",
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post(
            "/chat/register/",
            {"username": "rateuser", "password": "123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)


class MessageRoundTripTests(TestCase):
    """Sanity check that send/receive still decrypts correctly after the
    2048-bit key size change and the RSA key-object caching refactor."""

    def setUp(self):
        failed_login_ips.clear()
        failed_register_ips.clear()
        self.alice = APIClient()
        self.bob = APIClient()

    def tearDown(self):
        for username in ("alice", "bob"):
            path = _key_path(username)
            if os.path.exists(path):
                os.remove(path)

    def _register_and_login(self, client, username, password):
        reg = client.post("/chat/register/", {"username": username, "password": password}, format="json")
        self.assertEqual(reg.status_code, status.HTTP_201_CREATED, reg.data)
        login = client.post("/chat/login/", {"username": username, "password": password}, format="json")
        self.assertEqual(login.status_code, status.HTTP_200_OK, login.data)
        client.credentials(HTTP_AUTHORIZATION=f"Token {login.data['token']}")

    def test_send_and_receive_decrypts_correctly(self):
        self._register_and_login(self.alice, "alice", "a-strong-unguessable-pass1")
        self._register_and_login(self.bob, "bob", "a-strong-unguessable-pass2")

        create = self.alice.post("/chat/create-chat/", format="json")
        self.assertEqual(create.status_code, status.HTTP_201_CREATED)
        chat_id = create.data["chat_id"]

        join = self.bob.post("/chat/join-chat/", {"chat_id": chat_id}, format="json")
        self.assertEqual(join.status_code, status.HTTP_200_OK)

        send = self.alice.post(
            "/chat/send-message/",
            {"chat_id": chat_id, "message": "hello bob"},
            format="json",
        )
        self.assertEqual(send.status_code, status.HTTP_200_OK, send.data)

        received = self.bob.get(f"/chat/get-messages/{chat_id}/")
        self.assertEqual(received.status_code, status.HTTP_200_OK)
        messages = received.data["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["text"], "hello bob")

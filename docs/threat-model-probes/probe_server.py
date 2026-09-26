"""Server-side probes backing docs/THREAT_MODEL.md (findings T-01, T-02, T-06, T-07,
T-08, T-16, T-19, T-30, and the positive authorization control in STRIDE). Each test prints what it observed; assertions only guard the
probe's own preconditions -- these DOCUMENT current behaviour, they are not
regression tests, and they are deliberately not named test_*.py so the normal
suite does not collect them.

Run against a THROWAWAY test database (Django creates and drops test_<DB_NAME>;
never point this at data you care about). From the repo root, with Postgres and
Redis up as for the normal test suite:

    DJANGO_SECURE=false PYTHONPATH=docs/threat-model-probes \\
        python manage.py test probe_server --noinput

Notes: the two 10,000-request sweeps (T-01, T-02) take about a minute each. The
WebSocket probe (T-19) can make Django's teardown complain that the test database
is "being accessed by other users"; drop test_<DB_NAME> by hand if it does. Probes
use Django's in-process test client, so timings are a lower bound on real cost --
the point is the ABSENCE of throttling, not the wall-clock figure.
"""
import asyncio
import time
from datetime import timedelta
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from channels.db import database_sync_to_async as dbasync
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import Resolver404, resolve
from django.utils import timezone
from rest_framework.test import APIClient

from chat import services
from chat.models import Chat, ChatParticipant, Message

_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = _k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def say(*a):
    print("   ", *a, flush=True)


class HttpProbes(TestCase):
    def setUp(self):
        self.c = APIClient()

    def _join(self, pin, **extra):
        return self.c.post("/chat/join-chat/", {"chat_id": pin, "public_key": PUB}, format="json", **extra)

    def test_1_join_limiter_bypass_and_pin_bruteforce(self):
        print("\n[1] PIN brute force vs. the join rate limiter")
        from chat import views
        views.failed_join_attempts.clear()
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "max_participants": 8, "display_name": "victim"}, format="json")
        target = r.data["chat_id"]
        say(f"victim created a group chat, PIN={target}")
        # control: same source address, no header games
        codes = [self._join(f"{9000 + i}").status_code for i in range(7)]
        say("control (one source, 7 wrong PINs) status codes:", codes)
        views.failed_join_attempts.clear()
        # attack: rotate a client-supplied X-Forwarded-For per request
        attempts, n429, found = 0, 0, None
        t0 = time.time()
        for pin in range(10000):
            attempts += 1
            ip = f"10.{(attempts >> 16) & 255}.{(attempts >> 8) & 255}.{attempts & 255}"
            resp = self._join(f"{pin:04d}", HTTP_X_FORWARDED_FOR=ip)
            if resp.status_code == 429:
                n429 += 1
            if resp.status_code == 200:
                found = f"{pin:04d}"
                break
        say(f"attacker rotating X-Forwarded-For: joined PIN {found} after {attempts} attempts, "
            f"{n429} rate-limit responses, {time.time() - t0:.1f}s")
        say(f"distinct limiter buckets created (memory grows per spoofed value): {len(views.failed_join_attempts)}")
        self.assertEqual(found, target)

    def test_2_shared_bucket_lockout(self):
        print("\n[2] One client's failures lock out everyone sharing the source address (Tor: all clients)")
        from chat import views
        views.failed_join_attempts.clear()
        victim = self.c.post("/chat/create-chat/", {"public_key": PUB}, format="json").data["chat_id"]
        for i in range(5):
            self._join(f"{8000 + i}")
        legit = self._join(victim)
        say(f"after 5 bad guesses from the shared address, a legitimate join of the VALID pin {victim} ->", legit.status_code, legit.data)
        views.failed_join_attempts.clear()

    def test_3_check_chat_enumeration(self):
        # At 123be67 this swept all 10,000 PINs in about a minute with no
        # throttling and listed every live chat's participants (T-02). The
        # endpoint was removed in #96; this now just confirms it is gone.
        print("\n[3] /check-chat/ enumeration (endpoint removed in #96)")
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "alice"}, format="json")
        try:
            resolve(f"/chat/check-chat/{r.data['chat_id']}/")
            say("/chat/check-chat/<live pin>/ still resolves (unexpected)")
        except Resolver404:
            say("/chat/check-chat/<live pin>/ -> no such route")

    def test_4_create_chat_unthrottled_and_pin_exhaustion(self):
        print("\n[4] Unauthenticated create-chat flood + PIN-space exhaustion")
        t0 = time.time()
        codes = {self.c.post("/chat/create-chat/", {"public_key": PUB}, format="json").status_code for _ in range(300)}
        say(f"300 anonymous create-chat calls in {time.time() - t0:.1f}s -> status codes {codes}")
        have = set(Chat.objects.values_list("pin", flat=True))
        Chat.objects.bulk_create([Chat(pin=f"{i:04d}") for i in range(10000) if f"{i:04d}" not in have])
        say("PIN space now full:", Chat.objects.count(), "of 10000 rows")
        calls = {"n": 0}

        def counting_randint(a, b):
            calls["n"] += 1
            if calls["n"] > 20000:
                raise RuntimeError("probe stopped it")
            return 1234
        with mock.patch("chat.services.random.randint", counting_randint):
            try:
                services.create_chat("late", PUB, 2)
                say("create_chat returned (unexpected)")
            except RuntimeError:
                say(f"services.create_chat() never terminated: {calls['n']} PIN draws with no exit condition (probe cut it off)")

    def test_5_abandoned_chat_persists(self):
        print("\n[5] Abandoned chat: nobody returns, nothing reclaims it")
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "alice"}, format="json")
        pin = r.data["chat_id"]
        j = self._join(pin, )
        chat = Chat.objects.get(pin=pin)
        alice, bob = list(chat.participants.order_by("joined_at"))
        Message.objects.create(chat=chat, sender=alice, encrypted_text="x", aes_nonce="x", aes_tag="x", mac="x", seq=0)
        ChatParticipant.objects.filter(chat=chat).update(last_seen=timezone.now() - timedelta(days=30))
        active = list(chat.participants.filter(left_at__isnull=True).values_list("display_name", flat=True))
        say(f"30 days idle, no one authenticated since: chat exists={Chat.objects.filter(pin=pin).exists()} active participants={active}")
        say("Chat rows:", Chat.objects.filter(pin=pin).count(), " Message rows:", Message.objects.filter(chat=chat).count(),
            " -> PIN still held, ciphertext still stored")
        third = self._join(pin)
        say("a third party trying to use that PIN:", third.status_code, third.data)
        # The one path that does reclaim an idle participant: their OWN next authenticated request.
        for who, tok in (("alice", r.data["participant_token"]), ("bob", j.data["participant_token"])):
            resp = APIClient().get(f"/chat/get-messages/{pin}/", HTTP_AUTHORIZATION=f"Token {tok}")
            say(f"{who} finally returns after 30 days -> {resp.status_code} (idle-expired, marked left)")
        say("after BOTH were idle-expired: Chat rows:", Chat.objects.filter(pin=pin).count(),
            " Message rows:", Message.objects.filter(chat=chat).count(),
            " active participants:", ChatParticipant.objects.filter(chat=chat, left_at__isnull=True).count())
        say("-> idle expiry sets left_at but never deletes the emptied chat (only leave_chat() does); PIN stays taken")

    def test_6_display_names_not_unique(self):
        print("\n[6] Display names are not unique within a chat")
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "alice"}, format="json")
        j = self.c.post("/chat/join-chat/", {"chat_id": r.data["chat_id"], "public_key": PUB, "display_name": "alice"}, format="json")
        say("second participant joined as the same name 'alice' ->", j.status_code)
        roster = Chat.objects.get(pin=r.data["chat_id"]).participants.values_list("display_name", flat=True)
        say("roster as stored:", list(roster))
        v = services.is_valid_display_name("alice\n")
        say("is_valid_display_name('alice\\n') =", v, "(regex '$' tolerates a trailing newline)")


@override_settings(CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}})
class WsProbes(TransactionTestCase):
    def test_8_websocket_outlives_membership(self):
        print("\n[8] WebSocket subscription vs. membership")
        from channels.routing import URLRouter
        from channels.testing import WebsocketCommunicator
        import chat.routing
        from chat.realtime import notify_chat

        app = URLRouter(chat.routing.websocket_urlpatterns)
        chat_obj, alice, tok_a = services.create_chat("alice", PUB, 2)
        bob, tok_b = services.join_chat(chat_obj, "bob", PUB)
        pin = chat_obj.pin

        async def run():
            comm = WebsocketCommunicator(app, f"/ws/chat/{pin}/", subprotocols=[tok_b])
            ok, _ = await comm.connect()
            say("bob connected:", ok)
            await dbasync(services.leave_chat)(bob, pin)
            say("bob has left the chat via services.leave_chat (left_at set); alice still there")
            await asyncio.to_thread(notify_chat, pin, "new_message")
            try:
                msg = await comm.receive_json_from(timeout=2)
                say("bob's socket STILL receives signals for the chat he left:", msg)
            except asyncio.TimeoutError:
                say("bob's socket received nothing (subscription was cut)")
            # chat emptied -> deleted -> PIN recycled to a stranger's brand-new chat
            await dbasync(services.leave_chat)(alice, pin)
            await dbasync(Chat.objects.create)(pin=pin)
            await asyncio.to_thread(notify_chat, pin, "new_message")
            try:
                msg = await comm.receive_json_from(timeout=2)
                say("after the PIN was recycled to an UNRELATED chat, bob's old socket receives:", msg)
            except asyncio.TimeoutError:
                say("old socket received nothing after PIN recycling")
            await comm.disconnect()
            # positive control: a token for THIS chat must not open a socket on another chat
            other, _, _ = await dbasync(services.create_chat)("other", PUB, 2)
            cross = WebsocketCommunicator(app, f"/ws/chat/{other.pin}/", subprotocols=[tok_a])
            ok, code = await cross.connect()
            say(f"token for chat {pin} opening a socket on chat {other.pin}: accepted={ok} (close code {code})")
            await cross.disconnect()
        asyncio.run(run())


class FormatProbes(TestCase):
    def test_9_garbage_message_fields_accepted(self):
        print("\n[9] Server validates no ciphertext field format or size")
        c = APIClient()
        a = c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "a"}, format="json").data
        b = APIClient().post("/chat/join-chat/", {"chat_id": a["chat_id"], "public_key": PUB, "display_name": "b"}, format="json").data
        h = {"HTTP_AUTHORIZATION": f"Token {a['participant_token']}"}
        r = c.post(f"/chat/issue-chain-key/{a['chat_id']}/", {"wraps": [{"recipient_id": b["participant_id"], "encrypted_seed": "!!not-a-wrapped-seed!!"}]}, format="json", **h)
        say("issue-chain-key with a garbage 'wrapped seed' ->", r.status_code)
        body = {"encrypted_text": "Z" * (5 * 1024 * 1024), "aes_nonce": "not-base64!", "aes_tag": "x", "mac": "x",
                "prev_hash": "0" * 64, "sender_chain_epoch": 0, "chain_index": 0,
                "wrapped_keys": [{"recipient_id": a["participant_id"], "encrypted_symmetric_key": "x"}]}
        r = c.post(f"/chat/send-message/{a['chat_id']}/", body, format="json", **h)
        say(f"send-message with a 5 MB non-base64 'ciphertext', junk nonce/tag/mac -> {r.status_code}; stored length {len(Message.objects.get().encrypted_text)}")


class AuthzProbes(TestCase):
    """STRIDE 'Elevation of privilege': can a token for chat A act on chat B?
    Expected (and observed): no. Kept as a positive control for the threat model."""

    def test_10_cross_chat_authorization(self):
        print("\n[10] Cross-chat authorization (token from chat A used against chat B)")
        c = APIClient()
        a = c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "a1"}, format="json").data
        b = c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "b1"}, format="json").data
        APIClient().post("/chat/join-chat/", {"chat_id": b["chat_id"], "public_key": PUB, "display_name": "b2"}, format="json")
        h = {"HTTP_AUTHORIZATION": f"Token {a['participant_token']}"}
        B = b["chat_id"]
        body = {"encrypted_text": "x", "aes_nonce": "x", "aes_tag": "x", "mac": "x", "prev_hash": "0" * 64, "sender_chain_epoch": 0,
                "chain_index": 0, "wrapped_keys": [{"recipient_id": a["participant_id"], "encrypted_symmetric_key": "x"}]}
        rows = [
            ("GET  get-messages", c.get(f"/chat/get-messages/{B}/", **h)),
            ("POST send-message", c.post(f"/chat/send-message/{B}/", body, format="json", **h)),
            ("POST issue-chain-key", c.post(f"/chat/issue-chain-key/{B}/", {"wraps": [{"recipient_id": 1, "encrypted_seed": "x"}]}, format="json", **h)),
            ("GET  get-chain-keys", c.get(f"/chat/get-chain-keys/{B}/", **h)),
            ("GET  get-chat-participants", c.get(f"/chat/get-chat-participants/{B}/", **h)),
            ("POST leave-chat (chat_id=B)", c.post("/chat/leave-chat/", {"chat_id": B}, format="json", **h)),
            ("GET  get-messages, no token", APIClient().get(f"/chat/get-messages/{B}/")),
        ]
        for name, r in rows:
            say(f"{name:32s} -> {r.status_code}")
        say("B's roster untouched:", Chat.objects.get(pin=B).participants.filter(left_at__isnull=True).count(), "active")
        # a token whose participant has left must stop working
        ChatParticipant.objects.filter(pk=a["participant_id"]).update(left_at=timezone.now())
        r = c.get(f"/chat/get-messages/{a['chat_id']}/", **h)
        say("token of a participant who has left, on their own chat ->", r.status_code)


class LoadProbes(TestCase):
    """STRIDE 'Denial of service' from an authenticated member: get-messages is
    unpaginated and sweeps every expiring message on every fetch."""

    def test_11_fetch_cost_grows_with_transcript(self):
        print("\n[11] Cost of one GET /get-messages/ as the transcript grows (expiring messages)")
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        c = APIClient()
        a = c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "a"}, format="json").data
        APIClient().post("/chat/join-chat/", {"chat_id": a["chat_id"], "public_key": PUB, "display_name": "b"}, format="json")
        chat = Chat.objects.get(pin=a["chat_id"])
        alice = chat.participants.order_by("joined_at").first()
        h = {"HTTP_AUTHORIZATION": f"Token {a['participant_token']}"}
        made = 0
        for target in (10, 500, 2000):
            Message.objects.bulk_create([
                Message(chat=chat, sender=alice, encrypted_text="x" * 300, aes_nonce="n", aes_tag="t", mac="m",
                        seq=i, ttl_seconds=3600) for i in range(made, target)])
            made = target
            with CaptureQueriesContext(connection) as q:
                t0 = time.time()
                r = c.get(f"/chat/get-messages/{a['chat_id']}/", **h)
                dt = time.time() - t0
            say(f"{target:5d} messages: {len(q):5d} SQL queries, {len(r.content) / 1024:8.0f} KiB response, {dt * 1000:7.0f} ms")
        say("every member's client repeats this on each websocket push and every 15 s; the sender pays nothing extra")

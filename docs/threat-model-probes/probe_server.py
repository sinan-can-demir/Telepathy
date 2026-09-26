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

    def _join(self, invite, name=None, **extra):
        body = {"invite": invite, "public_key": PUB}
        if name:
            body["display_name"] = name
        return self.c.post("/chat/join-chat/", body, format="json", **extra)

    @staticmethod
    def _wrong(invite):
        handle, code = services.parse_invite(invite)
        return services.format_invite(handle, ("Z" if code[0] != "Z" else "Y") + code[1:])

    def test_1_join_limiter_bypass_and_pin_bruteforce(self):
        # At 123be67: a 4-digit PIN behind a per-address limiter that trusted
        # X-Forwarded-For; rotating it joined a live chat after ~8,000 tries
        # with no throttling (T-01). Since #101 stage 2 the secret is a
        # 30-bit single-use invite code, and wrong codes are charged to the
        # invite itself: three and it's burned, whatever address sent them.
        print("\n[1] Guessing an invite code (was: PIN brute force vs. the join limiter)")
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "max_participants": 8, "display_name": "victim"}, format="json")
        invite = r.data["invite"]
        say(f"victim created a group chat; invite handle {invite[:6]} (the code is the secret)")
        codes = []
        for i in range(10):
            ip = f"10.0.0.{i}"
            codes.append(self._join(self._wrong(invite), HTTP_X_FORWARDED_FOR=ip).status_code)
        say("attacker, 10 wrong codes from 10 spoofed addresses:", codes)
        say("the real code afterwards ->", self._join(invite).status_code, "(the invite burned after 3 strikes)")
        say("chance of guessing within 3 tries: 3 / 2^30 = ~3 in a billion per invite")

    def test_2_shared_bucket_lockout(self):
        # At 123be67 five bad guesses from a shared address (all of Tor)
        # made a VALID PIN return 429 for everyone (T-08).
        print("\n[2] Do one client's failures lock out others behind the same address?")
        victim = self.c.post("/chat/create-chat/", {"public_key": PUB}, format="json").data["invite"]
        for i in range(5):
            self._join(services.format_invite(f"{800000 + i}", "ABCDEF"))
        legit = self._join(victim)
        say("after 5 bad guesses from the shared address, a legitimate join with a VALID invite ->", legit.status_code)

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
        # At 123be67 anyone could fill all 10,000 PINs and create_chat then
        # looped forever (T-06). There is no PIN any more (#101 stage 2):
        # creation still isn't throttled, but there's no fixed space to fill.
        print("\n[4] Unauthenticated create-chat flood (was: + PIN-space exhaustion)")
        t0 = time.time()
        codes = {self.c.post("/chat/create-chat/", {"public_key": PUB}, format="json").status_code for _ in range(300)}
        say(f"300 anonymous create-chat calls in {time.time() - t0:.1f}s -> status codes {codes}")
        say("fields left on Chat that come from a finite space:",
            [f.name for f in Chat._meta.get_fields() if getattr(f, "max_length", None) == 4] or "none")

    def test_5_abandoned_chat_persists(self):
        print("\n[5] Abandoned chat: nobody returns, nothing reclaims it")
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "alice"}, format="json")
        pin = r.data["chat_id"]  # the chat's address (public id) since #101 stage 1
        j = self._join(r.data["invite"])
        chat = Chat.objects.get(public_id=pin)
        alice, bob = list(chat.participants.order_by("joined_at"))
        Message.objects.create(chat=chat, sender=alice, encrypted_text="x", aes_nonce="x", aes_tag="x", mac="x", seq=0)
        ChatParticipant.objects.filter(chat=chat).update(last_seen=timezone.now() - timedelta(days=30))
        active = list(chat.participants.filter(left_at__isnull=True).values_list("display_name", flat=True))
        say(f"30 days idle, no one authenticated since: chat exists={Chat.objects.filter(public_id=pin).exists()} active participants={active}")
        say("Chat rows:", Chat.objects.filter(public_id=pin).count(), " Message rows:", Message.objects.filter(chat=chat).count(),
            " -> seats still held, ciphertext still stored")
        try:
            services.issue_invite(chat, alice)
            say("an invite for a third party could be issued (unexpected: ghosts hold both seats)")
        except services.InviteLimit:
            say("no invite can be issued for a third party: the ghosts hold both seats")
        # The one path that does reclaim an idle participant: their OWN next authenticated request.
        for who, tok in (("alice", r.data["participant_token"]), ("bob", j.data["participant_token"])):
            resp = APIClient().get(f"/chat/get-messages/{pin}/", HTTP_AUTHORIZATION=f"Token {tok}")
            say(f"{who} finally returns after 30 days -> {resp.status_code} (idle-expired, marked left)")
        say("after BOTH were idle-expired: Chat rows:", Chat.objects.filter(public_id=pin).count(),
            " Message rows:", Message.objects.filter(chat=chat).count(),
            " active participants:", ChatParticipant.objects.filter(chat=chat, left_at__isnull=True).count())
        # At 123be67 the chat row and its messages survived this (T-07); since
        # #97 idle expiry deletes an emptied chat like an explicit leave does.
        # The reaper does it without anyone returning:
        r2 = self.c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "zoe"}, format="json")
        ChatParticipant.objects.filter(chat__public_id=r2.data["chat_id"]).update(last_seen=timezone.now() - timedelta(days=30))
        say("second abandoned chat, nobody returns; one reaper pass ->", services.reap_idle_chats(),
            " Chat rows left:", Chat.objects.filter(public_id=r2.data["chat_id"]).count())

    def test_6_display_names_not_unique(self):
        print("\n[6] Display names are not unique within a chat")
        r = self.c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "alice"}, format="json")
        j = self.c.post("/chat/join-chat/", {"invite": r.data["invite"], "public_key": PUB, "display_name": "alice"}, format="json")
        say("second participant joined as the same name 'alice' ->", j.status_code)
        roster = Chat.objects.get(public_id=r.data["chat_id"]).participants.values_list("display_name", flat=True)
        say("roster as stored:", list(roster))
        v = services.is_valid_display_name("alice\n")
        say("is_valid_display_name('alice\\n') =", v, "(True at 123be67: regex '$' tolerated a trailing newline; fixed in #107)")


@override_settings(CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}})
class WsProbes(TransactionTestCase):
    def test_8_websocket_outlives_membership(self):
        print("\n[8] WebSocket subscription vs. membership")
        from channels.routing import URLRouter
        from channels.testing import WebsocketCommunicator
        import chat.routing
        from chat.realtime import notify_chat

        app = URLRouter(chat.routing.websocket_urlpatterns)
        chat_obj, alice, tok_a, _invite = services.create_chat("alice", PUB, 2)
        bob, tok_b = services.join_chat(chat_obj, "bob", PUB)
        cid = chat_obj.public_id

        async def run():
            comm = WebsocketCommunicator(app, f"/ws/chat/{cid}/", subprotocols=[tok_b])
            ok, _ = await comm.connect()
            say("bob connected:", ok)
            await dbasync(services.leave_chat)(bob, cid)
            say("bob has left the chat via services.leave_chat (left_at set); alice still there")
            await asyncio.to_thread(notify_chat, cid, "new_message")
            try:
                msg = await comm.receive_json_from(timeout=2)
                say("bob's socket STILL receives signals for the chat he left:", msg)
            except asyncio.TimeoutError:
                say("bob's socket received nothing (subscription was cut)")
            # chat emptied -> deleted -> a stranger's brand-new chat. At 123be67
            # the new chat could get the same PIN and so the same group
            # (chat_<pin>); since #101 every chat has its own random id.
            await dbasync(services.leave_chat)(alice, cid)
            new_chat = await dbasync(Chat.objects.create)()
            say(f"new chat created after the old one was deleted; ids differ: {new_chat.public_id != cid}")
            await asyncio.to_thread(notify_chat, new_chat.public_id, "new_message")
            try:
                msg = await comm.receive_json_from(timeout=2)
                say("after the PIN was recycled to an UNRELATED chat, bob's old socket receives:", msg)
            except asyncio.TimeoutError:
                say("old socket received nothing after PIN recycling")
            await comm.disconnect()
            # positive control: a token for THIS chat must not open a socket on another chat
            other, _, _, _ = await dbasync(services.create_chat)("other", PUB, 2)
            cross = WebsocketCommunicator(app, f"/ws/chat/{other.public_id}/", subprotocols=[tok_a])
            ok, code = await cross.connect()
            say(f"token for chat {cid} opening a socket on chat {other.public_id}: accepted={ok} (close code {code})")
            await cross.disconnect()
        asyncio.run(run())


class FormatProbes(TestCase):
    def test_9_garbage_message_fields_accepted(self):
        print("\n[9] Server validates no ciphertext field format or size")
        c = APIClient()
        a = c.post("/chat/create-chat/", {"public_key": PUB, "display_name": "a"}, format="json").data
        b = APIClient().post("/chat/join-chat/", {"invite": a["invite"], "public_key": PUB, "display_name": "b"}, format="json").data
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
        APIClient().post("/chat/join-chat/", {"invite": b["invite"], "public_key": PUB, "display_name": "b2"}, format="json")
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
        say("B's roster untouched:", Chat.objects.get(public_id=B).participants.filter(left_at__isnull=True).count(), "active")
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
        APIClient().post("/chat/join-chat/", {"invite": a["invite"], "public_key": PUB, "display_name": "b"}, format="json")
        chat = Chat.objects.get(public_id=a["chat_id"])
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

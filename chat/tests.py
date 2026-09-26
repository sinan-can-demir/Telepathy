from datetime import datetime, timedelta
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase
from django.urls import Resolver404, resolve
from django.utils import timezone
from rest_framework.test import APIClient

from chat.views import failed_join_attempts
from chat.models import Chat, ChatParticipant, Message, MessageKey, MessageReadReceipt
from chat.auth import hash_token, IDLE_TIMEOUT
from chat.chain import GENESIS_HASH, compute_chain_hash
from chat import services


def _fake_public_key_pem():
    # .strip() matches the client's arrayBufferToPem(), which emits PEM with
    # no trailing newline.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode().strip()


def _create_chat(client, display_name="alice", max_participants=None, public_key=None):
    body = {"display_name": display_name, "public_key": public_key or _fake_public_key_pem()}
    if max_participants is not None:
        body["max_participants"] = max_participants
    return client.post("/chat/create-chat/", body, format="json")


def _join_chat(client, chat_id, display_name="bob", public_key=None):
    body = {"chat_id": chat_id, "display_name": display_name, "public_key": public_key or _fake_public_key_pem()}
    return client.post("/chat/join-chat/", body, format="json")


def _issue_chain_key(client, chat_id, other_ids):
    """Issues a chain-key epoch covering exactly other_ids, with placeholder
    (not real RSA-OAEP) wrapped seeds -- server-side, IssueChainKeyView never
    looks inside encrypted_seed, only that one is present per recipient."""
    return client.post(
        f"/chat/issue-chain-key/{chat_id}/",
        {"wraps": [{"recipient_id": rid, "encrypted_seed": f"seed-for-{rid}"} for rid in other_ids]},
        format="json",
    )


class ChatCreationTests(TestCase):
    """Coverage for the accountless entry points: no registration/login step
    exists anymore, CreateChatView/JoinChatView are the first calls a client
    ever makes."""

    def setUp(self):
        self.client = APIClient()

    def test_create_chat_requires_public_key(self):
        response = self.client.post("/chat/create-chat/", {"display_name": "alice"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_create_chat_needs_no_account_at_all(self):
        response = _create_chat(self.client, display_name="alice")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertIn("chat_id", response.data)
        self.assertIn("participant_token", response.data)
        self.assertIn("participant_id", response.data)

    def test_check_chat_endpoint_is_gone(self):
        # It let anyone list every live chat and its members' names without
        # authenticating, and nothing in the client used it (issue #96).
        # Checked by URL resolution rather than a test-client GET: rendering
        # the 404 page trips a Django 5.1 / Python 3.14 template bug locally.
        chat_id = _create_chat(self.client).data["chat_id"]
        with self.assertRaises(Resolver404):
            resolve(f"/chat/check-chat/{chat_id}/")

    def test_create_chat_rejects_out_of_range_max_participants(self):
        for bad in (0, 1, 9):
            response = _create_chat(self.client, max_participants=bad)
            self.assertEqual(response.status_code, 400, bad)
        for good in (2, 8):
            response = _create_chat(self.client, max_participants=good)
            self.assertEqual(response.status_code, 201, good)

    def test_default_display_name_is_generated_when_omitted(self):
        response = self.client.post(
            "/chat/create-chat/", {"public_key": _fake_public_key_pem()}, format="json"
        )
        self.assertEqual(response.status_code, 201, response.data)
        participant = ChatParticipant.objects.get(pk=response.data["participant_id"])
        self.assertTrue(participant.display_name)

    def test_create_chat_rejects_malformed_or_wrong_size_public_key(self):
        # Regression coverage for #72: every client-side importKey call
        # assumes a 2048-bit RSA SPKI PEM (see generateFreshKeys in
        # chatbox.html) -- presence alone used to be enough to pass here.
        not_a_key = "not a pem at all"
        response = self.client.post(
            "/chat/create-chat/", {"display_name": "alice", "public_key": not_a_key}, format="json"
        )
        self.assertEqual(response.status_code, 400)

        wrong_size_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        wrong_size_pem = wrong_size_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        response = self.client.post(
            "/chat/create-chat/", {"display_name": "alice", "public_key": wrong_size_pem}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_create_chat_rejects_oversized_public_key(self):
        response = self.client.post(
            "/chat/create-chat/", {"display_name": "alice", "public_key": "A" * 5000}, format="json"
        )
        self.assertEqual(response.status_code, 400)


class TokenAuthTests(TestCase):
    """Coverage for the accountless auth model: possession of a per-chat
    bearer token is the only credential, scoped to exactly one
    ChatParticipant and invalidated the moment that participant leaves."""

    def setUp(self):
        failed_join_attempts.clear()
        self.alice = APIClient()
        self.bob = APIClient()
        create = _create_chat(self.alice, display_name="alice")
        self.chat_id = create.data["chat_id"]
        self.alice_token = create.data["participant_token"]
        self.alice_participant_id = create.data["participant_id"]
        self.alice.credentials(HTTP_AUTHORIZATION=f"Token {self.alice_token}")

        join = _join_chat(self.bob, self.chat_id, display_name="bob")
        self.bob_token = join.data["participant_token"]
        self.bob_participant_id = join.data["participant_id"]
        self.bob.credentials(HTTP_AUTHORIZATION=f"Token {self.bob_token}")

    def test_valid_token_authenticates(self):
        response = self.alice.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(response.status_code, 200)

    def test_missing_token_is_rejected(self):
        response = APIClient().get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(response.status_code, 401)

    def test_garbage_token_is_rejected(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token not-a-real-token")
        response = client.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(response.status_code, 401)

    def test_raw_token_is_never_stored_only_its_hash(self):
        participant = ChatParticipant.objects.get(pk=self.alice_participant_id)
        self.assertNotEqual(participant.auth_token_hash, self.alice_token)
        self.assertEqual(participant.auth_token_hash, hash_token(self.alice_token))

    def test_token_stops_working_after_leaving(self):
        leave = self.bob.post("/chat/leave-chat/", {"chat_id": self.chat_id}, format="json")
        self.assertEqual(leave.status_code, 200)
        response = self.bob.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(response.status_code, 401)

    def test_a_participants_token_is_useless_in_a_different_chat(self):
        other = _create_chat(APIClient(), display_name="carol")
        other_chat_id = other.data["chat_id"]
        # alice's token authenticates fine, but she isn't a participant of this chat.
        response = self.alice.get(f"/chat/get-messages/{other_chat_id}/")
        self.assertEqual(response.status_code, 403)

    def test_idle_token_stops_working_and_is_marked_left(self):
        # Regression coverage for #71: a tab that's actually closed stops
        # re-authenticating entirely (no beforeunload hook can safely tell
        # a real close apart from a page refresh), so idle time -- not an
        # unload event -- is what reclaims an abandoned token.
        stale = timezone.now() - IDLE_TIMEOUT - timedelta(seconds=1)
        ChatParticipant.objects.filter(pk=self.bob_participant_id).update(last_seen=stale)

        response = self.bob.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(response.status_code, 401)

        bob = ChatParticipant.objects.get(pk=self.bob_participant_id)
        self.assertIsNotNone(bob.left_at)

    def test_active_use_keeps_last_seen_fresh(self):
        stale_but_within_timeout = timezone.now() - timedelta(minutes=1)
        ChatParticipant.objects.filter(pk=self.alice_participant_id).update(last_seen=stale_but_within_timeout)

        response = self.alice.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(response.status_code, 200)

        alice = ChatParticipant.objects.get(pk=self.alice_participant_id)
        self.assertIsNone(alice.left_at)
        self.assertGreater(alice.last_seen, stale_but_within_timeout)


class JoinChatRateLimitTests(TestCase):
    """Regression coverage for #20: brute-forcing the 4-digit chat PIN space
    via repeated JoinChatView calls must be throttled. There's no account to
    key this on before a join succeeds, so it's keyed on source IP -- see the
    failed_join_attempts comment in chat/views.py for why that's an accepted,
    Tor-collapses-this tradeoff rather than an oversight."""

    def setUp(self):
        failed_join_attempts.clear()
        self.client = APIClient()

    def test_repeated_wrong_pins_are_rate_limited(self):
        for _ in range(4):
            response = _join_chat(self.client, "0000")
            self.assertEqual(response.status_code, 404)

        # The 5th failed guess crosses the threshold and starts the cooldown immediately.
        response = _join_chat(self.client, "0000")
        self.assertEqual(response.status_code, 429)

        # Even a real PIN is throttled during the cooldown window.
        real_pin = _create_chat(APIClient(), display_name="creator").data["chat_id"]
        response = _join_chat(self.client, real_pin)
        self.assertEqual(response.status_code, 429)

    def test_group_chat_allows_joins_up_to_cap_then_rejects(self):
        create = _create_chat(self.client, display_name="alice", max_participants=3)
        chat_id = create.data["chat_id"]

        self.assertEqual(_join_chat(APIClient(), chat_id, "bob").status_code, 200)
        self.assertEqual(_join_chat(APIClient(), chat_id, "carol").status_code, 200)
        full = _join_chat(APIClient(), chat_id, "dave")
        self.assertEqual(full.status_code, 400)
        self.assertIn("full", full.data["message"].lower())

    def test_join_chat_rejects_malformed_public_key(self):
        # Regression coverage for #72 -- same validation as CreateChatView,
        # exercised through the other entry point.
        chat_id = _create_chat(APIClient(), display_name="alice").data["chat_id"]
        response = self.client.post(
            "/chat/join-chat/",
            {"chat_id": chat_id, "display_name": "bob", "public_key": "not a real key"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)


class MessageRoundTripTests(TestCase):
    """A 1:1 chat's full lifecycle: create, join, send (wrapping the AES key
    for both participants), read back each side's own wrapped key, and the
    leave-only-clears-history-once-fully-empty semantics."""

    def setUp(self):
        failed_join_attempts.clear()
        self.alice = APIClient()
        self.bob = APIClient()
        create = _create_chat(self.alice, display_name="alice")
        self.chat_id = create.data["chat_id"]
        self.alice_token = create.data["participant_token"]
        self.alice_id = create.data["participant_id"]
        self.alice.credentials(HTTP_AUTHORIZATION=f"Token {self.alice_token}")

        join = _join_chat(self.bob, self.chat_id, display_name="bob")
        self.bob_token = join.data["participant_token"]
        self.bob_id = join.data["participant_id"]
        self.bob.credentials(HTTP_AUTHORIZATION=f"Token {self.bob_token}")

        # Alice issues epoch 0 of her sending chain, covering bob -- required
        # before her first send now that message keys come from that chain
        # rather than a per-recipient RSA wrap (see docs/FORWARD_SECRECY.md).
        issued = _issue_chain_key(self.alice, self.chat_id, [self.bob_id])
        self.alice_epoch = issued.data["epoch"]

    def _send(self, client, key_for_self="key-a", prev_hash=GENESIS_HASH, sender_id=None, epoch=None):
        sender_id = sender_id if sender_id is not None else self.alice_id
        epoch = epoch if epoch is not None else self.alice_epoch
        return client.post(
            f"/chat/send-message/{self.chat_id}/",
            {
                "encrypted_text": "ciphertext", "aes_nonce": "n", "aes_tag": "t", "mac": "s",
                "prev_hash": prev_hash,
                "sender_chain_epoch": epoch, "chain_index": 0,
                "wrapped_keys": [{"recipient_id": sender_id, "encrypted_symmetric_key": key_for_self}],
            },
            format="json",
        )

    def test_chain_index_is_stored_and_served(self):
        resp = self.alice.post(
            f"/chat/send-message/{self.chat_id}/",
            {
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "mac": "s",
                "prev_hash": GENESIS_HASH, "sender_chain_epoch": self.alice_epoch, "chain_index": 7,
                "wrapped_keys": [{"recipient_id": self.alice_id, "encrypted_symmetric_key": "k"}],
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertEqual(resp.data["chain_index"], 7)
        self.assertEqual(Message.objects.get().chain_index, 7)
        served = self.bob.get(f"/chat/get-messages/{self.chat_id}/").data["messages"][0]
        self.assertEqual(served["chain_index"], 7)

    def test_chain_index_is_required_and_validated(self):
        def post(**extra):
            body = {
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "mac": "s",
                "prev_hash": GENESIS_HASH, "sender_chain_epoch": self.alice_epoch,
                "wrapped_keys": [{"recipient_id": self.alice_id, "encrypted_symmetric_key": "k"}],
            }
            body.update(extra)
            return self.alice.post(f"/chat/send-message/{self.chat_id}/", body, format="json")

        self.assertEqual(post().status_code, 400)  # missing entirely
        for bad in (-1, 2**31, "3", 1.5, True, None):
            self.assertEqual(post(chain_index=bad).status_code, 400, bad)
        self.assertEqual(Message.objects.count(), 0)

    def test_round_trip_creates_one_message_and_self_wrap_only(self):
        send = self._send(self.alice)
        self.assertEqual(send.status_code, 201, send.data)
        self.assertEqual(Message.objects.count(), 1)
        # Only the sender's own self-wrap is ever stored now -- other
        # participants derive the key from their cached copy of alice's
        # chain instead of unwrapping a per-message key.
        self.assertEqual(MessageKey.objects.count(), 1)
        self.assertEqual(send.data["sender_id"], self.alice_id)
        self.assertEqual(send.data["sender_chain_epoch"], self.alice_epoch)

        alice_view = self.alice.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(alice_view.data["current_user_id"], self.alice_id)
        self.assertEqual(alice_view.data["messages"][0]["my_encrypted_symmetric_key"], "key-a")

        bob_view = self.bob.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(bob_view.data["current_user_id"], self.bob_id)
        # Bob has no server-stored wrapped key for alice's message -- he'd
        # derive it client-side from the chain seed she issued him.
        self.assertIsNone(bob_view.data["messages"][0]["my_encrypted_symmetric_key"])

    def test_served_timestamp_is_bucketed_to_the_minute(self):
        # Regression coverage for #59: the API-facing timestamp is bucketed
        # to reduce timing-correlation exposure, but the stored value keeps
        # full precision for internal ordering.
        send = self._send(self.alice)
        self.assertEqual(send.status_code, 201, send.data)

        stored = Message.objects.get(seq=0).timestamp
        self.assertEqual(send.data["timestamp"], stored.replace(second=0, microsecond=0).isoformat())

        parsed = datetime.fromisoformat(send.data["timestamp"])
        self.assertEqual(parsed.second, 0)
        self.assertEqual(parsed.microsecond, 0)

    def test_send_rejects_missing_self_wrap(self):
        response = self._send(self.alice, key_for_self="")
        self.assertEqual(response.status_code, 400)

    def test_send_rejects_unknown_chain_epoch(self):
        response = self._send(self.alice, epoch=99)
        self.assertEqual(response.status_code, 400)

    def test_send_rejects_stale_epoch_after_rekey(self):
        # Regression coverage for #69: re-keying on roster change only
        # bounds a leaver's exposure if the server actually refuses a
        # since-superseded epoch, not merely one that once existed.
        send0 = self._send(self.alice, epoch=self.alice_epoch)
        self.assertEqual(send0.status_code, 201, send0.data)

        reissued = _issue_chain_key(self.alice, self.chat_id, [self.bob_id])
        new_epoch = reissued.data["epoch"]
        self.assertGreater(new_epoch, self.alice_epoch)

        stale = self._send(self.alice, prev_hash=compute_chain_hash(Message.objects.get(seq=0)), epoch=self.alice_epoch)
        self.assertEqual(stale.status_code, 400, stale.data)

        current = self._send(self.alice, prev_hash=compute_chain_hash(Message.objects.get(seq=0)), epoch=new_epoch)
        self.assertEqual(current.status_code, 201, current.data)

    def test_leave_only_deletes_chat_once_it_fully_empties(self):
        self._send(self.alice)
        self.assertEqual(Message.objects.count(), 1)

        # Alice leaves; Bob remains -- history and the chat itself must survive.
        leave = self.alice.post("/chat/leave-chat/", {"chat_id": self.chat_id}, format="json")
        self.assertEqual(leave.status_code, 200)
        self.assertEqual(Message.objects.count(), 1)
        self.assertTrue(Chat.objects.filter(pin=self.chat_id).exists())

        # Bob leaves too; chat is now fully empty -- it (and its messages,
        # via cascade) is hard-deleted, freeing its PIN for reuse (#35).
        leave2 = self.bob.post("/chat/leave-chat/", {"chat_id": self.chat_id}, format="json")
        self.assertEqual(leave2.status_code, 200)
        self.assertEqual(Message.objects.count(), 0)
        self.assertFalse(Chat.objects.filter(pin=self.chat_id).exists())

    def test_emptied_chats_pin_becomes_reusable(self):
        leave = self.alice.post("/chat/leave-chat/", {"chat_id": self.chat_id}, format="json")
        self.assertEqual(leave.status_code, 200)
        leave2 = self.bob.post("/chat/leave-chat/", {"chat_id": self.chat_id}, format="json")
        self.assertEqual(leave2.status_code, 200)
        self.assertFalse(Chat.objects.filter(pin=self.chat_id).exists())

        # A brand-new chat can now legitimately reuse that same PIN.
        with patch("random.randint", return_value=int(self.chat_id)):
            recreated = _create_chat(APIClient(), display_name="new-owner")
        self.assertEqual(recreated.status_code, 201, recreated.data)
        self.assertEqual(recreated.data["chat_id"], self.chat_id)


class GroupChatFeatureTests(TestCase):
    """Coverage for the group-chat generalization: the participants-roster
    endpoint used to wrap a message's AES key for everyone, and the N-way
    send/read round trip and response metadata for a >2-person chat."""

    def setUp(self):
        failed_join_attempts.clear()
        self.alice = APIClient()
        create = _create_chat(self.alice, display_name="alice", max_participants=3)
        self.chat_id = create.data["chat_id"]
        self.alice_id = create.data["participant_id"]
        self.alice.credentials(HTTP_AUTHORIZATION=f"Token {create.data['participant_token']}")

        self.bob = APIClient()
        join_bob = _join_chat(self.bob, self.chat_id, display_name="bob")
        self.bob_id = join_bob.data["participant_id"]
        self.bob.credentials(HTTP_AUTHORIZATION=f"Token {join_bob.data['participant_token']}")

        self.carol = APIClient()
        join_carol = _join_chat(self.carol, self.chat_id, display_name="carol")
        self.carol_id = join_carol.data["participant_id"]
        self.carol.credentials(HTTP_AUTHORIZATION=f"Token {join_carol.data['participant_token']}")

    def test_get_chat_participants_requires_active_membership(self):
        outsider = _create_chat(APIClient(), display_name="mallory")
        outsider_client = APIClient()
        outsider_client.credentials(HTTP_AUTHORIZATION=f"Token {outsider.data['participant_token']}")
        forbidden = outsider_client.get(f"/chat/get-chat-participants/{self.chat_id}/")
        self.assertEqual(forbidden.status_code, 403)

        ok = self.alice.get(f"/chat/get-chat-participants/{self.chat_id}/")
        self.assertEqual(ok.status_code, 200)
        ids = {p["id"] for p in ok.data["participants"]}
        self.assertEqual(ids, {self.alice_id, self.bob_id, self.carol_id})
        by_id = {p["id"]: p for p in ok.data["participants"]}
        self.assertEqual(by_id[self.bob_id]["display_name"], "bob")
        self.assertTrue(by_id[self.bob_id]["public_key"])

    def test_send_message_in_group_stores_only_senders_self_wrap(self):
        issued = _issue_chain_key(self.alice, self.chat_id, [self.bob_id, self.carol_id])
        self.assertEqual(issued.status_code, 201, issued.data)

        send = self.alice.post(
            f"/chat/send-message/{self.chat_id}/",
            {
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "mac": "s",
                "prev_hash": GENESIS_HASH,
                "sender_chain_epoch": issued.data["epoch"], "chain_index": 0,
                "wrapped_keys": [{"recipient_id": self.alice_id, "encrypted_symmetric_key": "key-a"}],
            },
            format="json",
        )
        self.assertEqual(send.status_code, 201, send.data)
        self.assertEqual(Message.objects.count(), 1)
        self.assertEqual(MessageKey.objects.count(), 1)

        alice_view = self.alice.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(alice_view.data["messages"][0]["my_encrypted_symmetric_key"], "key-a")
        for client in (self.bob, self.carol):
            view = client.get(f"/chat/get-messages/{self.chat_id}/")
            self.assertIsNone(view.data["messages"][0]["my_encrypted_symmetric_key"])

    def test_issue_chain_key_must_cover_exactly_current_other_participants(self):
        missing_carol = _issue_chain_key(self.alice, self.chat_id, [self.bob_id])
        self.assertEqual(missing_carol.status_code, 400)

        extra_outsider = _issue_chain_key(self.alice, self.chat_id, [self.bob_id, self.carol_id, 99999])
        self.assertEqual(extra_outsider.status_code, 400)

        exact = _issue_chain_key(self.alice, self.chat_id, [self.bob_id, self.carol_id])
        self.assertEqual(exact.status_code, 201, exact.data)
        self.assertEqual(exact.data["epoch"], 0)

    def test_chain_key_epoch_increments_and_get_chain_keys_returns_latest_only(self):
        first = _issue_chain_key(self.alice, self.chat_id, [self.bob_id, self.carol_id])
        self.assertEqual(first.data["epoch"], 0)
        second = _issue_chain_key(self.alice, self.chat_id, [self.bob_id, self.carol_id])
        self.assertEqual(second.data["epoch"], 1)

        bob_view = self.bob.get(f"/chat/get-chain-keys/{self.chat_id}/")
        self.assertEqual(bob_view.status_code, 200)
        [entry] = [e for e in bob_view.data["chain_keys"] if e["sender_id"] == self.alice_id]
        self.assertEqual(entry["epoch"], 1)
        self.assertEqual(entry["encrypted_seed"], f"seed-for-{self.bob_id}")

    def test_get_chain_keys_requires_active_membership(self):
        outsider = _create_chat(APIClient(), display_name="mallory")
        outsider_client = APIClient()
        outsider_client.credentials(HTTP_AUTHORIZATION=f"Token {outsider.data['participant_token']}")
        forbidden = outsider_client.get(f"/chat/get-chain-keys/{self.chat_id}/")
        self.assertEqual(forbidden.status_code, 403)

    def test_get_messages_others_and_group_metadata(self):
        view = self.alice.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertTrue(view.data["is_group"])
        self.assertEqual(view.data["max_participants"], 3)
        self.assertTrue(view.data["both_joined"])
        self.assertEqual(
            sorted(o["display_name"] for o in view.data["others"]), ["bob", "carol"]
        )

        # 1:1 chats stay is_group=False, with a single-entry others list.
        pair = _create_chat(APIClient(), display_name="dave")
        pair_client = APIClient()
        pair_client.credentials(HTTP_AUTHORIZATION=f"Token {pair.data['participant_token']}")
        _join_chat(APIClient(), pair.data["chat_id"], display_name="erin")
        pair_view = pair_client.get(f"/chat/get-messages/{pair.data['chat_id']}/")
        self.assertFalse(pair_view.data["is_group"])
        self.assertEqual([o["display_name"] for o in pair_view.data["others"]], ["erin"])


class TranscriptChainTests(TestCase):
    """Coverage for the transcript-tamper-evidence chain: seq/prev_hash are
    assigned atomically per chat and every send must reference the real
    current tip, so a client can independently detect a dropped, reordered,
    or replayed message rather than trusting GetMessagesView at face value."""

    def setUp(self):
        failed_join_attempts.clear()
        self.alice = APIClient()
        self.bob = APIClient()
        create = _create_chat(self.alice, display_name="alice")
        self.chat_id = create.data["chat_id"]
        self.alice_id = create.data["participant_id"]
        self.alice.credentials(HTTP_AUTHORIZATION=f"Token {create.data['participant_token']}")

        join = _join_chat(self.bob, self.chat_id, display_name="bob")
        self.bob_id = join.data["participant_id"]
        self.bob.credentials(HTTP_AUTHORIZATION=f"Token {join.data['participant_token']}")

        self.alice_epoch = _issue_chain_key(self.alice, self.chat_id, [self.bob_id]).data["epoch"]
        self.bob_epoch = _issue_chain_key(self.bob, self.chat_id, [self.alice_id]).data["epoch"]

    def _send(self, client, prev_hash, text="ct", sender_id=None, epoch=None):
        sender_id = sender_id if sender_id is not None else self.alice_id
        epoch = epoch if epoch is not None else (
            self.alice_epoch if sender_id == self.alice_id else self.bob_epoch
        )
        return client.post(
            f"/chat/send-message/{self.chat_id}/",
            {
                "encrypted_text": text, "aes_nonce": "n", "aes_tag": "t", "mac": "s",
                "prev_hash": prev_hash,
                "sender_chain_epoch": epoch, "chain_index": 0,
                "wrapped_keys": [{"recipient_id": sender_id, "encrypted_symmetric_key": "key-self"}],
            },
            format="json",
        )

    def test_first_message_requires_genesis_hash(self):
        wrong = self._send(self.alice, prev_hash="not-the-genesis-hash")
        self.assertEqual(wrong.status_code, 409)
        self.assertEqual(wrong.data["expected_prev_hash"], GENESIS_HASH)

        ok = self._send(self.alice, prev_hash=GENESIS_HASH)
        self.assertEqual(ok.status_code, 201, ok.data)
        self.assertEqual(ok.data["seq"], 0)
        self.assertEqual(ok.data["prev_hash"], GENESIS_HASH)

    def test_send_missing_prev_hash_is_rejected(self):
        response = self.alice.post(
            f"/chat/send-message/{self.chat_id}/",
            {
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "mac": "s",
                "wrapped_keys": [
                    {"recipient_id": self.alice_id, "encrypted_symmetric_key": "key-a"},
                    {"recipient_id": self.bob_id, "encrypted_symmetric_key": "key-b"},
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_chain_advances_and_stale_prev_hash_is_rejected(self):
        first = self._send(self.alice, prev_hash=GENESIS_HASH)
        self.assertEqual(first.status_code, 201, first.data)
        first_msg = Message.objects.get(pk=first.data["id"])
        real_tip_hash = compute_chain_hash(first_msg)

        # Resending against the now-stale genesis hash is rejected, and the
        # server tells the client what the real current tip actually is.
        stale = self._send(self.bob, prev_hash=GENESIS_HASH, text="stale", sender_id=self.bob_id)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.data["expected_prev_hash"], real_tip_hash)

        second = self._send(self.bob, prev_hash=real_tip_hash, text="second", sender_id=self.bob_id)
        self.assertEqual(second.status_code, 201, second.data)
        self.assertEqual(second.data["seq"], 1)
        self.assertEqual(second.data["prev_hash"], real_tip_hash)

        # The chain is independently verifiable end to end from what's stored.
        second_msg = Message.objects.get(pk=second.data["id"])
        self.assertEqual(second_msg.prev_hash, compute_chain_hash(first_msg))

    def test_seq_is_unique_per_chat_even_across_senders(self):
        first = self._send(self.alice, prev_hash=GENESIS_HASH)
        tip_hash = compute_chain_hash(Message.objects.get(pk=first.data["id"]))
        second = self._send(self.bob, prev_hash=tip_hash, text="from bob", sender_id=self.bob_id)
        self.assertEqual([first.data["seq"], second.data["seq"]], [0, 1])
        self.assertEqual(
            list(Message.objects.filter(chat__pin=self.chat_id).order_by("seq").values_list("seq", flat=True)),
            [0, 1],
        )


class ChatServicesUnitTests(TestCase):
    """Exercises chat/services.py directly, with no APIClient/HTTP round
    trip at all -- the actual point of issue #39/ARCHITECTURE.md #6: these
    run against the test database in milliseconds instead of driving a
    full request/response cycle for every domain-rule check."""

    def setUp(self):
        self.chat, self.alice, self.alice_token = services.create_chat(
            "alice", _fake_public_key_pem(), max_participants=2
        )
        self.bob, self.bob_token = services.join_chat(self.chat, "bob", _fake_public_key_pem())

    def _send(self, sender, **overrides):
        kwargs = dict(
            encrypted_text="ct", aes_nonce="n", aes_tag="t", mac="m",
            wrapped_keys=[{"recipient_id": sender.pk, "encrypted_symmetric_key": "k"}],
            prev_hash=GENESIS_HASH, sender_chain_epoch=0, chain_index=0,
        )
        kwargs.update(overrides)
        return services.send_message(self.chat.pin, sender, **kwargs)

    def test_create_chat_generates_a_4_digit_pin_and_first_participant(self):
        self.assertRegex(self.chat.pin, r'^\d{4}$')
        self.assertEqual(self.alice.display_name, "alice")
        self.assertEqual(self.alice.chat_id, self.chat.pk)

    def test_join_chat_rejects_once_the_chat_is_full(self):
        with self.assertRaises(services.ChatFull):
            services.join_chat(self.chat, "carol", _fake_public_key_pem())

    def test_get_chat_raises_not_found_for_an_unknown_pin(self):
        with self.assertRaises(services.ChatNotFound):
            services.get_chat("0000")

    def test_leave_chat_keeps_the_chat_alive_while_someone_remains(self):
        deleted, remaining = services.leave_chat(self.alice, self.chat.pin)
        self.assertFalse(deleted)
        self.assertEqual(remaining, 1)
        self.assertTrue(Chat.objects.filter(pk=self.chat.pk).exists())

    def test_leave_chat_deletes_the_chat_once_everyone_has_left(self):
        services.leave_chat(self.alice, self.chat.pin)
        deleted, remaining = services.leave_chat(self.bob, self.chat.pin)
        self.assertTrue(deleted)
        self.assertEqual(remaining, 0)
        self.assertFalse(Chat.objects.filter(pk=self.chat.pk).exists())

    def test_leave_chat_rejects_a_participant_who_isnt_in_that_chat(self):
        _other_chat, carol, _token = services.create_chat("carol", _fake_public_key_pem(), max_participants=2)
        with self.assertRaises(services.NotAParticipant):
            services.leave_chat(carol, self.chat.pin)

    def test_send_message_requires_a_chain_key_to_be_issued_first(self):
        with self.assertRaises(services.UnknownChainEpoch):
            self._send(self.alice)

    def test_send_message_rejects_a_stale_chain_epoch(self):
        epoch = services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "seed"}]
        )
        with self.assertRaises(services.StaleChainEpoch):
            self._send(self.alice, sender_chain_epoch=epoch + 1)

    def test_send_message_rejects_a_stale_prev_hash(self):
        services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "seed"}]
        )
        with self.assertRaises(services.StaleTranscript) as ctx:
            self._send(self.alice, prev_hash="not-the-real-genesis-hash")
        self.assertEqual(ctx.exception.expected_prev_hash, GENESIS_HASH)

    def test_send_message_requires_the_senders_own_self_wrap(self):
        services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "seed"}]
        )
        with self.assertRaises(services.MissingSelfWrap):
            self._send(self.alice, wrapped_keys=[{"recipient_id": self.bob.pk, "encrypted_symmetric_key": "k"}])

    def test_send_message_appends_and_returns_the_created_message(self):
        services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "seed"}]
        )
        msg = self._send(self.alice)
        self.assertEqual(msg.seq, 0)
        self.assertEqual(msg.sender_id, self.alice.pk)
        self.assertEqual(Message.objects.count(), 1)

    def test_issue_chain_key_rejects_wraps_that_dont_cover_exactly_the_roster(self):
        with self.assertRaises(services.RosterMismatch):
            services.issue_chain_key(self.chat.pin, self.alice, [])  # missing bob's wrap entirely
        with self.assertRaises(services.RosterMismatch):
            services.issue_chain_key(self.chat.pin, self.alice, [
                {"recipient_id": self.bob.pk, "encrypted_seed": "seed"},
                {"recipient_id": 999999, "encrypted_seed": "seed"},  # extra, unrelated recipient
            ])

    def test_issue_chain_key_epoch_increments_per_sender(self):
        epoch0 = services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "s0"}]
        )
        epoch1 = services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "s1"}]
        )
        self.assertEqual([epoch0, epoch1], [0, 1])

    def test_get_latest_chain_keys_dedupes_to_the_newest_epoch_per_sender(self):
        services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "old-seed"}]
        )
        services.issue_chain_key(
            self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "new-seed"}]
        )
        result = services.get_latest_chain_keys_for_recipient(self.chat, self.bob)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {"sender_id": self.alice.pk, "epoch": 1, "encrypted_seed": "new-seed"})

    def test_require_same_chat_vs_require_active_participant_differ_on_a_left_participant(self):
        # Documents a pre-existing, harmless asymmetry between these two
        # checks rather than silently changing it as part of this refactor:
        # ParticipantTokenAuthentication already guarantees a left
        # participant's token can't authenticate at all (chat/auth.py
        # filters left_at__isnull=True at the query level), so no live
        # request can ever reach either check with a left participant --
        # this test exercises the service functions directly, bypassing
        # that guarantee, specifically to make the distinction visible.
        services.leave_chat(self.bob, self.chat.pin)
        bob_row = ChatParticipant.objects.get(pk=self.bob.pk)

        services.require_same_chat(self.chat, bob_row)  # does not raise -- FK check only

        with self.assertRaises(services.NotAParticipant):
            services.require_active_participant(self.chat, bob_row)

    def test_is_valid_display_name_rejects_empty_and_overlong_names(self):
        self.assertTrue(services.is_valid_display_name("alice_01"))
        self.assertFalse(services.is_valid_display_name(""))
        self.assertFalse(services.is_valid_display_name("a" * 33))
        self.assertFalse(services.is_valid_display_name("has/slash"))

    def test_is_valid_rsa_public_key_pem_rejects_garbage(self):
        self.assertTrue(services.is_valid_rsa_public_key_pem(_fake_public_key_pem()))
        self.assertFalse(services.is_valid_rsa_public_key_pem("not a pem"))
        self.assertFalse(services.is_valid_rsa_public_key_pem(None))


class MessageExpiryUnitTests(TestCase):
    """Disappearing messages (issue #64): per-message TTL, read-time
    expiry, and the tombstoning that wipes content while keeping the
    transcript hash chain intact. All against chat/services.py directly --
    same rationale as ChatServicesUnitTests."""

    def setUp(self):
        self.chat, self.alice, _ = services.create_chat("alice", _fake_public_key_pem(), max_participants=3)
        self.bob, _ = services.join_chat(self.chat, "bob", _fake_public_key_pem())
        services.issue_chain_key(self.chat.pin, self.alice, [{"recipient_id": self.bob.pk, "encrypted_seed": "seed"}])

    def _send(self, ttl_seconds=None):
        return services.send_message(
            self.chat.pin, self.alice,
            encrypted_text="ct", aes_nonce="n", aes_tag="t", mac="m",
            wrapped_keys=[{"recipient_id": self.alice.pk, "encrypted_symmetric_key": "k"}],
            prev_hash=GENESIS_HASH, sender_chain_epoch=0, chain_index=0, ttl_seconds=ttl_seconds,
        )

    def test_send_message_without_ttl_creates_no_read_receipt(self):
        msg = self._send(ttl_seconds=None)
        self.assertEqual(MessageReadReceipt.objects.filter(message=msg).count(), 0)

    def test_send_message_with_ttl_auto_reads_for_the_sender(self):
        msg = self._send(ttl_seconds=60)
        self.assertTrue(MessageReadReceipt.objects.filter(message=msg, participant=self.alice).exists())

    def test_send_message_rejects_ttl_out_of_bounds(self):
        with self.assertRaises(services.InvalidTTL):
            self._send(ttl_seconds=services.MIN_TTL_SECONDS - 1)
        with self.assertRaises(services.InvalidTTL):
            self._send(ttl_seconds=services.MAX_TTL_SECONDS + 1)

    def test_sweep_does_not_tombstone_until_everyone_required_has_read_it(self):
        msg = self._send(ttl_seconds=60)
        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertIsNone(msg.tombstone_hash)  # bob hasn't read it yet

    def test_sweep_does_not_tombstone_before_ttl_elapses(self):
        msg = self._send(ttl_seconds=60)
        services.mark_messages_read(self.chat, self.bob, [msg])
        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertIsNone(msg.tombstone_hash)  # read by everyone, but 60s hasn't passed

    def test_sweep_tombstones_once_everyone_required_has_read_and_ttl_elapsed(self):
        msg = self._send(ttl_seconds=60)
        services.mark_messages_read(self.chat, self.bob, [msg])
        stale = timezone.now() - timedelta(seconds=61)
        MessageReadReceipt.objects.filter(message=msg).update(read_at=stale)

        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertIsNotNone(msg.tombstone_hash)
        self.assertIsNone(msg.encrypted_text)
        self.assertIsNone(msg.aes_nonce)
        self.assertIsNone(msg.aes_tag)
        self.assertIsNone(msg.mac)
        self.assertIsNotNone(msg.tombstoned_at)
        self.assertEqual(MessageKey.objects.filter(message=msg).count(), 0)
        self.assertEqual(MessageReadReceipt.objects.filter(message=msg).count(), 0)

    def test_tombstoning_preserves_the_original_chain_hash(self):
        msg = self._send(ttl_seconds=60)
        original_hash = compute_chain_hash(msg)
        services.mark_messages_read(self.chat, self.bob, [msg])
        MessageReadReceipt.objects.filter(message=msg).update(read_at=timezone.now() - timedelta(seconds=61))

        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertEqual(compute_chain_hash(msg), original_hash)

    def test_a_later_joiner_cannot_block_expiry(self):
        # Forward secrecy already means someone who joins after a message
        # was sent can never decrypt it -- their never reading it can't be
        # what's blocking expiry.
        msg = self._send(ttl_seconds=60)
        services.mark_messages_read(self.chat, self.bob, [msg])
        MessageReadReceipt.objects.filter(message=msg).update(read_at=timezone.now() - timedelta(seconds=61))

        services.join_chat(self.chat, "carol", _fake_public_key_pem())  # joined after msg, never reads it

        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertIsNotNone(msg.tombstone_hash)

    def test_expiry_unblocks_once_a_never_reading_participant_leaves(self):
        msg = self._send(ttl_seconds=60)
        services.leave_chat(self.bob, self.chat.pin)  # bob never read it, then left

        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertIsNone(msg.tombstone_hash)  # alice's own read receipt isn't stale yet

        MessageReadReceipt.objects.filter(message=msg).update(read_at=timezone.now() - timedelta(seconds=61))
        services.sweep_expired_messages(self.chat)
        msg.refresh_from_db()
        self.assertIsNotNone(msg.tombstone_hash)

    def test_mark_messages_read_is_idempotent(self):
        msg = self._send(ttl_seconds=60)
        services.mark_messages_read(self.chat, self.bob, [msg])
        services.mark_messages_read(self.chat, self.bob, [msg])  # must not raise
        self.assertEqual(MessageReadReceipt.objects.filter(message=msg, participant=self.bob).count(), 1)

    def test_mark_messages_read_ignores_non_expiring_messages(self):
        msg = self._send(ttl_seconds=None)
        services.mark_messages_read(self.chat, self.bob, [msg])
        self.assertEqual(MessageReadReceipt.objects.filter(message=msg).count(), 0)


class MessageExpiryHTTPTests(TestCase):
    """A couple of tests through the real send-message/get-messages
    endpoints, to confirm the service-level behavior above is actually
    wired up correctly -- not just correct in isolation."""

    def setUp(self):
        failed_join_attempts.clear()
        self.alice = APIClient()
        self.bob = APIClient()
        create = _create_chat(self.alice, display_name="alice")
        self.chat_id = create.data["chat_id"]
        self.alice.credentials(HTTP_AUTHORIZATION=f"Token {create.data['participant_token']}")
        self.alice_id = create.data["participant_id"]

        join = _join_chat(self.bob, self.chat_id, display_name="bob")
        self.bob.credentials(HTTP_AUTHORIZATION=f"Token {join.data['participant_token']}")
        self.bob_id = join.data["participant_id"]

        issued = _issue_chain_key(self.alice, self.chat_id, [self.bob_id])
        self.epoch = issued.data["epoch"]

    def _send(self, ttl_seconds):
        return self.alice.post(
            f"/chat/send-message/{self.chat_id}/",
            {
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "mac": "m",
                "prev_hash": GENESIS_HASH, "sender_chain_epoch": self.epoch, "chain_index": 0,
                "ttl_seconds": ttl_seconds,
                "wrapped_keys": [{"recipient_id": self.alice_id, "encrypted_symmetric_key": "k"}],
            },
            format="json",
        )

    def test_send_message_accepts_and_returns_ttl_seconds(self):
        send = self._send(ttl_seconds=60)
        self.assertEqual(send.status_code, 201, send.data)
        self.assertEqual(send.data["ttl_seconds"], 60)
        self.assertIsNone(send.data["tombstone_hash"])

    def test_send_message_rejects_a_too_short_ttl(self):
        send = self._send(ttl_seconds=1)
        self.assertEqual(send.status_code, 400)

    def test_get_messages_serves_an_already_tombstoned_message(self):
        send = self._send(ttl_seconds=60)
        msg_id = send.data["id"]

        # bob fetches (marks his own read receipt), then both receipts get
        # backdated so the sweep on the *next* fetch tombstones it.
        fetch = self.bob.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(fetch.status_code, 200)
        MessageReadReceipt.objects.filter(message_id=msg_id).update(
            read_at=timezone.now() - timedelta(seconds=61)
        )

        second_fetch = self.bob.get(f"/chat/get-messages/{self.chat_id}/")
        self.assertEqual(second_fetch.status_code, 200)
        msg_data = next(m for m in second_fetch.data["messages"] if m["id"] == msg_id)
        self.assertIsNotNone(msg_data["tombstone_hash"])
        self.assertIsNone(msg_data["encrypted_text"])

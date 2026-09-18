from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase
from rest_framework.test import APIClient

from chat.views import failed_join_attempts
from chat.models import Chat, ChatParticipant, Message, MessageKey
from chat.auth import hash_token
from chat.chain import GENESIS_HASH, compute_chain_hash


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

    def test_create_chat_accepts_valid_signing_public_key_and_rejects_invalid_one(self):
        good = self.client.post(
            "/chat/create-chat/",
            {"display_name": "alice", "public_key": _fake_public_key_pem(), "signing_public_key": _fake_public_key_pem()},
            format="json",
        )
        self.assertEqual(good.status_code, 201, good.data)

        bad = self.client.post(
            "/chat/create-chat/",
            {"display_name": "alice", "public_key": _fake_public_key_pem(), "signing_public_key": "garbage"},
            format="json",
        )
        self.assertEqual(bad.status_code, 400)


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
                "encrypted_text": "ciphertext", "aes_nonce": "n", "aes_tag": "t", "signature": "s",
                "prev_hash": prev_hash,
                "sender_chain_epoch": epoch,
                "wrapped_keys": [{"recipient_id": sender_id, "encrypted_symmetric_key": key_for_self}],
            },
            format="json",
        )

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
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "signature": "s",
                "prev_hash": GENESIS_HASH,
                "sender_chain_epoch": issued.data["epoch"],
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
                "encrypted_text": text, "aes_nonce": "n", "aes_tag": "t", "signature": "s",
                "prev_hash": prev_hash,
                "sender_chain_epoch": epoch,
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
                "encrypted_text": "ct", "aes_nonce": "n", "aes_tag": "t", "signature": "s",
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

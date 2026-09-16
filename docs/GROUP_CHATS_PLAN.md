# Group Chats: Design & Implementation Plan

## Context

The product direction (see [ARCHITECTURE.md](../ARCHITECTURE.md)) is to keep Telepathy anonymous and ephemeral — no persistent contacts, no email, no multi-device identity sync. Group chats fit that model as long as they're scoped as "more than two people can join a PIN-based room," not as a shift toward persistent identity.

This is blocked today by two structural facts documented in ARCHITECTURE.md and tracked as issues:
- **#34** — `Message` has no foreign key to `Chat`; chat identity is inferred from `(sender, receiver)` user pairs, which only works for exactly two people.
- **#38** — chat participation is tracked via fixed `Chat.user1`/`Chat.user2` slots, which can't generalize past two.

Both need a real schema migration regardless of group chat, so this plan treats the migration as groundwork (Phase 1) done before any group-specific feature work (Phase 2), per the decision to fix #34 now rather than defer it.

## Current schema (for reference)

```python
# chat/models.py, current state
class Chat(models.Model):
    pin = models.CharField(max_length=4, unique=True, db_index=True)
    user1 = models.ForeignKey(User, null=True, blank=True, related_name="chats_as_user1")
    user2 = models.ForeignKey(User, null=True, blank=True, related_name="chats_as_user2")
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(User, related_name="sent_messages", db_index=True)
    receiver = models.ForeignKey(User, related_name="received_messages", db_index=True)
    encrypted_text = models.TextField()
    encrypted_symmetric_key = models.TextField(null=True, blank=True)          # AES key wrapped for receiver
    sender_encrypted_symmetric_key = models.TextField(null=True, blank=True)   # AES key wrapped for sender
    aes_nonce = models.TextField(null=True, blank=True)
    aes_tag = models.TextField(null=True, blank=True)
    signature = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
```

The key insight: the app *already* wraps the AES key twice — once per recipient — via two hardcoded columns. Group chat support is really just generalizing "wrap the key exactly twice, into two fixed columns" into "wrap the key once per active participant, into a table."

## Target schema

```python
class Chat(models.Model):
    pin = models.CharField(max_length=4, unique=True, db_index=True)
    is_group = models.BooleanField(default=False)
    max_participants = models.IntegerField(default=2)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)


class ChatParticipant(models.Model):
    chat = models.ForeignKey(Chat, related_name="participants", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="chat_memberships", on_delete=models.CASCADE)
    joined_at = models.DateTimeField(auto_now_add=True)
    left_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("chat", "user")]


class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    chat = models.ForeignKey(Chat, related_name="messages", on_delete=models.CASCADE, db_index=True)
    sender = models.ForeignKey(User, related_name="sent_messages", on_delete=models.CASCADE, db_index=True)
    encrypted_text = models.TextField()
    aes_nonce = models.TextField()
    aes_tag = models.TextField()
    signature = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["chat", "-timestamp"], name="msg_chat_time_idx"),
        ]


class MessageKey(models.Model):
    message = models.ForeignKey(Message, related_name="wrapped_keys", on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name="message_keys", on_delete=models.CASCADE)
    encrypted_symmetric_key = models.TextField()

    class Meta:
        unique_together = [("message", "recipient")]
```

Notes on the design:
- `MessageKey` has one row per participant who could read the message, including the sender's own copy (replacing the old `sender_encrypted_symmetric_key` special case). For a 1:1 chat this is exactly 2 rows, identical to today's behavior — Phase 1 changes nothing observable.
- `Chat.pin` staying `unique=True` forever is issue #35 (PIN exhaustion) — out of scope for this plan, but flagged so it isn't accidentally "fixed" as a side effect of this migration and then forgotten. Track separately.
- `is_group`/`max_participants` default to `False`/`2` so Phase 1 introduces the columns with no behavior change; Phase 2 is the only place they start being set to group values.

## Phase 1 — Groundwork migration (no user-visible change)

Goal: move onto the new schema while 1:1 chats behave identically to today. This is fully testable in isolation before any group code exists.

1. **Add new models** (`ChatParticipant`, `MessageKey`) and new `Chat`/`Message` fields (`is_group`, `max_participants`, `Message.chat` as nullable) in one migration.
2. **Data migration** to backfill:
   - For each existing `Chat`, create `ChatParticipant` rows for `user1` and `user2` (if not null).
   - For each existing `Message`, set `chat` by finding the `Chat` whose participants are exactly `{sender, receiver}`. Since `LeaveChatView` currently hard-deletes messages on leave, there should be at most one plausible `Chat` per `(sender, receiver)` pair in practice — but the migration should log/flag any message it can't unambiguously resolve rather than guessing silently.
   - Create two `MessageKey` rows per existing `Message`: one for the receiver (from `encrypted_symmetric_key`), one for the sender (from `sender_encrypted_symmetric_key`).
3. **Switch view logic**:
   - `CreateChatView` (`chat/views.py:341`): create `Chat` + one `ChatParticipant` for the creator, instead of setting `user1`.
   - `JoinChatView` (`chat/views.py:371`): create a `ChatParticipant` instead of assigning `user2`; check `participants.count() < max_participants` instead of the `user1`/`user2 is None` checks.
   - `LeaveChatView` (`chat/views.py:471`): set `ChatParticipant.left_at` instead of nulling `user1`/`user2`; **stop hard-deleting messages on leave** (this was already flagged as a design smell in ARCHITECTURE.md #34 — message persistence should not be coupled to session lifecycle). Deactivate the `Chat` only when zero participants remain active.
   - `SendMessageView` (`chat/views.py:547`): create one `Message` row with `chat=chat`, then one `MessageKey` per active participant (still exactly 2 for a 1:1 chat in Phase 1).
   - `GetMessagesView` (`chat/views.py:595`): fetch `chat.messages.order_by("timestamp")`, and for each message look up the caller's `MessageKey` to get their wrapped AES key, instead of the `Q(sender=...)&Q(receiver=...)` matching.
   - `GetPublicKeyView` (`chat/views.py:515`) stays as-is (single-user lookup by id); Phase 2 adds a chat-scoped "all participants' keys" endpoint on top of it.
4. **Update `MessageSerializer`** (`chat/serializers.py`) to serialize the caller-specific `MessageKey` instead of the two hardcoded key fields — likely via a `SerializerMethodField` that takes the requesting user from context.
5. **Update the frontend** (`chat/templates/chatbox.html`): the send handler (around line 507) currently posts exactly `encrypted_symmetric_key` (partner) + `sender_encrypted_symmetric_key` (self) — Phase 1 keeps this 2-key shape unchanged from the *client's* perspective if we keep those exact field names as a compatibility shim in the API, OR update the client at the same time to post `{recipient_id, encrypted_symmetric_key}` pairs (recommended, since Phase 2 needs this shape anyway and there's no reason to ship two frontend changes).
6. **Testing**: extend `chat/tests.py`'s `MessageRoundTripTests`-equivalent to cover the new schema; verify a full register → create-chat → join-chat → send → get-messages round trip produces identical decrypted output to today.
7. **Cleanup migration** (separate, after Phase 1 is verified in use): drop `Chat.user1`, `Chat.user2`, `Message.receiver`, `Message.encrypted_symmetric_key`, `Message.sender_encrypted_symmetric_key`. Keep this as its own migration so Phase 1 can be rolled back independently if something is wrong with the backfill.

## Phase 2 — Group chat feature

Only start once Phase 1 is merged and stable.

1. **Chat creation**: `CreateChatView` accepts an optional `is_group=true` + `max_participants` (cap at some reasonable N, e.g. 20, to bound key-wrapping cost per message and abuse potential).
2. **Joining**: `JoinChatView`'s capacity check becomes `participants.count() < chat.max_participants` (already generalized in Phase 1); no longer limited to exactly 2.
3. **Key exchange for sending**: add an endpoint (or extend `GetPublicKeyView`) returning all *active* participants' public keys for a given chat, e.g. `GET /chat/get-chat-participants/<chat_id>/`. The frontend's send handler wraps the AES key once per participant returned (including the sender), instead of the current hardcoded "partner + self" pair.
4. **Frontend UI**: participant list / "N people in this chat," a "Create Group" toggle with a size selector on the create-chat flow, and adjusting `renderMsg()` (`chatbox.html:379`) to show sender names for messages (needed once there are more than 2 possible senders — today's UI can assume "if it's not me, it's my one partner").
5. **Leave semantics**: a participant leaving a group should not affect other participants' ability to keep chatting (unlike today's 1:1 leave, which ends the chat for both). Only deactivate the `Chat` when it drops to zero active participants.
6. **Rate limiting**: `JoinChatView`'s existing per-user PIN-brute-force throttle (see issue #20 fix) already applies; no new rate-limit surface needed, but confirm the cap on `max_participants` prevents a single chat from becoming a way to mass-message via wrapped-key spam (bound message-send cost to O(max_participants) RSA-OAEP wraps client-side, which is cheap at N≤20).

## Open questions to resolve before Phase 2 starts

- What's the actual `max_participants` cap? (Affects client-side wrap cost and UI design for the participant list.)
- Should a group's PIN be reusable after everyone leaves (feeding into #35's PIN-recycling fix), or single-use like today?
- Does leaving a group require confirmation / does the group persist with history for remaining members, or does any leave still wipe history for everyone (recommend: no, per the Phase 1 change to stop coupling message persistence to leave events)?

## Testability

This design directly resolves the testability gap noted in ARCHITECTURE.md #39: once `Message.chat` and `MessageKey` exist, pairing/messaging rules can be tested against the models directly (e.g. "does `chat.messages.filter(...)` return the right set") without needing a full `APIClient` HTTP round trip for every case, though the existing HTTP-level tests in `chat/tests.py` remain valuable as integration coverage.

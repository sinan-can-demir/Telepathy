# Why Telepathy Has No Accounts

## The question that started this

Telepathy's stated design is anonymous and ephemeral — no persistent contacts, no email, no multi-device identity sync. Yet until this change, every chat participant was a persistent Django `User`: a username, a password, an optional TOTP secret, authenticated once via `LoginView` and reused across every chat that account ever joined.

That's a real, unintended cost. Because `ChatParticipant.user` and `Message.sender` both pointed at one durable `User` row, the database could already show "this same account was in chat A, chat B, and chat C" — even though message *content* stayed encrypted throughout. Message confidentiality was never the weak point; **who talked to whom, and when, across multiple separate conversations, was** — a cross-chat linkability vector the product never actually wanted, sitting quietly underneath a system that otherwise did the crypto correctly.

2FA existed solely to protect that persistent, password-protected account. Once the account goes away, 2FA has nothing left to protect — so it goes too, deliberately, not as an oversight.

## The design: possession of the PIN is the credential

There is no registration step and no password anymore. Creating or joining a chat issues a **bearer token scoped to exactly one `ChatParticipant` row** — a free-standing identity that exists only for that one chat, holds its own encryption/signing keys (see below), and is discarded the moment its participant leaves. Nothing links one chat's participant to any other chat the same person may have joined, because nothing *is* shared between them: no username, no account row, no reused keypair.

Concretely:
- `ChatParticipant` gained `display_name`, `public_key`, `signing_public_key`, and `auth_token_hash` (a SHA-256 hash — the raw token is returned to the client exactly once, at creation/join time, and is never stored or logged server-side; this is already stronger than DRF's own default `authtoken.Token`, which stores tokens in plaintext).
- `Message.sender` and `MessageKey.recipient` now point at `ChatParticipant`, not `User`.
- `django.contrib.auth`'s `User` model still exists, but solely so Django's own admin/staff login keeps working. No end-user chat functionality touches it anymore.
- A new `ParticipantTokenAuthentication` (`chat/auth.py`) resolves a bearer token straight to a `ChatParticipant`; a token stops authenticating the instant that participant's `left_at` is set.
- Client-side, keys are generated fresh for every chat created or joined — "burner" keys, never reused across chats, deleted from `localStorage` the moment the chat is left. Reusing one keypair across multiple chats would have silently reintroduced the exact cross-chat correlation this change exists to remove, so it isn't optional.

## Red-team pass

| Attack | Verdict |
|---|---|
| Token theft via XSS (browser storage) | Same underlying storage risk as before, but blast radius is now bounded to **one chat**, not an account's entire lifetime across every chat it ever joined. |
| PIN/token brute force | Can no longer be keyed on an account — `CreateChatView`/`JoinChatView` are unauthenticated entry points by necessity. Falls back to source-IP throttling, which is weak under a Tor hidden-service deployment (every client collapses to one address); Tor's own `HiddenServicePoWDefensesEnabled` is the intended mitigation there instead of an app-level CAPTCHA. Under a plain non-Tor deployment, IP throttling is the only defense left, and it is genuinely weaker than the old per-account limiter — a real, accepted regression, not a hidden one. |
| Participant impersonation / slot hijack | Same bearer-token risk class as the old DRF token — not worse, and scoped tighter (one chat instead of a whole account). |
| Replay after leaving | Defended: the auth lookup filters on `left_at__isnull=True`, so a token stops working the moment its participant leaves. |
| Cross-chat correlation creeping back in | Requires generating tokens via a CSPRNG (`secrets.token_urlsafe`) with no shared pattern across chats, and never logging a raw token server-side — both true of the current implementation. |

## What this is not

This makes the software more honest about its own "anonymous, ephemeral" claim. It does **not**, by itself, make Telepathy ready for a high-stakes use case like source protection — that also needs forward secrecy / per-message key ratcheting (Signal-style), key verification (safety numbers / TOFU), and metadata minimization beyond what a single schema change provides. Those remain open, larger pieces of work. See `ARCHITECTURE.md` for the full limitations list.

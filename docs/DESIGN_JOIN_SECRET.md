# Design: replacing the 4-digit PIN with an invite (locator + secret)

**Status: decisions settled 2026-09-21 (see "Decisions"). Stage 1 built 2026-09-26; stages 2-4 not started.**
Motivation: #95 (limiter bypass), #96 (enumeration), #98 (PIN exhaustion), #100 (silent admission), and the threat-model review in #93 (findings T-01, T-02, T-03, T-06, T-08, T-19). This doc also records the alternatives that were considered and rejected, so they don't get re-litigated.

## The problem in one paragraph

Today the 4-digit PIN is doing three unrelated jobs: it is the chat's **address** (every API path, the websocket group `chat_<pin>`, `localStorage.chat_id`, and the MAC's `chat_id` input), its **join secret** (whoever has it can enter), and a **scarce resource** (10,000 values, so exhaustion is a denial of service). As a secret it is about 13 bits, and the only defence, a per-IP limiter, is bypassable (`X-Forwarded-For`) and self-inflicted-outage prone under Tor's shared address. Because the secret is also the address, it sits in every URL and log line for the chat's whole life and is known to every participant.

## Rejected alternatives

| Idea | Why not |
|---|---|
| **PIN + the creator's name, hashed** | Hashing protects a *stored* secret from a database thief; the attack here is *online guessing*, where the server hashes the guess for the attacker. A name is free text, guessable by anyone who knows the creator, and `check-chat` currently leaks it. Adds ~10-20 bits at best. |
| **Invite link with the secret in the URL fragment** | Technically neat (the fragment never reaches the server), but links leak: they're copied, synced (browser history sync), previewed and kept in message history. The maintainer rejected it. |
| **A PAKE handshake now** | Would make a short code safe against guessing *and* against a hostile server, but see below. **Deferred, not rejected.** |
| **Just make the PIN longer** | Helps, but the address/secret conflation, exhaustion and URL-leak problems remain. |

### Why not a PAKE yet

A password-authenticated key exchange (CPace, SPAKE2) is the principled fix for "short human-typeable code + untrusted server". Checked 2026-09-21:

- No audited browser implementation was found. The npm `spake2` package states it is unaudited; the JavaScript port of magic-wormhole is inactive (the working browser route is Rust compiled to WebAssembly, adding a binary and a toolchain); the one CPace implementation found (`filippo.io/cpace`, Go) calls itself experimental; CPace itself is an Internet-Draft awaiting the RFC Editor, not yet an RFC.
- `@noble/curves` is audited but is curve math only. Composing a PAKE from it is hand-rolling the protocol, which `docs/FORWARD_SECRECY.md` already rules out for this project.
- It is interactive: the creator's browser must hold per-joiner handshake state and be online to complete each join; groups need the creator to vouch for each joiner.
- **It does not stop a leaked code.** Anyone who learns the code passes the handshake. It fixes weak-secret and hostile-server problems, not leaks.

This search was one pass, not a survey, and no candidate library was audited by the author of this doc. Revisit if a vetted browser implementation appears or the project is used seriously. The design below does not prevent adding one.

## Design

Split the PIN into three identifiers with different lifetimes.

| Layer | What it is | Properties |
|---|---|---|
| **Chat id** (`Chat.public_id`) | Opaque, random, 96 bits (`secrets.token_urlsafe(12)`). Used for routing: API paths, websocket group, `localStorage.chat_id`, the MAC's `chat_id`. | Not a secret. **Never reused.** Nobody types it. |
| **Invite handle** | Short numeric, 6 digits, that finds an open invite. | Unique among *open* invites only; released when the invite is consumed, expires, or is burned. |
| **Invite code** | The secret: random, generated with `secrets`, 6 Crockford-base32 chars (30 bits). | Stored **keyed-hashed**, never plaintext; single use; **at most 3 wrong attempts *per invite*, then burned**; expires after 15 minutes. |

An invitee types `handle` + `code` plus a trailing **check character** computed over the whole string (displayed as one string, e.g. `482913-7KQ2MX-V`; Crockford's mod-37 check symbol is one option). The check character is included because typos still spend the 3-attempt budget, and a mistyped *handle* could put a strike on someone else's live invite. It is not needed for the security argument, so it can be dropped if the extra character proves annoying. One invite admits **one** person; adding another person means issuing another invite. No standing "join by PIN" path exists once a chat has started, and a seat vacated by a leaver reopens only through a fresh invite.

### How a join is checked

`POST /chat/join-chat/` takes `handle`, `code`, `public_key`, `display_name`. In one transaction, with the invite row locked (`select_for_update`):

0. **Validate the check character first.** A malformed or mistyped string is rejected with the same generic error and **charges no strike to any invite**. The check character is derived from public data, so this gives an attacker nothing; it exists to protect honest typos and other people's invites.
1. Look up the open invite by handle. Missing, expired, burned, consumed, wrong code: **all return the same generic error**, with comparable timing, so a probe can't tell a live handle from a dead one.
2. Compare with `hmac.compare_digest`. On a wrong code, increment the invite's failed counter *inside the same locked transaction*; at 3, mark it **burned**. The creator's waiting screen shows that an invite was burned, so they know to issue a new one (and that someone, or a typo, hit it).
3. On success, mark the invite consumed, create the participant, notify the roster.

A wrong attempt is charged **to the invite, regardless of source address**. This replaces the per-IP limiter entirely (#95): nothing depends on `X-Forwarded-For`, and nothing collapses under Tor's shared address. A coarse global throttle may remain for *load* protection, but no security property depends on it.

### Why the locking matters

If the compare and the counter increment aren't atomic, an attacker can fire many guesses in parallel before any increment lands and get far more than 3. The check-and-increment must be atomic. This needs a concurrency test (see below), not just a unit test.

### Guessing odds

3 guesses per invite against a 30-bit code:

| Code | Bits | Success per invite | Across 10,000 simultaneously open invites |
|---|---|---|---|
| 4 base32 chars | 20 | ~3 in a million | ~3% |
| **6 base32 chars (chosen)** | **30** | **~3 in a billion** | **~0.003%** |
| 3 words (7,776-word list) | ~39 | negligible | negligible |

## Threat analysis: what if someone hijacks the locator?

"Locator" here means the address/handle. Each variant, and what the design does about it:

| Attack | What the attacker gets | Defence |
|---|---|---|
| **Enumerate live handles**, then guess codes | A guess costs a strike against that invite; 3 strikes burn it. Success is ~10⁻⁹ per invite. **No access.** But see the burn-DoS row. | Per-invite cap; generic errors so live and dead handles look the same; longer handle raises sweep cost. |
| **Burn invites** (3 wrong guesses per handle) | Denial of service on *unjoined* invites: the creator has to issue another. **No confidentiality loss; fails safe.** Cost to burn every open invite: sweep the handle space three times (~3 million requests for 6 digits). | Longer handle; global load throttle; Tor Client Authorization (#62) so strangers can't reach the app at all. Accepted residual (see Decisions). |
| **Squat or predict a handle** (get the one the creator was given, or reuse it after it lapses) | Nothing on its own: without the code the attacker can't join, and a friend arriving late with the old code fails against the attacker's different code. | Handles are assigned server-side, unpredictably, never chosen by the client, released on use. The code is what admits. |
| **Overhear or leak both handle and code** | Can join first. This is the leaked-secret case; nothing in a code-based design prevents it. | Single use, short expiry, roster notice, and the **fingerprint gate** (#100). The intended friend is refused or notices a wrong roster. |
| **Malicious server redirects the friend** to another chat under the same handle | The server learns the typed code and can admit the friend to an attacker-controlled chat. **Not prevented.** | Only comparing key fingerprints (made mandatory by #100) catches it; a PAKE would prevent it. This is T-04 and stays an accepted limitation. |
| **Hijack an *established* chat's routing** (websocket group, API paths) | Today: a recycled PIN lets a former member's socket receive signals for an unrelated new chat with the same PIN (T-19, verified). | The chat id is opaque and never reused, so a new chat can never inherit an old chat's group. The handle exists only during the invite window and is not used for routing after that. |

**One more finding, surfaced while writing this.** `services.create_chat` generates PINs with `random.randint(0, 9999)` (`chat/services.py:135`), Python's non-cryptographic Mersenne Twister, while `secrets` is already imported in the same file and used for tokens. Whether an attacker can recover the generator's state from the PINs they can observe (via `check-chat`) was **not tested**, and the truncation and rejection sampling in `randint` make it harder than for raw outputs. It doesn't need to be exploitable to be wrong: **everything generated for a security purpose must use `secrets`.** This is Stage 1's first change.

### A correction to earlier guidance

An earlier discussion said storing "a hash of the code" is sound because the code is random. That is true for a 256-bit bearer token, not for a 30-bit code: an unsalted SHA-256 of a 30-bit value can be brute-forced in seconds by anyone who reads the database. What protects a live invite is that it lives **minutes** and its row is **deleted on use**. To also protect it from a database-only thief, store `HMAC-SHA256(server_key, code)` with the key held outside the database. That ties this to T-20: `SECRET_KEY` currently has an insecure default, so the app must refuse to start with it outside debug mode before it is used as an HMAC key.

## Stages (one PR each)

1. **Opaque chat id, and `secrets` everywhere. (Done.)** Add `Chat.public_id`; route on it (API paths, websocket group `chat_<public_id>`); return it as `chat_id` from create/join so the client barely changes; switch the remaining `random` use to `secrets`. Still no invites: the 4-digit PIN stays as the join mechanism for now. Fixes the recycled-PIN websocket cross-talk (T-19, the PIN-reuse half), takes the PIN out of every request path after the join (it still appears in the join request itself and in the `[JOIN-CHAT]` log line until Stage 2; T-12's logging fix is separate), and separates address from secret. **Breaking:** in-flight chats end on deploy (their stored `chat_id` no longer resolves). There is precedent: migration 0021 wiped pre-forward-secrecy messages.
2. **Invites.** `ChatInvite` model; `POST /chat/create-invite/<chat_id>/` (any member); `create-chat` issues the first invite; join takes handle+code; per-invite atomic attempt cap; check character; single use; expiry; generic errors; keyed-hashed code. UI: two-part input in `usermenu.html`, invite display with expiry and "new invite" in the waiting overlay. Removes `Chat.pin`, the per-IP limiter (#95) and `check-chat` (#96, which has no first-party caller). Bounds the resource at the source: handles exist only while an invite is open.
3. **Companion (issue #100).** Roster-change notices, unique display names per chat, and the **fingerprint gate** before the first message to a new participant. Stage 2 makes admission deliberate; this makes a wrongly admitted person visible.
4. **Optional, later.** A PAKE, if a vetted implementation exists (see above).

## Decisions (settled 2026-09-21)

| # | Question | Decision | Consequence to carry |
|---|---|---|---|
| 1 | Code shape | **6 Crockford-base32 characters** (30 bits) | No wordlist to vendor or license. Harder to read aloud than words; the check character catches typos. |
| 2 | Wrong attempts before burn | **3** | Forgiving of honest typos while keeping the odds at ~3 in a billion per invite. Typos still spend the budget, so the client validates the check character first. (Set to 1 earlier the same day, then raised to 3 as too strict.) |
| 3 | Who may issue invites | **Any current member**, every issuance announced to the roster | A group isn't stranded if the creator leaves. |
| 4 | Burn vs timed lockout | **Permanent burn** | Fails safe, no timer state. A burned invite is replaced, not revived. |
| 5 | Invite lifetime | **15 minutes** | A slow friend means regenerating. |
| 6 | Handle length | **6 digits** | ~1 million handles. |

Consequences of the 3-attempt cap that the implementation must respect:

- **Typos still spend the budget.** The check character over the whole `handle-code` string is validated in the client *and* the server, and a bad checksum charges no strike to any invite. It is included but not essential; see the note above.
- **A mistyped handle can hit another live invite.** That costs a stranger's invite one strike of three. With the check character the residual chance is a typo that still passes the checksum.
- **Burn-DoS costs about 3 million requests** (three sweeps of the ~1 million handles) to burn every open invite. Accepted: it fails safe (no confidentiality loss) and Tor Client Authorization (#62) is the real gate against strangers reaching the app. Revisit the handle length (decision 6) if this is ever a public instance.
- **The creator must be told** when an invite burns, so a burn is a visible event, not a silent failure.

## What this does not fix

- **The server still sees the code** (it verifies it), so a malicious server can join or intercept: T-04.
- **A leaked code** is a leaked invitation until used or expired. Single use, expiry and the fingerprint gate limit it; nothing removes it.
- **Burning invites** remains possible (DoS, not compromise).
- **Typing cost:** 13 characters (6-digit handle, 6-character code, check character) instead of 4 digits. That is the price of moving from 13 bits to a secret worth having.

## Tests the implementation must carry

- **Concurrent guesses:** N simultaneous wrong codes on one invite result in at most 3 evaluated attempts, then burned.
- **Check character:** a one-character typo in the handle or the code is rejected before any invite is touched, on both client and server, and burns nothing.
- **Creator notification:** a burned invite is reported to the issuing member.
- **Uniformity:** nonexistent, expired, burned, consumed and wrong-code responses are byte-identical in status and body.
- **Single use and expiry:** a consumed or lapsed invite never admits; its handle is reusable afterward.
- **No id reuse:** a deleted chat's `public_id` is never issued again.
- **Randomness:** chat id, handle and code all come from `secrets` (assert no `random` import in the generation path).
- **Migration:** in-flight chats end cleanly; the client returns to the dashboard instead of looping.

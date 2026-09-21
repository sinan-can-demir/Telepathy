# Threat Model & Security Assessment

**Read this before you decide to use Telepathy, and before you tell anyone else to.**

- **Code reviewed:** `main` at commit `123be67` (2026-09-21), including the per-chain message index from #92.
- **Reviewer:** an AI assistant (Claude), working in a single session at the maintainer's request. This is a careful review with running evidence, **not** an independent audit, and it is not a substitute for one.
- **Relationship to other docs:** `docs/SECURITY_AUDIT.md` (2026-09-18) hunted implementation bugs in the crypto/auth core, and those are fixed. This document asks a different question: *who could attack this system, what could each of them actually do, and is that acceptable for your use?* It also records findings that audit did not cover. `ARCHITECTURE.md` ("Accepted limitations") and the per-feature docs remain accurate; this pulls them together and adds what was missing.

---

## 1. TL;DR

Telepathy is a well-documented, thoughtfully built **learning project**. Its cryptographic layering is better than most hobby E2EE chat apps, and the project has been unusually honest about its own limits. But measured against its README ("privacy is guaranteed by design"), three things stand out:

1. **The only thing standing between a stranger and your chat is a 4-digit PIN, and the rate limiter that guards it can be bypassed** (T-01, T-02, T-03). Anyone who can reach the server can list every live chat and its participants' names, guess the PIN, and be admitted to a chat with no confirmation from its members.
2. **Two headline promises are weaker than advertised.** *Forward secrecy* does not hold against an attacker who has both a copy of the server's data and a participant's device key (T-05), which is the exact scenario forward secrecy exists for. *"History is deleted once everyone has left"* holds only for people who click Leave; closing the tab leaves the chat, its ciphertext and its PIN on the server indefinitely (T-07).
3. **Whoever runs the server is trusted more than the README implies.** A malicious or compromised server can substitute keys from the first message and can serve modified JavaScript that defeats every client-side check (T-04). This is inherent to a browser-delivered web app and is already recorded as an accepted limitation; it is the single most important fact for deciding whether to use it.

Not audited by anyone independent. Not suitable for whistleblowing, source protection, or any situation where being wrong has serious consequences (see §7).

### Where it stands, by adversary

| If your adversary is… | Verdict | Why |
|---|---|---|
| Someone on your Wi-Fi / your ISP | **Fine** (over TLS or Tor) | Content is E2EE; transport is encrypted. |
| A random person who finds the server | **Weak** | PIN is guessable; chats are enumerable; server is DoS-able (T-01/02/06/08). Tor client authorization (§6) closes most of this. |
| A curious host who doesn't tamper | **Content safe, metadata exposed** | Sees who, when, how often, group membership (T-11). |
| A malicious or compromised server | **Not protected** | Can MITM from message one and ship altered code (T-04). Only self-hosting plus out-of-band fingerprint checks helps. |
| Someone who steals a DB dump or backup | **Content safe today; long tail of risk** | Ciphertext and wrapped keys are kept far longer than advertised (T-05, T-07, T-23). |
| Someone who seizes or infects your device | **Not protected** | Full history, keys' *use*, and the session token are recoverable (T-15). |
| A state-level / global passive adversary | **Not protected** | Timing correlation, no cover traffic (T-11, accepted #63). |

---

## 2. Scope, method, and what was *not* assessed

**Reviewed:** every Python module in `chat/` and `pc/`; the full client (`chatbox.html`, `usermenu.html`, `index.html`); the container, compose, Tor and CI configuration; every existing security doc; the pinned dependency set.

**Method:** full read of server and client code; then *running* the riskiest suspicions rather than only asserting them. Each finding below carries one evidence tag:

| Tag | Meaning |
|---|---|
| **Verified** | Reproduced by running code against this repository. The probe is in `docs/threat-model-probes/` (§9). |
| **Code-read** | Follows from reading the code; not run. Reasonably certain, but weaker evidence. |
| **Documented** | Already recorded by the project in an existing doc; included here for completeness. |

**Not assessed** (treat these as unknown, not as "fine"): behaviour in a real browser end-to-end (no click-through was done); the Tor network path, the `tor` container's runtime behaviour, or host/OS hardening; TLS termination for a clearnet deployment (nothing in the repo configures it); Postgres and Redis configuration; traffic captures; fuzzing; reachability of the dependency vulnerabilities in §T-13; any formal analysis of the hand-rolled protocol; social engineering, legal, or physical threats beyond what is noted. Django, DRF, Channels and the browser's WebCrypto were assumed correct.

---

## 3. What is being protected

| Asset | Where it lives | Who could want it |
|---|---|---|
| Message plaintext | Sender's and recipients' browsers only | Everyone below |
| Message keys / chain seeds | Browser IndexedDB; **RSA-wrapped copies on the server** (see T-05) | Server-side attackers, device attackers |
| Who talks to whom, and when | Server DB, logs, network timing | Operators, observers, coercive parties |
| Chat membership / access (the PIN) | Server DB; shared out-of-band by users | Outsiders, guessers |
| Transcript integrity (no dropped/forged messages) | Hash chain + MACs, checked by clients | Malicious server or member |
| Availability (able to create/join/use a chat) | Server | Anyone wanting disruption |
| Operator secrets (`.onion` key, Django secret, DB creds) | Container env / volumes | Anyone attacking the deployment |

---

## 4. System and trust boundaries

```
                    ┌─────────────────────────────┐
  Browser A ──┐     │  Server operator's domain   │
  (keys,      │ TLS │ ┌──────────┐   ┌─────────┐  │
  plaintext,  ├─or──┼─► daphne /  ├──►│Postgres │  │  ciphertext, wrapped seeds,
  history)    │ Tor │ │ Django   │   └─────────┘  │  roster, timestamps, read
  Browser B ──┘     │ │ (serves  │   ┌─────────┐  │  receipts, PINs, names
                    │ │  the JS!)├──►│ Redis   │  │  ("something happened" signals
   ▲ trusts the     │ └──────────┘   └─────────┘  │   only — no content)
   server to serve  │  chat_debug.log (T-12)      │
   honest code      └─────────────────────────────┘
```

Two trust facts follow from the picture and drive most findings:

- **The server is the key directory, the PIN gatekeeper, and the code distributor.** Each participant's public key reaches the others only via the server (TOFU can detect a *later* change, not a substitution from the start). Every page load runs whatever JavaScript the server sends.
- **The browser holds the crypto identity.** A chat's RSA key, chain keys and per-message keys live in the browser profile for the chat's whole life.

---

## 5. Adversaries considered

| ID | Adversary | Capabilities assumed |
|---|---|---|
| **A1** | Passive network observer | Sees traffic to/from the server or the Tor entry. |
| **A2** | Global passive adversary | Correlates traffic timing across the network. |
| **A3** | Anonymous outsider | Can send HTTP(S)/Tor requests to the server; knows nothing else. |
| **A4** | Malicious chat participant | Holds a valid PIN and token; may be a group member. |
| **A5** | Curious operator | Runs the server honestly but reads DB, logs, network metadata. |
| **A6** | Malicious / compromised server | Can alter any response, drop messages, ship modified JS. |
| **A7** | Data thief | Gets a copy of DB / backups / logs, offline, once or over time. |
| **A8** | Device attacker | (a) runs code in the victim's browser (XSS, malware); (b) seizes or images the device. |
| **A9** | Supply-chain attacker | Compromises a dependency or base image. |
| **A10** | Future cryptanalyst | Stores today's ciphertext; breaks RSA-2048 later. |

### Exposure matrix

`●` protected · `◐` partially / with caveats · `○` not protected · `—` not applicable

| Adversary | Content confidentiality | Transcript integrity | Anonymity / metadata | Availability |
|---|---|---|---|---|
| A1 Network observer | ● (TLS/Tor) | ● | ◐ IP visible on clearnet; sizes bucketed | — |
| A2 Global passive | ● | ● | ○ timing correlation (#63) | — |
| A3 Outsider | ◐ can join open chats (T-01–03) | ◐ | ◐ enumerates live chats + names | ○ T-06, T-08, T-16 |
| A4 Malicious member | ● past epochs / ◐ future | ◐ can send garbage, forge in collusion (T-24) | ◐ | ◐ |
| A5 Curious operator | ● | — | ○ full metadata (T-11, T-12) | — |
| A6 Malicious server | ○ MITM + code (T-04) | ○ silent censorship (T-09/10) | ○ | ○ |
| A7 Data thief | ● now / ◐ over time (T-05, T-23) | — | ○ | — |
| A8 Device attacker | ○ (T-15) | ○ | ○ | — |
| A9 Supply chain | ○ (T-13) | ○ | ○ | ○ |
| A10 Future cryptanalyst | ○ if ciphertext retained (T-23) | — | — | — |

---

## 6. Findings

**Severity** is judged against what Telepathy claims to be, assuming the deployments in `README.md`. **High**: an outsider or normal-operation adversary breaks a headline promise with modest effort, or a headline claim does not hold in the scenario it names. **Medium**: needs a stronger position (operator, member, device) or has bounded impact. **Low**: hardening or minor leakage. Fix suggestions are directions, not designs.

### Summary

| ID | Sev | Finding | Adversary | Evidence |
|---|---|---|---|---|
| T-01 | High | 13-bit join secret; join rate limiter bypassable | A3 | Verified |
| T-02 | High | Unauthenticated, unthrottled enumeration of live chats and participant names | A3 | Verified |
| T-03 | High | Admission is silent; names unverifiable; groups auto re-key to intruders | A3 | Verified + Code-read |
| T-04 | High | Server can MITM keys from message one and ship altered client code | A6 | Documented + Code-read |
| T-05 | High | Forward secrecy is bounded by the RSA key's lifetime | A7 + A8 | Verified |
| T-06 | High | Anonymous, permanent PIN-space exhaustion; `create_chat` hangs when full | A3 | Verified |
| T-07 | High | Abandoned chats, ciphertext and PINs are never reclaimed; ghost seats | A3, A5, A7 | Verified |
| T-08 | Med | One client's failed joins lock out every client sharing an address | A3 | Verified |
| T-09 | Med | Unauthenticated `chain_index` lets a server silently destroy single messages | A6 | Verified |
| T-10 | Med | Transcript tamper-evidence has gaps; undecryptable messages vanish silently | A6 | Code-read |
| T-11 | Med | Rich metadata visible to the operator and any data thief | A5, A7 | Verified + Documented |
| T-12 | Med | Logs persist PINs, display names, addresses, unrotated | A5, A7 | Verified |
| T-13 | Med | 42 known advisories across 7 pinned dependencies | A9 | Verified |
| T-14 | Med | No Content-Security-Policy; no `no-store`; XSS surface currently clean | A8a | Verified + Code-read |
| T-15 | Med | A seized or infected device yields history, key use and the session token | A8 | Code-read |
| T-16 | Med | No request-size limits; no field validation on ciphertext | A3, A4 | Verified |
| T-17 | Med | Disappearing messages are best-effort and easily blocked | A4, A7 | Code-read |
| T-18 | Med | Django admin reachable on the public origin | A3 | Verified |
| T-19 | Low | WebSockets outlive membership; signals cross over on PIN reuse | A4 | Verified |
| T-20 | Low | Configuration defaults fail open | A3, A9 | Code-read |
| T-21 | Low | Deployment hardening gaps | A9 | Code-read |
| T-22 | Low | Minor identifier and validation leaks | A3 | Verified |
| T-23 | Low | Crypto limits: RSA-2048, hand-rolled and unreviewed, no post-compromise security | A10 | Documented + Code-read |
| T-24 | Low | Powers of a malicious member; deniability caveat in groups | A4 | Code-read |

---

### T-01 · High · The join secret is 13 bits and the throttle is bypassable

**Adversary:** A3. **Evidence:** Verified (probe 1).

A chat is joined with a 4-digit PIN: 10,000 possibilities. `JoinChatView` limits failed attempts per source address, but `_client_ip()` (`chat/views.py`) reads the client-supplied `X-Forwarded-For` header first. Sending a different value per request gives every attempt its own fresh bucket.

**Observed:** one address is throttled after 4 failures (control). Rotating `X-Forwarded-For`, an attacker guessed the PIN of a live chat in 8,027 attempts with **zero** throttled responses, creating 8,026 limiter buckets that are never evicted. The probe is in-process, so the wall-clock time (56 s) understates real cost, but the absence of any throttle is the finding. Under the Tor deployment all clients share the loopback address (see T-08); the header trick should work there too, since Django reads the header the same way, but the Tor path itself was not exercised.

**Impact:** anyone who can reach the server can enter any chat that has a free slot. Combined with T-02 the attacker doesn't even need to guess blindly.

**Today's mitigation:** Tor Client Authorization (`docs/INVITE_ONLY_ONION.md`) stops non-invited clients from reaching the app at all, and is the strongest existing control. Tor's PoW defence limits connection floods, not targeted guessing.

**Fix direction:** never trust `X-Forwarded-For` unless set by a proxy you control; count failures per *target PIN* and globally, not per claimed address; cap or slow all joins to a PIN; lengthen the join secret (more digits, or PIN plus a passphrase) since 13 bits cannot be made safe by throttling alone; evict stale limiter entries.

### T-02 · High · Anyone can list every live chat and who is in it

**Adversary:** A3. **Evidence:** Verified (probe 3).

`GET /chat/check-chat/<pin>/` needs no authentication, has no throttle, and returns `{"exists": true, "participants": ["alice", …]}`.

**Observed:** all 10,000 PINs swept in 60 s with zero throttled responses, returning the three live chats and every participant's display name.

**Impact:** converts blind PIN guessing into a targeted attack; leaks participant names; reveals chat activity to anyone.

**Fix direction:** return only `exists` and free-slot count (or nothing until a join attempt), throttle it like joins, and never return names to non-members.

### T-03 · High · Admission is silent, and names can't be trusted

**Adversary:** A3 (with T-01/T-02). **Evidence:** Verified (probe 6, names) + Code-read (admission).

- Nothing asks the existing members to approve a joiner. A 1:1 chat simply starts when the second participant appears; a group silently admits anyone while a seat is free.
- Display names are chosen by the joiner, unverified, and **not unique**: a second participant named "alice" joined a chat that already had an "alice" (roster shown as `['alice', 'alice']`). An intruder can wear the expected friend's name.
- The client pins a new participant's key on first sight without any prompt (`verifyAndPinKey`), and each member's next send re-keys to include them (`ensureMyChainKey`). So an intruder in a group receives every *subsequent* message from every member. They cannot read earlier ones.
- The fingerprint shown in the header is display-only. Nothing gates sending on a person having compared it.

**Detectability:** in a 1:1 chat, if the intruder wins the race, the intended friend gets "Chat is full". Members who notice can tell; the app does not tell them.

**Fix direction:** creator-approval or "lock chat" once the expected people have joined; require a fingerprint acknowledgement before the first send; show a persistent "N people are in this chat" indicator and a notice on every roster change; enforce unique display names per chat (and reject the trailing-newline case, T-22).

### T-04 · High · The server can MITM from message one and rewrite the client

**Adversary:** A6 (also an attacker who compromises the server). **Evidence:** Documented (`docs/KEY_VERIFICATION.md`, `ARCHITECTURE.md` #42) + Code-read.

The server distributes every public key and every line of JavaScript. Consequently a malicious or compromised server can:

- **Substitute keys from the start.** TOFU only catches a change *after* first sight. If the first key each side sees is the attacker's, both pin it. The fingerprint exists to catch this, but only if users compare it out-of-band.
- **Ship modified JavaScript** that disables verification, exfiltrates plaintext, or leaks keys. None of the client-side defences (TOFU, hash chain, MAC) can catch tampering with the code that runs them. Accepted as #42.
- **Force a key wipe.** The client destroys all local keys on any `403`/`404` from `/get-messages/` (`handleSessionEnded`, `chatbox.html`), so the server can trigger message loss on demand.
- Drop, delay or reorder messages (partly detectable, see T-10).

**This is the fundamental limit of browser-delivered E2EE, not a Telepathy bug.** It matters most: *if the operator is in your threat model, only self-hosting plus real fingerprint verification gives you anything.*

**Fix direction:** none within the current architecture; a pinned native client or reproducible/verifiable web delivery is the real fix (#42, deferred).

### T-05 · High · Forward secrecy is bounded by the RSA key's lifetime

**Adversary:** A7 + A8 (one alone is not enough). **Evidence:** Verified (probe B in `crypto_probe.js`).

The ratchet is one-way, so stealing the *current chain key* does not reveal past messages. That is true, and it is what `docs/FORWARD_SECRECY.md` proves. But a chain's starting seed is RSA-OAEP-wrapped to each recipient and **kept on the server for the chat's whole life** (`ChainKeyWrap`, returned by `/get-chain-keys/`). Each sender's per-message key is also RSA-wrapped to the sender and kept (`MessageKey`). The RSA private key lives in the recipient's browser until they leave.

**Observed:** after a receiver had ratcheted past four messages (their live chain state advanced, old keys discarded), an attacker holding only the RSA private key, the server's stored wrapped seed and the ciphertext derived all four keys from index 0 and decrypted every message.

**Impact:** the scenario forward secrecy exists for, an adversary who has been *keeping* ciphertext and later compromises a device, is not defended. The server operator (or anyone with a DB copy) is exactly such a keeper. The README's "stealing current key material can't unlock messages sent before that point" is true only for chain-key theft alone. The doc's "What the server sees" section addresses the sender's self-wrap, but not the retained recipient seed.

**Caveats:** needs two things (data copy + key access). A non-extractable key can't be exported by JavaScript, but it can be *used* by any script in the page (T-14) and, as far as I know but did not test, is persisted in the browser profile in a form recoverable by someone with disk access (T-15).

**Fix direction:** deliver seeds once and delete them server-side after fetch; stop storing per-message self-wraps (keep the sender's message keys locally, as receivers already do); ideally transport seeds under per-epoch ephemeral keys that are destroyed after use. Relay-only mode (#90) also shrinks what is retained.

### T-06 · High · Anyone can permanently exhaust the PIN space, and `create_chat` then hangs

**Adversary:** A3. **Evidence:** Verified (probe 4).

`POST /chat/create-chat/` is unauthenticated and unthrottled (300 anonymous creates in 3.2 s, all `201`). There are only 10,000 PINs, and nothing reclaims abandoned chats (T-07), so an attacker can occupy all of them and keep them. Worse, `services.create_chat` is `while True: pick random PIN; if unused: break` with no exit: with the space full, every legitimate create request **spins forever** (20,001 draws before the probe cut it off) and pins a worker.

**Impact:** a single anonymous client can take out chat creation for everyone, indefinitely, until the operator intervenes. On the order of minutes of requests.

**Fix direction:** bounded retries returning `503`; per-source create throttle; reap idle chats (T-07); consider a larger identifier space.

### T-07 · High · Abandoned chats, ciphertext and PINs are never reclaimed

**Adversary:** A3 (squatting), A5/A7 (retention). **Evidence:** Verified (probe 5).

The README promises "Message history is automatically deleted once every participant has left." That is true only if each participant clicks **Leave**. Closing the tab, losing a device, or clearing storage sends nothing (the old `sendBeacon` was removed, #71). The replacement, a 30-minute idle timeout, is applied *lazily, only when that same participant next authenticates*, and even then it only sets `left_at`.

**Observed:**
- After 30 days with nobody returning: the chat still exists, both participants are still listed as active, ciphertext still stored, and a third party is refused with "Chat is full" (the ghosts hold the seats).
- After both idle-expired participants finally made a request: **0 active participants, but the `Chat` row and its messages remain** and the PIN stays taken. Only `leave_chat()` deletes an emptied chat.

**Impact:** ciphertext, wrapped seeds, roster and timestamps are retained indefinitely for the common exit path (feeds T-05, T-11, T-23); PINs leak permanently (feeds T-06); a participant who loses their local state can never rejoin (their seat is held by a token they no longer have); disappearing messages can't expire (T-17).

**Fix direction:** a scheduled reaper (management command/cron) that expires idle participants and deletes empty or long-idle chats; make the idle path delete an emptied chat like `leave_chat` does; consider relay-only mode (#90).

### T-08 · Medium · One client's failures lock out everyone behind the same address

**Adversary:** A3. **Evidence:** Verified (probe 2).

With no forwarded header the limiter buckets by `REMOTE_ADDR`. Under the Tor deployment every client shares the loopback address. Five bad guesses made a *valid* PIN return `429 "Try again in 9 seconds"`, and the wait doubles with each further failure. One request per window sustains the lockout.

**Impact:** trivial denial of joins for all users of a Tor-hosted instance. (Removing the limiter would worsen T-01; this needs a redesign, not a deletion.)

**Fix direction:** per-target-PIN failure accounting, not per-address; keep Tor Client Authorization as the real gate.

### T-09 · Medium · A server can silently and permanently destroy individual messages

**Adversary:** A6. **Evidence:** Verified (probe A in `crypto_probe.js`). Introduced by #92 (merged 2026-09-20).

`chain_index` is deliberately not MAC'd or hashed ("a lie just fails AES-GCM"). But in `deriveReceivedKeys` the client, *before* decrypting, (1) ratchets forward to the claimed index, (2) stores every skipped key, (3) caches the derived key under the message id, and (4) commits the new chain position. `renderMsg` then drops a message that fails to decrypt with only a console warning.

**Observed:** a message served with `chain_index=50` instead of `0` failed to decrypt; served *honestly* later, it **still** failed (the wrong key is cached under its id and reused forever). Later honest messages were fine. The tampered field is not in `computeChainHash`, so the tamper-evidence banner never fires.

**Impact:** the very feature meant to reveal a server dropping a message (the hash chain) is blind to this stealthier way of doing it. A tampering server can also make a client store up to `MAX_SKIP=100` skipped keys per message, never expiring.

**Fix direction:** derive-then-verify-then-commit (only cache and advance after a successful decrypt); don't cache a failed derivation; bind `chain_index` into the hashed or MAC'd fields; surface decrypt failures in the UI (T-10).

### T-10 · Medium · Transcript tamper-evidence has gaps

**Adversary:** A6. **Evidence:** Code-read.

The hash chain is real and catches dropped/reordered/altered *interior* messages. Its limits:

- **The newest message is unchained.** Altering or truncating the tail can't be caught by a later message's `prev_hash`, because none exists yet.
- **Split view.** A server can show different members different, each internally consistent, transcripts. The chain cannot expose this. The only defence is comparing the transcript fingerprint out-of-band, which is optional.
- **Silent drop.** `renderMsg` swallows any decrypt failure without telling the user a message existed (`return; // skip broken messages`), and `renderedIds` is set first, so it is never retried in-session.

**Fix direction:** show "N messages could not be decrypted", and treat repeated failure as a tamper signal; encourage or require tip-fingerprint comparison.

### T-11 · Medium · The operator sees a lot

**Adversary:** A5, A7. **Evidence:** Verified + Documented (`#59`, `#63`, `ARCHITECTURE.md`).

Content is opaque, but the server and any data thief see:

| Data | Detail |
|---|---|
| Chat identity | PIN, size, group or not, creation time |
| Participants | Display name, public key, `joined_at`, `left_at`, and **`last_seen` refreshed on every request**, so a near-live presence signal |
| Messages | Sender, count, exact insertion timestamp (the API coarsens to the minute; **the database does not**), ciphertext size to a 256-byte bucket, per-message TTL choice |
| Reads | For expiring messages, per-participant `read_at` |
| Epochs | Who re-keyed when, and to whom, so membership history |
| Network | Client IP on clearnet; on Tor, request timing and sizes |

Timing correlation by a global observer (sender's POST, receivers' immediate refetch) is accepted as #63. Accountless identity does prevent cross-chat linkage *by the app*; on clearnet, IP address and timing still link a person's chats.

### T-12 · Medium · Logs persist PINs, names and addresses

**Adversary:** A5, A7. **Evidence:** Verified.

`pc/settings.py` sends the root logger at `DEBUG` to a file (`chat_debug.log`, never rotated) and to the console. From a live run the file contained: `[JOIN-CHAT] 'probe-bob' joined chat '8413'.`, every request path including the PIN (`/chat/check-chat/8413/`), and access-log lines with client address and latency. Under clearnet the address is real; under Tor it is loopback.

**Impact:** a log copy gives roster/PIN/name/timing history that outlives the chat, and the file grows without bound.

**Fix direction:** stop logging PINs and names; log to stdout only in containers; rotate; keep `INFO` or higher.

### T-13 · Medium · Known-vulnerable dependencies

**Adversary:** A9. **Evidence:** Verified (`pip-audit` on `requirements.txt`, 2026-09-21).

42 unique advisories across 7 of the 20 pinned packages: Django 5.1.5 (18), cryptography 44.0.0 (7), urllib3 2.3.0 (6), sqlparse 0.5.3 (6), djangorestframework 3.15.2 (2), requests 2.32.3 (2), idna 3.10 (1). Several of the newest Django fixes exist only in 5.2.x/6.0.x, which suggests the 5.1 branch no longer receives security fixes (not independently confirmed against Django's release notes). **Reachability was not analysed**, so this is a list of exposure, not of exploitable bugs. Dependencies are not hash-pinned and base images use floating tags.

**Fix direction:** move to a supported Django (5.2 LTS) and current pins; `pip-compile --generate-hashes`; add Dependabot or a scheduled `pip-audit` CI job; pin image digests.

### T-14 · Medium · No CSP or `no-store`, though the XSS surface is currently clean

**Adversary:** A8a. **Evidence:** Verified (headers) + Code-read (rendering).

**Good news:** every user- or server-supplied string reaches the DOM via `textContent`; the two `innerHTML` uses interpolate only constants; display names are charset-restricted server-side; Django templates auto-escape; no third-party scripts or fonts load. Set correctly by Django: `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, COOP.

**Gap:** there is **no `Content-Security-Policy`**, so a future slip, or a compromised template, runs with full authority and can exfiltrate to anywhere. All script is inline, so a strict CSP needs nonces. API responses carrying ciphertext also send no `Cache-Control: no-store`. `Server: daphne` is disclosed.

### T-15 · Medium · What a seized or infected device yields

**Adversary:** A8. **Evidence:** Code-read.

- **Non-extractable is not encrypted at rest.** It stops JavaScript from *reading* the key; it does not stop code in the page from *using* it, and (untested here) the browser must persist it in the profile to survive restarts, so disk access should be treated as key access unless the OS encrypts the profile.
- IndexedDB holds the RSA key, the bearer token (a plain string), chain keys, **and a cached key for every message ever received** (`msgkey_*`). With the server's ciphertext (or an A7 copy) those decrypt the whole history of that chat on that device.
- `localStorage` holds the chat PIN, participant id, pinned keys and chain epoch in the clear.
- The create/join URL carries the PIN and display name in its query string. It is replaced with `replaceState`, but the browser may have already recorded the original URL (not tested).
- Nothing locks the app; there is no PIN, timeout, or panic-wipe. Leave destroys keys; closing the tab does not.

**Fix direction:** advise a dedicated browser profile on an encrypted disk; consider an idle-lock and an explicit "wipe now" action; long-term, T-05's fixes reduce what a device holds.

### T-16 · Medium · No size limits, no field validation

**Adversary:** A3, A4. **Evidence:** Verified.

A 30 MB anonymous JSON body to `/create-chat/` was accepted with `201` on a real server. (The likely cause is that DRF streams the body rather than reading `request.body`, which would bypass Django's `DATA_UPLOAD_MAX_MEMORY_SIZE`; that mechanism was inferred from the behaviour, not confirmed.) A participant's 5 MB non-base64 "ciphertext" with junk nonce, tag and MAC was accepted and stored as-is, and a garbage "wrapped seed" was accepted.

**Impact:** cheap storage/bandwidth exhaustion by anyone; any member can poison a chat with undecryptable data (which the client then drops silently, T-10).

**Fix direction:** enforce a body-size cap at the proxy/ASGI layer; validate base64 and lengths per field; per-chat message/size quotas.

### T-17 · Medium · Disappearing messages are best-effort

**Adversary:** A4, A7. **Evidence:** Code-read (`services.sweep_expired_messages`).

- A message expires only after **every** participant who was present at send time has fetched it *and* their TTL has run. One idle, ghosted (T-07) or malicious member who never fetches blocks expiry for everyone, indefinitely.
- The sweep is lazy: it runs only when somebody fetches messages.
- Any recipient can screenshot or copy; the local fade is cosmetic. Backups and logs taken before the wipe are unaffected.

Treat TTL as a courtesy, not a guarantee.

### T-18 · Medium · Admin panel on the public origin

**Adversary:** A3. **Evidence:** Verified (`GET /admin/login/` → 200).

`/admin/` is served on the same origin (and `.onion`) as the chat, with no throttle. Compromise of a staff password exposes the full metadata set in T-11 and lets an attacker delete chats. It shows no plaintext.

**Fix direction:** remove `django.contrib.admin` from production, or serve it on a separate, access-controlled address.

### T-19 · Low · WebSockets outlive membership

**Adversary:** A4 (ex-member). **Evidence:** Verified (probe 8).

Authentication happens once at connect. After a participant **left**, their socket kept receiving `new_message` signals; after the chat emptied and the **PIN was reused for an unrelated chat**, the old socket still received that stranger chat's signals. Signals carry no content, only "something happened", but that is metadata about a chat the listener has no right to. There is also no origin check on the socket (mitigated by the bearer-token requirement).

**Fix direction:** close or evict sockets on leave/expiry/delete; re-check membership on each push; add `AllowedHostsOriginValidator`.

### T-20 · Low · Configuration fails open

**Evidence:** Code-read.

`DJANGO_SECRET_KEY` falls back to a published dev string; DB credentials default to `mysecretpassword`. Only `compose.yaml` forces you to set them. `SECURE_PROXY_SSL_HEADER` trusts a client-supplied header unless a proxy strips it. `ALLOWED_HOSTS` hard-codes `project2-2-telepathy.work`, a domain inherited from the original project. Cookies use `SameSite=None` in secure mode.

**Fix direction:** refuse to start with the default key when `DEBUG` is false; drop the inherited host.

### T-21 · Low · Deployment hardening

**Evidence:** Code-read.

Good: nothing publishes a host port, the app runs as a non-root user, Tor drops privileges, secrets come from env, a secret scanner runs in CI. Gaps: the Tor container shares the app's network namespace, so a Tor-daemon exploit lands beside the database and Redis network; Redis has no authentication; no container resource limits; Postgres data is unencrypted at rest; images use floating tags; no backup, retention or log-retention guidance. The Tor path and container runtime were not exercised in this review.

### T-22 · Low · Minor identifier and validation leaks

**Evidence:** Verified.

Participant ids are global auto-increment integers returned to clients (`participant_id`, `sender_id`), leaking overall service volume. `is_valid_display_name` uses `$`, which accepts a trailing newline (`"alice\n"` validates).

### T-23 · Low · Cryptographic limits

**Evidence:** Documented + Code-read.

- **Not post-quantum.** Seeds and self-wrapped keys use RSA-2048. Because the server *retains* wrapped seeds and ciphertext (T-05, T-07), it is an attractive harvest-now-decrypt-later target.
- **Hand-rolled protocol, never externally reviewed.** The primitives (AES-GCM, HMAC-SHA-256, RSA-OAEP) are standard and used sensibly (fresh 96-bit IVs under per-message keys, so no nonce reuse); the *composition* is novel.
- **No post-compromise security** (#60, accepted): a stolen chain key exposes that sender's future messages until the next roster-change re-key.
- Length hiding is to 256-byte buckets, not exact.

### T-24 · Low · What a malicious member can do

**Evidence:** Code-read.

Cannot: read messages from before they joined, post as someone else through the server (the server sets `sender_id` from the token), or remove anyone. Can: send undecryptable garbage (T-16), advance others' ratchets by jumping `chain_index` and make them store skipped keys (T-09), never fetch and so block expiry (T-17), stay in a group indefinitely with no way to be evicted, and learn all members' names.

**Deniability caveat:** the MAC is derived from the ratchet, so any member who holds a sender's seed can compute valid MACs for that sender. That is the point of deniability and safe against outsiders. In a group, a malicious member *colluding with a malicious server* (which controls the recorded `sender_id`) could inject a message that verifies as another member's.

---

## 7. Is Telepathy right for you?

| Situation | Verdict |
|---|---|
| Learning how E2EE chat, ratchets, TOFU and Tor services fit together | ✅ Good fit; the docs are a real asset. |
| Casual private chat with friends on a server **you** run, over Tor with client authorization, fingerprints compared out-of-band | 🟡 Reasonable, with the checklist below. |
| Chat on someone else's server, or a public instance | 🟡 Content is protected from casual snooping; the operator can see metadata and could, if malicious, defeat the crypto (T-04). |
| Sensitive business, legal, medical, or regulated conversations | 🔴 No: unaudited, retention behaviour differs from the promise (T-07). |
| Journalist/source, dissident, or any adversary with state resources | 🔴 No. Use an audited tool (Signal, or Briar/Tor-based options). |
| You need guaranteed deletion, non-repudiation, multi-device, or offline delivery | 🔴 Not provided. |

### Operating checklist (if you deploy or use it anyway)

1. **Run the server yourself.** If the operator is in your threat model, nothing else matters (T-04).
2. Prefer the **Tor deployment with Client Authorization** (`docs/INVITE_ONLY_ONION.md`). It is the only existing control that stops strangers from reaching a chat (T-01/02/06/08).
3. **Share the PIN over an authenticated, private channel**, and use each PIN once.
4. **Compare the key fingerprint and transcript fingerprint out-of-band before saying anything sensitive.** If your friend sees "Chat is full", or the participant count is wrong, treat the chat as compromised (T-03).
5. **Click Leave** when done; don't just close the tab (T-07).
6. Don't rely on disappearing messages (T-17).
7. Use a **dedicated browser profile on an encrypted disk**; log out of the OS when unattended (T-15).
8. Operators: set `DJANGO_SECRET_KEY`; disable the admin (T-18); stop logging PINs/names and rotate logs (T-12); update dependencies (T-13); cap request sizes (T-16); reap idle chats (T-07); don't publish extra ports.

---

## 8. Remediation roadmap

Suggested order by value per effort. Nothing here has been filed or implemented.

**Quick wins (hours to a day)**
- Stop trusting `X-Forwarded-For`; per-PIN failure accounting; throttle and slim down `check-chat` (T-01, T-02, T-08).
- Bounded `create_chat` retries plus a create throttle (T-06).
- Stop logging PINs and names; stdout only; rotate (T-12).
- Bump dependencies; add `pip-audit`/Dependabot; hash-pin (T-13).
- Fail closed on the default secret key; drop the inherited host (T-20).
- Remove or isolate the admin (T-18).

**Medium (days)**
- Reaper for idle participants and empty/idle chats; make idle expiry delete an emptied chat (T-07).
- Derive-then-verify-then-commit in `deriveReceivedKeys`; surface decrypt failures (T-09, T-10).
- Body-size cap and per-field validation (T-16).
- Join approval or chat lock, unique names, fingerprint acknowledgement before first send (T-03).
- CSP with nonces and `Cache-Control: no-store` (T-14).
- Close sockets on leave/expiry (T-19).

**Structural (already decided or larger)**
- Fix T-05: one-time seed delivery, drop per-message self-wraps, ephemeral seed-transport keys. Relay-only mode (#90) reduces retention (T-05/T-07/T-11) once completed; note that only stage 1 (#92) has landed, so it is not yet in effect.
- Native/pinned client (#42), post-compromise security via MLS (#60), cover traffic (#63): all deferred as not worth it for the project's scale. Revisit only if it gains real users.
- An independent cryptographic review of the protocol before any serious use.
- A `SECURITY.md` with a vulnerability-reporting route (none exists today).

---

## 9. Reproducing the evidence

The probes live in `docs/threat-model-probes/`. They document behaviour *at the reviewed commit*; once a finding is fixed the output should change.

| File | Backs | How |
|---|---|---|
| `crypto_probe.js` | T-05, T-09 | `node docs/threat-model-probes/crypto_probe.js`. Extracts the real functions from `chatbox.html`; needs no dependencies. |
| `probe_server.py` | T-01, T-02, T-06, T-07, T-08, T-16, T-19, T-22 | Needs Postgres and Redis as for the normal suite; uses a throwaway test database. See the file's header. |

Others were checked directly:
- Headers: `curl -sI http://127.0.0.1:8000/chat/usermenu/` on a local dev server (T-14).
- Admin reachability: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/admin/login/` (T-18).
- Dependencies: `pip-audit -r requirements.txt --no-deps` (T-13).
- Request size: a 30 MB JSON POST to `/chat/create-chat/` on a running server (T-16).
- Log content: run the app, create/join a chat, inspect `chat_debug.log` (T-12).

Timings from the in-process probes are lower bounds on real-world cost.

## 10. Keeping this current

Re-run the probes and `pip-audit` after any change touching the join flow, chain-key issuance, the ratchet, logging, or deployment config, and update the finding table. If relay-only mode (#90) lands, re-assess T-05, T-07 and T-11 first: it changes what the server retains.

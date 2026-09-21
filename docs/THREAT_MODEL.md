# Threat Model & Security Assessment

**Read this before you decide to use Telepathy, and before you tell anyone else to.**

- **Code reviewed:** `main` at commit `123be67` (2026-09-21), including the per-chain message index from #92.
- **Reviewer:** an AI assistant (Claude), working in a single session at the maintainer's request. This is a careful review with running evidence, **not** an independent audit, and it is not a substitute for one.
- **Relationship to other docs:** `docs/SECURITY_AUDIT.md` (2026-09-18) hunted implementation bugs in the crypto/auth core, and those are fixed. This document asks a different question: *who could attack this system, what could each of them actually do, and is that acceptable for your use?* It also records findings that audit did not cover. `ARCHITECTURE.md` ("Accepted limitations") and the per-feature docs remain accurate; this pulls them together and adds what was missing.
- **Revision 2 (2026-09-21):** widened the adversary catalogue from 10 to 15 (added coercive/legal pressure, a compromised counterpart, the Tor network, repository/release compromise, and abusive users; browser extensions are folded into A8), added a capability profile per adversary, and added two structured passes: STRIDE by component and LINDDUN for the anonymity claims. That added findings T-25 to T-31, extended T-15, and produced a list of things that held up under testing. Existing IDs T-01 to T-24 are unchanged.

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
| Someone who seizes or infects your device, or a malicious browser extension | **Not protected** | Full history, keys' *use*, and the session token are recoverable (T-15). |
| A state-level / global passive adversary | **Not protected** | Timing correlation, no cover traffic (T-11, accepted #63). |
| Your chat partner, or your partner's device | **Not protected** | E2EE protects the endpoints from everyone *except each other*; a leak or a compromised partner device exposes everything (T-28). |
| A court order or coercion aimed at the operator | **Metadata and retained data can be handed over; a targeted backdoored client could be ordered** | (T-25, T-04). Not legal advice. |
| Someone who compromises the repo or a release | **Not protected** | Clients run whatever the server serves, so the repo is part of the trust base; its protections are thin (T-26). |
| Attackers inside the Tor network (relays, directories) | **Mostly out of the app's hands** | Relies on Tor's guarantees; the app-side risk is how the onion identity and client keys are handled (T-27). |
| Abusive users of a public instance | **Nothing built in** | No report, block or moderation, and deniability cuts both ways (T-29). |

---

## 2. Scope, method, and what was *not* assessed

**Reviewed:** every Python module in `chat/` and `pc/`; the full client (`chatbox.html`, `usermenu.html`, `index.html`); the container, compose, Tor and CI configuration; every existing security doc; the pinned dependency set.

**Method:** full read of server and client code; adversary analysis (§5); a STRIDE pass per component and a LINDDUN privacy pass (§5); then *running* the riskiest suspicions rather than only asserting them. Each finding below carries one evidence tag:

| Tag | Meaning |
|---|---|
| **Verified** | Reproduced by running code against this repository. The probe is in `docs/threat-model-probes/` (§9). |
| **Code-read** | Follows from reading the code; not run. Reasonably certain, but weaker evidence. |
| **Documented** | Already recorded by the project in an existing doc; included here for completeness. |

**Not assessed** (treat these as unknown, not as "fine"): behaviour in a real browser end-to-end (no click-through was done); the Tor network path, the `tor` container's runtime behaviour, or host/OS hardening; TLS termination for a clearnet deployment (nothing in the repo configures it); Postgres and Redis configuration; traffic captures; fuzzing; reachability of the dependency vulnerabilities in §T-13; any formal analysis of the hand-rolled protocol; social engineering, physical threats, and legal advice (T-25 and T-31 flag legal exposure but do not assess it); the maintainer's account-level security (2FA, key storage), which the GitHub API does not expose. Django, DRF, Channels and the browser's WebCrypto were assumed correct.

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

An adversary is defined here by **position** (where they stand relative to the system), **resources**, and **motivation**, because "botnet scanning for open servers" and "someone targeting one person" need different defences.

### 5.1 Catalogue

| ID | Adversary | Position and capabilities |
|---|---|---|
| **A1** | Passive network observer | Sees traffic to and from the server or the Tor entry. |
| **A2** | Global passive adversary | Correlates traffic timing across the network. |
| **A3** | Anonymous outsider | Can send HTTP(S)/Tor requests to the server; knows nothing else. |
| **A4** | Malicious chat participant | Holds a valid PIN and token; may be a group member or an ex-member. |
| **A5** | Curious operator | Runs the server honestly but reads the DB, logs, and network metadata. |
| **A6** | Malicious or compromised server | Can alter any response, drop messages, ship modified JS. |
| **A7** | Data thief | Gets a copy of the DB, backups, or logs, offline, once or over time. |
| **A8** | Device attacker | (a) runs code in the victim's browser: XSS, **a malicious browser extension**, malware; (b) seizes or images the device. |
| **A9** | Dependency / image supply chain | Compromises a package or base image. |
| **A10** | Future cryptanalyst | Stores today's ciphertext; breaks RSA-2048 later. |
| **A11** | Coercive or legal pressure | Compels the operator (or a participant) to hand over data, keys, or to change what is served. |
| **A12** | Compromised or careless counterpart | Is a legitimate member, but leaks, screenshots, or has a compromised device. |
| **A13** | Tor network adversary | Runs relays or directory nodes; attempts guard discovery, onion-service deanonymisation, traffic confirmation. |
| **A14** | Repository / release compromise | Controls a maintainer account, a merged PR, or a CI action. |
| **A15** | Abusive user | Uses an open instance for spam, harassment, or content the operator would refuse. |

### 5.2 Capability profiles

"Realistic for a small deployment" is my judgement, not a measurement. It says how much attention each adversary deserves at this project's scale.

| ID | Resources | Motivation | Realistic for a small deployment? |
|---|---|---|---|
| A1 | Low | Opportunistic | **High**: always present on any network. |
| A2 | Very high | Targeted | Low; a state-level concern. |
| A3 | Low to moderate | Opportunistic, griefing | **High**: internet-wide scanners find open servers. |
| A4 | Low | Targeted (an insider) | Medium |
| A5 | n/a | Curiosity or commercial | Medium; depends entirely on who hosts. |
| A6 | Moderate | Targeted or financial | Low to medium; a hobby server with known-vulnerable dependencies (T-13) is a plausible target. |
| A7 | Moderate | Financial | Medium; backups and breaches are routine. |
| A8 | Low to moderate | Opportunistic (malware, extensions) or targeted (seizure) | Medium |
| A9 | Moderate to high | Opportunistic or targeted | Low to medium |
| A10 | Very high | Long-term | Low |
| A11 | Authority | Targeted | Low to medium; rises with the deployment's profile. |
| A12 | Low | Varied, often carelessness | **High**: the most common real-world leak in any E2EE tool. |
| A13 | High | Targeted deanonymisation | Low |
| A14 | Moderate | Targeted or opportunistic | Low to medium; single maintainer, public repo. |
| A15 | Low | Opportunistic | Medium on a public instance; low on an invite-only one. |

### 5.3 Exposure matrix

`●` protected · `◐` partially / with caveats · `○` not protected · `—` not applicable

| Adversary | Content confidentiality | Transcript integrity | Anonymity / metadata | Availability |
|---|---|---|---|---|
| A1 Network observer | ● (TLS/Tor) | ● | ◐ IP visible on clearnet; sizes bucketed | — |
| A2 Global passive | ● | ● | ○ timing correlation (#63) | — |
| A3 Outsider | ◐ can join open chats (T-01–03) | ◐ | ◐ enumerates live chats + names | ○ T-06, T-08, T-16 |
| A4 Malicious member | ● past epochs / ◐ future | ◐ can send garbage, forge in collusion (T-24) | ◐ | ◐ T-30 |
| A5 Curious operator | ● | — | ○ full metadata (T-11, T-12) | — |
| A6 Malicious server | ○ MITM + code (T-04) | ○ silent censorship (T-09/10) | ○ | ○ |
| A7 Data thief | ● now / ◐ over time (T-05, T-23) | — | ○ | — |
| A8 Device attacker | ○ (T-15) | ○ | ○ | — |
| A9 Supply chain | ○ (T-13) | ○ | ○ | ○ |
| A10 Future cryptanalyst | ○ if ciphertext retained (T-23) | — | — | — |
| A11 Coercive / legal | ◐ safe unless a backdoored client is ordered (T-04, T-25) | ◐ | ○ retained data and logs can be produced (T-25) | ○ service can be ordered down |
| A12 Counterpart | ○ they hold the plaintext (T-28) | ◐ deniable, can lie | ◐ they know your name and timing | — |
| A13 Tor network | ● | ● | ◐ Tor's guarantees; timing (#63); onion key handling (T-27) | ◐ |
| A14 Repo / release | ○ (T-26) | ○ | ○ | ○ |
| A15 Abusive user | — | ◐ | ◐ | ○ T-06, T-16, T-29, T-30 |

### 5.4 STRIDE pass by component

Each component was checked for Spoofing, Tampering, Repudiation, Information disclosure, Denial of service and Elevation of privilege. Cells give the finding that covers the threat. **holds** means the check was run and the defence worked. `—` means no relevant threat found.

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| Browser client | T-03 names; T-27 lookalike server | T-09; T-15 (pins editable by any script) | deniable by design (T-29) | T-05, T-14, T-15 | — | T-14 no CSP |
| HTTP API | T-01 | T-16 no field validation | T-29 | T-02, T-11 | T-06, T-08, T-16, **T-30** | **holds**: cross-chat authorization (probe 10); T-18 admin |
| Bearer token / sessions | T-15 replay | — | — | T-15 | T-08 | **holds**: 256-bit, hashed at rest; T-07 idle path |
| WebSocket + Redis | T-21 unauthenticated Redis could forge signals | T-21 | — | T-19 | T-19 | **holds**: cross-chat socket refused |
| Postgres + logs | — | T-10 tail | no tamper-evident operator audit trail (minor) | T-05, T-07, T-11, T-12 | T-06, T-07 | — |
| Tor sidecar + keys | **T-27** | T-27 | — | T-11 | T-27 silent reopen | T-21 shared netns |
| Containers + deps | T-13 | T-13, T-20 | — | T-12 | — | T-13, T-21 |
| Repo + CI | **T-26** | T-26 | — | T-26 | — | T-26 |

What the pass turned up beyond the findings I already had: the fetch-cost amplification (**T-30**, from the DoS column), the lookalike-server problem and onion key handling (**T-27**, from Spoofing), repository trust (**T-26**, from the Repo + CI row), and one clean positive (Elevation of privilege on the API).

### 5.5 Privacy pass (LINDDUN)

Because Telepathy's pitch is anonymity, its privacy properties were checked against the LINDDUN categories.

| Category | Assessment | Where |
|---|---|---|
| **L**inkability | Within a chat, by design. Across chats the app does well: keys and ids are per chat. But on clearnet, IP and timing still link a person's chats; display names are free text and easily reused; participant ids are global and sequential. | T-11, T-22 |
| **I**dentifiability | Names are self-chosen; IPs appear in logs on clearnet; a partner learns your name and timing. | T-12, T-28 |
| **N**on-repudiation (a *good* property here) | Deniable MAC: no third-party proof of authorship. Caveats: the operator's own records attribute each send to a token, and in groups a member colluding with a server could forge (T-24). Deniability also means a harassment victim can't prove abuse. | T-24, T-29 |
| **D**etectability | Anyone can enumerate which chats exist and who is in them. On Tor, use of the network is visible but use of Telepathy is not. | T-02 |
| **D**isclosure of information | Retained wrapped seeds and ciphertext; rich server-side metadata; device contents. | T-05, T-11, T-15 |
| **U**nawareness | Users are never told what the server keeps, for how long, or that logs exist; the README says "guaranteed". | T-31 |
| **N**on-compliance | No retention policy or user-initiated deletion beyond Leave; personal data in logs on clearnet. Regulatory exposure was not assessed. | T-31, T-25 |

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
| T-25 | Med | A compelled operator can hand over a lot, or be ordered to backdoor the client | A11 | Code-read |
| T-26 | Med | Thin protection of the repository and release process | A14 | Verified |
| T-27 | Med | Onion identity and client-auth key handling; lookalike servers | A13, A6 | Code-read + Documented |
| T-28 | Med | A compromised or careless counterpart defeats everything | A12 | Code-read |
| T-29 | Low | No abuse controls; deniability cuts both ways | A15 | Code-read |
| T-30 | Med | One fetch costs O(transcript), and a member controls the transcript | A4 | Verified |
| T-31 | Low | Users aren't told what is kept; no retention or deletion policy | A11, LINDDUN | Code-read |

T-25 to T-31 were added in revision 2. IDs are stable identifiers, not a severity ranking; sort by the **Sev** column.

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

**Adversary:** A8, including malicious browser extensions. **Evidence:** Code-read.

- **Non-extractable is not encrypted at rest.** It stops JavaScript from *reading* the key; it does not stop code in the page from *using* it, and (untested here) the browser must persist it in the profile to survive restarts, so disk access should be treated as key access unless the OS encrypts the profile.
- IndexedDB holds the RSA key, the bearer token (a plain string), chain keys, **and a cached key for every message ever received** (`msgkey_*`). With the server's ciphertext (or an A7 copy) those decrypt the whole history of that chat on that device.
- `localStorage` holds the chat PIN, participant id, pinned keys and chain epoch in the clear.
- **TOFU pins are ordinary `localStorage` entries.** Any script or extension running on the origin can overwrite them, after which a key swap passes the check silently. Extensions can also read the rendered chat directly. Tor Browser's defaults blunt this; a general-purpose browser with extensions installed does not.
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

### T-25 · Medium · A compelled operator can hand over a lot, or be ordered to backdoor the client

**Adversary:** A11. **Evidence:** Code-read, built on the data inventory verified in T-11 and T-12. This is a technical description of exposure, not legal advice.

- **What can be produced without any user's cooperation:** everything in the T-11 table, the logs (T-12), and retained ciphertext and wrapped seeds (T-07). Not plaintext.
- **What a targeted order could add:** the operator controls the JavaScript (T-04), so an operator compelled or coerced to do so could serve a modified client to one specific chat (the PIN is in every request) or one client-authorization holder. Users cannot detect this.
- **The onion identity** (`tor_data`, see T-27) can be compelled too, which lets a third party *be* the server.
- **Participants** can be compelled to unlock a device (T-15). Deniability helps against third-party proof of authorship; it does nothing about what the device already holds.
- Because the design retains more than it needs to (T-07, T-11), there is little the operator could truthfully say "we don't have". There is no retention policy or transparency statement.

**Fix direction:** keep less. Fix T-07 and T-12, then relay-only mode (#90); write down a retention policy; choose hosting jurisdiction deliberately.

### T-26 · Medium · The repository and release process are thinly protected

**Adversary:** A14. **Evidence:** Verified (GitHub API for branch protection, Actions and security settings; the workflow file).

Because browsers run whatever the server serves, the source repository is effectively part of every deployment's trusted base: a malicious commit becomes client code for every operator who deploys it.

| Observed on `main` | |
|---|---|
| Pull request required | yes, but **0 approving reviews required** |
| Admin bypass | `enforce_admins` is **off** (admins can bypass; the early license commits went straight to `main` this way) |
| Required status checks | **none**, so the secret scan is advisory |
| Signed commits, CODEOWNERS | **none** |
| Force-push and branch deletion | blocked |
| Actions | `actions/checkout@v4` and `gitleaks/gitleaks-action@v2` use **floating tags**; default token is read-only |
| Dependabot security updates | **disabled** |
| Secret scanning + push protection | **enabled** |
| `SECURITY.md` / vulnerability reporting route | **none** |

There is a single maintainer, and the repository is public. Account-level security (2FA, hardware keys) cannot be seen through the API and was not assessed.

**Fix direction:** require status checks; pin Actions by commit SHA; enable Dependabot; add `SECURITY.md`; enforce rules for admins; require a review as soon as there is a second maintainer (a solo maintainer cannot self-approve, which is why 0 may be a deliberate trade-off); tag releases and advise operators to deploy a reviewed tag, not whatever is on `main`.

### T-27 · Medium · Onion identity and client-auth key handling

**Adversary:** A13, A6, A3. **Evidence:** Code-read + Documented (`docs/INVITE_ONLY_ONION.md`).

- **The `tor_data` volume is the server's identity.** It holds the hidden-service private key and the `authorized_clients/` directory. README calls it "the one piece of state that must persist", which means it gets backed up, and backups are targets. Whoever holds a copy *is* the server: they can run a byte-identical lookalike at the same address serving modified JavaScript (T-04). The key cannot be rotated without changing the address.
- **Users can't check they're at the right server.** The only identity signal is the 56-character address. Lookalike ("vanity prefix") onion addresses are a known phishing technique, and the app shows no server identity.
- **Client-authorization keys** are printed once to the operator's terminal (scrollback, shell logging) and delivered by hand; they never expire; a leaked key is a leaked invitation until revoked.
- **Revoking the last authorized client silently reopens the service to everyone.** The script prints a warning, but nothing prevents it.
- The interaction of client auth with the PoW defence is untested (the project's own doc says so).

Tor-network attacks proper (A13: guard discovery, directory nodes, traffic confirmation) are outside the app's control. Beyond the `Server: daphne` banner (T-14) and timing patterns (T-11) I found no app-specific leak that helps them.

**Fix direction:** treat the hidden-service key like a signing key (encrypted, minimal-copy backups); tell users to verify the full address; make removing the last client require an explicit flag.

### T-28 · Medium · A compromised or careless counterpart defeats everything

**Adversary:** A12. **Evidence:** Code-read.

End-to-end encryption protects the conversation from everyone except its endpoints. Nothing stops a partner from screenshotting, copying, forwarding, sharing the PIN, or having a compromised device, and their device holds every key for the chats they're in plus all future messages (T-15). "✓ Verified" means "sent by whoever holds this chat's key", not "trustworthy". In groups the weakest member sets the security level, and members can't see or limit who was added (T-03) or evict anyone (T-24). Disappearing messages are unenforceable against them (T-17). Deniability protects against third-party *proof*, not against a partner leaking content.

**Fix direction:** none that is purely technical. Be honest about it in user-facing docs; keep groups small; verify identities out-of-band.

### T-29 · Low · No abuse controls, and deniability cuts both ways

**Adversary:** A15. **Evidence:** Code-read.

There is no report, block, mute, kick or moderation. Anyone with a PIN can post. An operator can delete a chat in the admin but cannot see what it contained. Because messages are deniable (#61), a harassed user cannot prove to a third party who sent what, and the operator cannot verify a claim. Flooding is possible via T-06, T-16 and T-30. As with any E2EE tool, a public instance can be used for things its operator would never permit and cannot see; anyone hosting for strangers should decide their position on that before they host.

**Fix direction:** client-side block/mute; rate limits; an operator policy. Invite-only Tor (T-27's caveats aside) removes most of this by not being open.

### T-30 · Medium · One fetch costs O(transcript), and a member controls the transcript

**Adversary:** A4. **Evidence:** Verified (probe 11).

`GET /chat/get-messages/` returns the whole transcript with no pagination, and it runs the expiry sweep on every call (about three SQL queries per expiring message). Measured in-process against a local database:

| Transcript | SQL queries | Response | Time |
|---|---|---|---|
| 10 messages | 38 | 12 KiB | 0.16 s |
| 500 messages | 1,508 | 570 KiB | 6.0 s |
| 2,000 messages | 6,008 | 2.3 MiB | 21.6 s |

Every member's client refetches on each websocket push and every 15 s, so one member posting a few thousand messages (cheap: no size or rate limit, T-16) makes every fetch by every member expensive, and can saturate a worker. The figures are an order-of-magnitude guide, not a benchmark of a real deployment. Also, this GET **has side effects** (it writes read receipts and tombstones messages), so any retried or prefetched GET changes state; that interacts with T-17.

**Fix direction:** delta fetches (`since` a sequence number, as relay-only mode would need anyway); batch or background the sweep (the T-07 reaper is the natural home); per-chat message rate and quota.

### T-31 · Low · Users aren't told what is kept, and there's no retention or deletion policy

**Adversary:** A11 / LINDDUN (Unawareness, Non-compliance). **Evidence:** Code-read.

Nothing in the UI or docs tells a user what the server retains (T-11), for how long (T-07), or that logs exist (T-12); the README says "guaranteed by design". Users can't request deletion except by leaving. There is no operator-facing retention policy. Where a deployment stores personal data (IP addresses on clearnet, display names), regulatory duties such as GDPR may apply to the operator. This was not assessed.

**Fix direction:** a short user-facing "what the server keeps" statement derived from the T-11 table; an operator retention policy; soften "guaranteed".

### What held up under testing

A threat model that only lists failures misleads in the other direction. These were checked and worked:

| Area | Result | Evidence |
|---|---|---|
| Cross-chat authorization | A token for chat A was refused on every chat B endpoint (403, or 400 for leave); unauthenticated calls got 401; a left participant's token got 401 | Verified (probe 10) |
| WebSocket isolation | A token for one chat cannot open a socket on another (close code 4001) | Verified (probe 8) |
| Bearer tokens | 256-bit random; only the SHA-256 hash is stored | Code-read |
| Public-key intake | Validated as a 2048-bit RSA SPKI PEM with a length cap | Code-read |
| DOM rendering | All untrusted strings go through `textContent`; no third-party requests | Code-read |
| Transcript ordering | `seq` assigned under a row lock; stale `prev_hash` rejected with 409 | Code-read |
| Identity | Keys and ids are per chat; the private key is generated non-extractable | Code-read |
| Deployment defaults | `DEBUG` off, HTTPS on by default, no published ports, non-root app, secret scanning with push protection | Code-read + Verified (T-26) |

---

## 7. Is Telepathy right for you?

| Situation | Verdict |
|---|---|
| Learning how E2EE chat, ratchets, TOFU and Tor services fit together | ✅ Good fit; the docs are a real asset. |
| Casual private chat with friends on a server **you** run, over Tor with client authorization, fingerprints compared out-of-band | 🟡 Reasonable, with the checklist below. |
| Chat on someone else's server, or a public instance | 🟡 Content is protected from casual snooping; the operator can see metadata and could, if malicious, defeat the crypto (T-04). |
| Operating a public instance for strangers | 🔴 Not advisable: open to abuse and floods (T-06, T-29, T-30), and you may hold data you cannot inspect or easily delete (T-25, T-31). |
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
8. Remember the weakest link is often the other person: choose who you chat with, and expect anything they can read to be copyable (T-28).
9. If you deploy on Tor: protect the `tor_data` volume like a signing key, tell users to check the **entire** `.onion` address, and don't revoke your last client authorization unless you mean to reopen the service (T-27).
10. Deploy from a reviewed release tag, not whatever is on `main` (T-26).
11. Operators: set `DJANGO_SECRET_KEY`; disable the admin (T-18); stop logging PINs/names and rotate logs (T-12); update dependencies (T-13); cap request sizes (T-16); reap idle chats (T-07); don't publish extra ports.

---

## 8. Remediation roadmap

Suggested order by value per effort. Nothing here has been filed or implemented.

**Quick wins (hours to a day)**
- Stop trusting `X-Forwarded-For`; per-PIN failure accounting; throttle and slim down `check-chat` (T-01, T-02, T-08).
- Bounded `create_chat` retries plus a create throttle (T-06).
- Stop logging PINs and names; stdout only; rotate (T-12).
- Bump dependencies; add `pip-audit`/Dependabot; hash-pin (T-13).
- Require the secret-scan check on `main`, pin Actions by SHA, enable Dependabot, add `SECURITY.md` (T-26).
- Fail closed on the default secret key; drop the inherited host (T-20).
- Remove or isolate the admin (T-18).

**Medium (days)**
- Reaper for idle participants and empty/idle chats; make idle expiry delete an emptied chat (T-07).
- Derive-then-verify-then-commit in `deriveReceivedKeys`; surface decrypt failures (T-09, T-10).
- Body-size cap and per-field validation (T-16).
- Join approval or chat lock, unique names, fingerprint acknowledgement before first send (T-03).
- CSP with nonces and `Cache-Control: no-store` (T-14).
- Close sockets on leave/expiry (T-19).
- Delta fetches and a batched or background expiry sweep; per-chat message quota (T-30).
- Guard against revoking the last Tor client by accident; document onion-key handling (T-27).
- A short "what the server keeps" statement and a retention policy (T-25, T-31).

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
| `probe_server.py` | T-01, T-02, T-06, T-07, T-08, T-16, T-19, T-22, T-30, and the authorization results under "What held up" | Needs Postgres and Redis as for the normal suite; uses a throwaway test database. See the file's header. |

Others were checked directly:
- Headers: `curl -sI http://127.0.0.1:8000/chat/usermenu/` on a local dev server (T-14).
- Admin reachability: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/admin/login/` (T-18).
- Dependencies: `pip-audit -r requirements.txt --no-deps` (T-13).
- Request size: a 30 MB JSON POST to `/chat/create-chat/` on a running server (T-16).
- Repository settings (T-26): `gh api repos/<owner>/<repo>/branches/main/protection`, `.../actions/permissions/workflow`, and the repository's `security_and_analysis` field; plus `.github/workflows/`.
- Log content: run the app, create/join a chat, inspect `chat_debug.log` (T-12).

Timings from the in-process probes are lower bounds on real-world cost.

## 10. Keeping this current

Re-run the probes and `pip-audit` after any change touching the join flow, chain-key issuance, the ratchet, logging, or deployment config, and update the finding table. If relay-only mode (#90) lands, re-assess T-05, T-07 and T-11 first: it changes what the server retains.

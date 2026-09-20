# Design: Post-Compromise Security (issue #60)

**Status: decided not to build (2026-09-19).** This records the analysis, so the decision can be revisited on real criteria rather than re-derived. Nothing here is implemented.

## The gap

`docs/FORWARD_SECRECY.md` already states it: the per-sender HMAC ratchet only runs forward. Steal a participant's *current* chain key and every future message key from that sender is derivable until the next membership-change re-key. There is no way to "self-heal" after a compromise ends. Forward secrecy protects the past; post-compromise security (PCS) is about recovering the future.

## What PCS actually requires

Healing needs *fresh secret entropy the attacker never saw*, mixed into the key schedule after the compromise. A hash chain can't provide that, since everything it derives is a function of state the attacker already holds. In Signal's Double Ratchet the ephemeral Diffie-Hellman exchange on each round trip is that fresh entropy. Any real solution has to be a DH-style (or KEM-style) ratchet.

## Why a periodic re-key wrapped to the existing keys is not the answer

The cheap idea is to rotate the chain seed on a timer, wrapped to each recipient's RSA key as today. It doesn't heal what matters. The RSA burner keys are static for the chat's lifetime, and an attacker who compromised the device (the case PCS is for) has, or can keep using, that key, so they can unwrap the new seed too. Rotating the RSA keys themselves means inventing an authenticated key-update protocol through an untrusted server, which collides with TOFU pinning (`docs/KEY_VERIFICATION.md`). That is exactly the hand-rolled protocol `FORWARD_SECRECY.md` warns against. Rejected.

## Options

| Option | PCS | Fit for 3-8 person groups | Assessment |
|---|---|---|---|
| Hand-rolled multi-party DH ratchet | yes, if correct | n/a | Rejected: research-grade risk for a solo project. |
| Signal Double Ratchet (pairwise) | yes | poor: N-1 sessions, N-1 encryptions per message, no single-ciphertext fan-out | Not evaluated further. Not verified whether a maintained browser build exists. |
| Sender Keys (what we have) | no | good | The status quo. |
| **MLS (RFC 9420)** via `ts-mls` | yes (TreeKEM) | designed for groups | The only vetted route. See caveats. |
| **MLS (RFC 9420)** via `openmls` (WASM) | yes | designed for groups | Same, Rust. A `wasm` target exists in the repo. |

**The issue's premise ("adopt a vetted library") is weaker than it sounded.** From the projects' own READMEs, read 2026-09-19 (not code-reviewed, and I did not test either):

- `ts-mls`: full RFC 9420 implementation in TypeScript, MIT, runs in browsers on WebCrypto, single core dependency. Its README says it "has not undergone a formal security audit."
- `openmls`: Rust, MIT, maintained by Phoenix R&D and CE Labs, with a WASM build path. The page I read stated no audit status either way.

MLS the *protocol* is standardized and has had serious analysis. Neither *implementation* I looked at is one I can call audited. Trading a small hand-rolled ratchet for a large young library is not automatically a security win.

## The decision inside the decision: MLS vs. deniability (#61)

MLS application messages carry a sender signature (inside the encrypted content) that the RFC describes as providing non-repudiation, and MLS itself makes no deniability claim. Telepathy deliberately moved *from* signatures *to* a ratchet-derived MAC in #61 (`docs/DENIABLE_AUTH.md`) because deniability matches its "Anonymous, Ephemeral" positioning. Adopting MLS as specified would likely undo that. If this is ever pursued, choose explicitly:

1. Accept MLS's signatures and drop deniability. Simplest; contradicts a deliberate decision.
2. Keep an inner deniable MAC as the user-facing authentication and treat MLS signatures as transport-level. Doesn't remove the signature's existence, so it doesn't restore real deniability.
3. Find or build an MLS variant without transferable signatures. That is a hand-rolled protocol change, back where we started.

I have no recommendation between these that I'd defend as sound; it needs a cryptographer, not this document.

## Integration surface (why it isn't a drop-in)

MLS would replace, not extend, most of the client crypto layer:

- **Removed or replaced:** `ChainKey`/`ChainKeyWrap`/`MessageKey` models, `IssueChainKeyView`, the RSA-OAEP seed wrapping, the `ratchetStep` HMAC ratchet, and the `0x03` MAC label in `chatbox.html`.
- **Server becomes an MLS Delivery Service:** stores single-use KeyPackages (uploaded at join, which fits accountless identity), relays Welcome and Commit messages, and must order Commits. The existing 409 stale-transcript model is a plausible fit, unverified.
- **Interactions to re-verify:** transcript hash chain (#49, hashes ciphertext bytes, likely unaffected), 256-byte padding (#58, MLS has its own padding mechanism), TOFU pinning (#19, would pin MLS credentials/keys instead of the RSA key), disappearing-message tombstones (#64), out-of-order and concurrent delivery under the WS+poll race (#68).
- **Build/supply chain:** the client is vanilla inline JS with no build step. A TS/WASM dependency means a bundling step and a vendored, hash-pinned artifact self-hosted like the fonts (#65), so nothing is fetched from a third party from an onion page.

## Decision

Not building. For a solo learning project with no deployed users, the cost (a rewrite of the crypto layer, a new build step, a deniability decision) outweighs a gain that only matters against an attacker who compromises a device and then loses access, and that is a narrow window on top of already-non-extractable keys (#55/#56).

**What "taking it seriously" would change:** the calculus flips. Then the path is MLS plus an independent security audit of whichever implementation is chosen, with the deniability question settled first by someone qualified.

**Revisit if:** the project gets real users; an audited, maintained browser-capable MLS implementation exists; or the deniability requirement is dropped.

## Caveats on this analysis

Library facts are from README-level reads on 2026-09-19, not code review or testing. Feature support (group size limits, out-of-order handling, credential types) was not verified for either library.

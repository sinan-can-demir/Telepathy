# Deniable Authentication: MAC Instead of Signatures

## The gap this closes

Every message used to be signed with RSA-PSS, and the "✓ Verified" badge was built on that signature. RSA-PSS signatures are *publicly verifiable*: anyone who has a message's ciphertext, its signature, and the signer's public key can verify it, not just the intended recipient. That gives **non-repudiation** — a participant can't later credibly deny having sent a specific message, because the signature is provable to anyone, including a court, a platform, or an abusive ex-partner who got hold of a device.

Signal deliberately avoids this. It authenticates messages with MACs, not signatures — verifiable only by someone who already holds the shared key, which is exactly the property that makes them **deniable**: no one who receives a MAC'd message can *prove* to a third party who sent it, because they could in principle have computed a matching MAC themselves. Telepathy's own positioning — "Anonymous. Encrypted. Ephemeral." — leans the same direction. Shipping non-repudiable signatures was the opposite of what that positioning implies. That tension is issue #61.

## The design: a MAC from the same ratchet, not a persistent signing key

Rather than adding a second key-agreement mechanism, this reuses the forward-secrecy sender-chain ratchet (see `docs/FORWARD_SECRECY.md`) that already existed for the AES message key. Each ratchet step now derives three values from the current chain key, each its own HMAC-SHA256 label so none can be computed from another:

- `0x01` → the AES-GCM message key (unchanged)
- `0x02` → the next chain key (unchanged)
- `0x03` → a per-message MAC auth key (new)

The sender computes `mac = HMAC-SHA256(auth_key, seq|prev_hash|chat_id|plaintext)` — the exact payload the old RSA-PSS signature covered, unchanged, so replay-across-chain-position protection is identical. Recipients derive the same `auth_key` the same way they already derived the message key (advancing their cached copy of the sender's chain), so verification needs no extra round trip and no new server endpoint.

`ChatParticipant.signing_public_key` and the RSA-PSS keypair are gone entirely, not kept unused alongside the MAC — once messages aren't signed, a signing identity has no remaining purpose, and keeping one around would just be dead surface area. TOFU pinning and the safety-number fingerprint (`docs/KEY_VERIFICATION.md`) now cover only the encryption key.

## What this catches (and what stayed exactly as strong as before)

The property this was actually protecting against day to day — a malicious or compromised **server** swapping a message's ciphertext before anything has chained past it (the hash-chain alone can't catch tampering with a tip nothing yet references) — is preserved exactly as strongly as RSA-PSS gave it. The server never holds the ratchet's auth key any more than it held the old signing private key, so it can't forge a MAC over substituted content either.

## What this explicitly does not give

- **No non-repudiation.** That's the point being given up, deliberately: no participant can prove to someone outside the conversation, after the fact, that another participant sent a specific message.
- **No intra-group message-forgery protection was actually lost, despite first appearances.** It's tempting to assume a MAC shared across a group's chain key means any group member could forge a message that looks like it came from another member. That's not reachable in this app's actual design: `sender_id` on a stored `Message` is set server-side from whoever's authenticated bearer token made the `POST /chat/send-message/` request — never from anything inside the payload — and there is no edit endpoint. A participant holding another sender's chain key can compute a *valid* MAC over fabricated content, but submitting it still attributes it to themselves, not the victim. The MAC's only job is catching server-side tampering with already-attributed content, and it does that regardless of how many participants share the chain key.
- **No protection against a live, currently-executing compromise reading key material and using it.** Same caveat as `docs/CLIENT_KEY_STORAGE.md`'s non-extractable keys: this stops a MAC from being forged *for later reuse* by someone who never had the key, not real-time abuse by code already running on a device that legitimately holds it.

## What this is not

Same caveat as the project's other security docs: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. See `ARCHITECTURE.md` for the full limitations list.

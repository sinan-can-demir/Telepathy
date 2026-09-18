# Client Key Storage: Non-Extractable Keys in IndexedDB

## The gap this closes

`chatbox.html` used to generate RSA-OAEP/RSA-PSS keypairs as *extractable* `CryptoKey` objects, immediately export the private halves to PEM, and store those PEM strings — plus the bearer auth token — as plain strings in `localStorage`. Any XSS on the origin, current or future, first-party or from a compromised third-party script, could read `priv_<chat_id>` / `sign_priv_<chat_id>` / `participant_token_<chat_id>` directly and walk off with fully usable decryption/signing keys and the session token. That's issue #21, still valid under the current accountless architecture (the original finding was against a now-removed `auth.html`; the same gap moved to `chatbox.html`'s per-chat key storage) — see also #42, which scoped two candidate fixes.

## The design: non-extractable keys, stored in IndexedDB

Both keypairs are now generated with `extractable: false`. Per the WebCrypto spec, that flag only governs the *private* half of a generated pair — the public half is always extractable regardless, since it isn't secret. That one spec detail is what makes this a clean, behavior-preserving swap rather than a redesign:

- `exportKey('spki', publicKey)` keeps working exactly as before, so the public key PEM sent to the server at join/create time is unaffected.
- `exportKey('pkcs8', privateKey)` now throws `InvalidAccessError` ("key is not extractable") for *anyone* who tries it — including an XSS payload with full JS execution in the page.
- `decrypt`/`sign` with the non-extractable private key work identically to before — verified directly against Node's WebCrypto implementation (same W3C spec) before writing this: a non-extractable RSA-OAEP private key still decrypts correctly, it just can never be exported.

The private `CryptoKey` objects (not PEM strings) are stored directly in IndexedDB, which natively supports structured-clone storage of `CryptoKey` — this is a standard, well-supported browser capability, not a workaround. The bearer token moved to IndexedDB alongside them, for a smaller reason: it can't be made non-extractable (it's just a string used in the `Authorization` header), but keeping it off `localStorage` reduces exposure to generic, opportunistic "dump `localStorage`" exfiltration payloads.

Public keys and the numeric participant id stay in `localStorage` unchanged — they aren't secret, and moving them would add complexity for no security benefit.

## What this catches

An XSS payload (or any other JS running on the page, current or injected) that tries to read out and exfiltrate the private keys for later, offline reuse — the exact scenario #21 describes — now simply cannot. The raw key bytes never exist as a JS-readable string at any point after generation.

## What this explicitly does not give

- **No protection against an *active* XSS using the keys while it's running.** A non-extractable key can still be *used* — `sign`/`decrypt` calls succeed for any JS with a reference to it or that can look it up in IndexedDB. This stops key *theft for later/offline reuse*, not real-time abuse by malicious code currently executing on the page. Those are different threat models; this only closes the first one.
- **No equivalent guarantee for the bearer token.** A string can't be made non-extractable. Moving it to IndexedDB is defense-in-depth against low-effort/generic scraping, not a hard security boundary — a targeted, live XSS can query IndexedDB just as easily as it could `localStorage`.
- **The forward-secrecy ratchet seeds and per-message derived keys were unaffected by this change**, and moved to the same non-extractable-CryptoKey-in-IndexedDB pattern separately (issue #55, see `docs/FORWARD_SECRECY.md`).

**Update (issue #61):** the RSA-PSS signing keypair described above no longer exists at all -- per-message authentication moved to a ratchet-derived MAC instead of a persistent signing identity, so `sign_priv_<chat_id>`/`sign_pub_<chat_id>` were removed rather than migrated. See `docs/DENIABLE_AUTH.md`. Everything above about the RSA-OAEP encryption keypair and the bearer token is still accurate.

## What this is not

Same caveat as the project's other security docs: this narrows a real gap, it doesn't make Telepathy ready for a high-stakes use case like source protection on its own. See `ARCHITECTURE.md` for the full limitations list.

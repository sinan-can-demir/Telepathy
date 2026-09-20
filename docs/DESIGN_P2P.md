# Design: P2P / WebRTC (issue #14)

**Status: proposal, not built, issue still open.** The analysis concludes WebRTC is the wrong way to reach #14's goal for this app, and proposes an alternative for discussion.

## What #14 was after

Remove the central server from the trust path: crypto client-side (done), keys ephemeral per chat (done via #45), and messages moving peer-to-peer over a WebRTC data channel with only a thin signaling server. The remaining piece is the transport.

## What the server holds today

Ciphertext, sender ID, sequence/`prev_hash`, MAC, bucketed timestamps (#59), the roster, and the PIN. Never plaintext or private keys. The residual exposure is *stored metadata that persists* in Postgres and what a live-observing server sees.

## Why WebRTC conflicts with this app

- **It doesn't work in the Tor deployment.** Tor Browser disables WebRTC (`media.peerconnection.enabled` is false) to prevent IP leaks. The `.onion` deployment (#44, #62) is the app's strongest anonymity story and would have no P2P transport at all.
- **It exposes IPs, the opposite of the goal.** ICE candidate exchange reveals each peer's network addresses to the other. Hiding them requires a TURN relay, which then sees IPs and traffic timing and is a central server again.
- **The signaling server still learns who connects to whom and when.**
- **It needs STUN/TURN infrastructure**, third-party (a clearnet request, an anonymity smell) or self-hosted.
- **It loses properties the app relies on:** store-and-forward (both peers must be online at once), server-ordered concurrency (the 409 stale-transcript check that keeps the hash chain and ratchet consistent), roster authority, and server-driven expiry and read receipts (#64). Groups (3-8) become an N-1 mesh with no natural ordering authority.

One old Tor ticket explored WebRTC with hidden services (title seen only; nothing I found says it shipped).

## Options

| Option | Verdict |
|---|---|
| WebRTC everywhere | Rejected: breaks the Tor deployment and leaks IPs. |
| WebRTC as a clearnet-only optional mode | Not recommended: two very different trust models in one app, doubling what must be reasoned about, for the deployment that matters least. |
| **Ephemeral relay-only server** | Recommended if this goal is pursued. |

## Proposal: ephemeral relay-only mode

Keep the server as a relay (so Tor, ordering, and store-and-forward all keep working) but stop it from *keeping* anything:

- Ciphertext lives only in Redis with a TTL, until every current participant has fetched it (or the TTL lapses), and is never written to Postgres. Redis persistence stays off (already true in `compose.yaml`: no volume).
- Postgres keeps only what's needed to route: chat, roster, PIN.
- Clients keep their own transcript locally (IndexedDB) since the server no longer can. Hash-chain verification then runs against local state; reload restores from local storage.
- Fits the app's "Ephemeral" positioning and complements disappearing messages (#64).

**Costs and open questions**

- A participant offline past the TTL misses messages (and can't recover them). Needs a chosen TTL and clear UX.
- A Redis restart loses undelivered messages. Acceptable for ephemeral chat, but visible as dropped messages.
- A new device or cleared browser storage loses history. Consistent with the model, but a behavior change.
- `GetMessagesView` currently returns the whole transcript each time; this would move it to delivery-oriented fetches, and the chain/ratchet processing queue (`processMessages`) must be re-checked against that.
- Late joiners, `MessageReadReceipt`, and expiry sweeps (`services.sweep_expired_messages`) all assume persisted messages and would need rework.

**What it does not fix:** while a chat is live, the server still sees who talks, when, and how much, and a malicious server can still drop or delay messages. It shrinks what a server *compromise after the fact* yields; it doesn't blind a live server. Any timing-correlation defense is a separate, larger problem (see `ARCHITECTURE.md`, Accepted limitations, #63).

## Recommendation

Close #14 as superseded, and if the goal is worth pursuing, scope it as the relay-only mode above in a new issue with this doc as its starting point. Not started; awaiting a decision.

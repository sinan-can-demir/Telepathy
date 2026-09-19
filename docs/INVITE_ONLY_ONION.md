# Invite-Only `.onion`: Tor Client Authorization

## The gap this closes

The default Tor deployment (`compose.yaml` + `deploy/torrc`) is *open*: anyone who learns the `.onion` address can reach `CreateChatView`/`JoinChatView` and use the app. The address is the only barrier, and `.onion` addresses leak — pasted into an insecure channel, scraped, or guessed if ever indexed. That's the right default for the "share a PIN with anyone" use case, but not for a higher-stakes deployment. That's issue #62.

## The mechanism

Tor v3 **Client Authorization** makes the hidden service's descriptor unreadable to anyone without an authorized x25519 key. An unauthorized client can't even learn where to open a connection: it fails inside Tor's own protocol, before any byte reaches the app container, let alone Django. This is a much stronger gate than anything the app could enforce itself, and it composes with `HiddenServicePoWDefensesEnabled` (which still applies to *authorized* clients).

It is **opt-in**. Nothing in `deploy/torrc` changes: Tor enforces client auth whenever `<HiddenServiceDir>/authorized_clients/` contains at least one `<name>.auth` file, and stays open when it's empty. So the default deployment is untouched, and going back to open is just revoking the last client.

## Usage

`deploy/tor-client-auth.sh` (works with `podman`, or `CONTAINER_ENGINE=docker`; finds the compose `tor` service, or set `TOR_CONTAINER`):

```
deploy/tor-client-auth.sh add alice      # generate a keypair, authorize it, print alice's key
deploy/tor-client-auth.sh remove alice   # revoke
deploy/tor-client-auth.sh list
```

- The keypair is generated **on your host**. Only the public half is written into the tor container; the private key is printed once and never stored server-side. Treat that output like a password: send it over a channel you already trust.
- **add** signals Tor to reload (`SIGHUP`), so connected users aren't disturbed. Allow a minute or two for the service descriptor to republish before that user can connect.
- **remove** restarts the tor container, so a revoked client's already-established circuits are dropped. Everyone connected reconnects; the app container and its state are untouched.
- The client adds the key in Tor Browser (Settings → Privacy & Security → Onion Services Authentication), or as `<ClientOnionAuthDir>/<name>.auth_private` for a tor daemon.

Client auth files live in the `tor_data` volume alongside the hidden-service key, so they persist across restarts and rebuilds.

## How this was verified

Against the real `deploy/Containerfile.tor` image on the live Tor network, with a stub HTTP server on port 8000 and a separate client Tor container doing SOCKS requests:

- No clients authorized: an unauthenticated client gets HTTP 200 (still open by default).
- After `add`: the authorized client gets 200; an unauthenticated client is rejected.
- After `remove` (last client): an unauthenticated client gets 200 again.
- Separately confirmed that a bare `SIGHUP` makes Tor pick up both an added and a removed `.auth` file. (Tor's own docs imply a restart is required; observed behavior differs, so `add` uses the lighter reload. `remove` restarts anyway, for the circuit-drop reason above, which was **not** independently tested.)

Descriptor propagation on the live network was slow and occasionally timed out for a few minutes after a restart; those were retried, not a script fault.

## What this is not

- **Not a substitute for E2E encryption or the rest of the model.** It gates *who can reach the server*. The server is still untrusted for message content, exactly as before.
- **Not per-chat access control.** An authorized client can create or join any chat on the deployment. It answers "who may use this instance", not "who may join this chat".
- **Not deniability-preserving key distribution.** You now have a list of client names, and the private keys pass through whatever channel you use to hand them out. A leaked client key is a leaked invitation until you revoke it. Revoke by name; there's no expiry.
- **Not a defense against a malicious authorized client** (they can still enumerate/brute-force PINs like any user; see `ARCHITECTURE.md` on the IP-keyed throttle collapsing under Tor).
- **The client name is operator-side bookkeeping only.** It's stored as the `.auth` filename on the server and is never exposed to the app or to other users.
- **Adds real key-distribution overhead**, which is why it's not the default.

#!/usr/bin/env bash
# Manage Tor v3 Client Authorization for the Telepathy hidden service.
# Opt-in: with zero authorized clients the .onion stays open to anyone who
# has the address (the default); with one or more, Tor rejects everyone else
# at the protocol level, before a connection ever reaches Django. See
# README.md's "Invite-only .onion" section and issue #62.
#
#   deploy/tor-client-auth.sh add <name>      generate a keypair, authorize it
#   deploy/tor-client-auth.sh remove <name>   revoke a client
#   deploy/tor-client-auth.sh list            show authorized client names
#
# The private key is generated here on the host, printed once for you to hand
# to that user, and never written to the server. Only the public half goes
# into the tor container's HiddenServiceDir.
#
# Container lookup: set TOR_CONTAINER, or this finds the `tor` service of the
# running compose project by its compose label.
set -euo pipefail

ENGINE="${CONTAINER_ENGINE:-podman}"
HS_DIR=/var/lib/tor/telepathy_hidden_service
AUTH_DIR="$HS_DIR/authorized_clients"

die() { echo "error: $*" >&2; exit 1; }

find_container() {
    if [[ -n "${TOR_CONTAINER:-}" ]]; then
        echo "$TOR_CONTAINER"
        return
    fi
    # podman-compose and docker compose label services differently.
    local found label
    for label in io.podman.compose.service com.docker.compose.service; do
        found=$("$ENGINE" ps --filter "label=$label=tor" --format '{{.Names}}' 2>/dev/null || true)
        [[ -n "$found" ]] && break
    done
    [[ $(wc -l <<<"$found") -le 1 && -n "$found" ]] \
        || die "couldn't find exactly one running tor container; set TOR_CONTAINER=<name>"
    echo "$found"
}

valid_name() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]] || die "client name must match [A-Za-z0-9_-]+"; }

# Tor re-reads authorized_clients on SIGHUP (verified for both adds and
# removals). Adds use that so connected users aren't disturbed; revocation
# does a full restart instead, so a revoked client's already-established
# circuits are dropped rather than left to linger. The tor container's PID 1
# is tor itself (the Containerfile `exec`s it), so the signal reaches it.
reload_tor() { "$ENGINE" kill --signal HUP "$1" >/dev/null; }
restart_tor() { "$ENGINE" restart "$1" >/dev/null; }

cmd_add() {
    local name="$1" c tmp onion priv pub
    valid_name "$name"
    c=$(find_container)
    "$ENGINE" exec "$c" test -e "$AUTH_DIR/$name.auth" \
        && die "client '$name' already exists; remove it first to re-issue"
    onion=$("$ENGINE" exec "$c" cat "$HS_DIR/hostname" | tr -d '[:space:]')
    onion="${onion%.onion}"
    [[ ${#onion} -eq 56 ]] || die "unexpected hostname from tor container: '$onion'"

    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" EXIT
    openssl genpkey -algorithm x25519 -out "$tmp/k.pem" 2>/dev/null
    # x25519 DER encodings end in the raw 32-byte key; Tor wants it base32
    # with the padding stripped.
    priv=$(openssl pkey -in "$tmp/k.pem" -outform DER | tail -c 32 | base32 | tr -d '=')
    pub=$(openssl pkey -in "$tmp/k.pem" -pubout -outform DER | tail -c 32 | base32 | tr -d '=')

    printf 'descriptor:x25519:%s\n' "$pub" \
        | "$ENGINE" exec -i "$c" sh -c "cat > '$AUTH_DIR/$name.auth' \
            && chown debian-tor:debian-tor '$AUTH_DIR/$name.auth' \
            && chmod 600 '$AUTH_DIR/$name.auth'"
    reload_tor "$c"

    cat <<EOF
Authorized client '$name'. Tor was signalled to reload; it can take a minute
or two for the service descriptor to republish before that client can connect.

Give this to that user over a channel you trust (it is shown only once, and
anyone holding it can reach the service as this client):

  ${onion}:descriptor:x25519:${priv}

Tor Browser: about:preferences#privacy -> Onion Services Authentication ->
Add, then paste the base32 key after 'x25519:' (or the whole line, depending
on your Tor Browser version). Or, for a tor daemon, save the full line as
<ClientOnionAuthDir>/${name}.auth_private.
EOF
}

cmd_remove() {
    local name="$1" c
    valid_name "$name"
    c=$(find_container)
    "$ENGINE" exec "$c" test -e "$AUTH_DIR/$name.auth" || die "no such client: $name"
    "$ENGINE" exec "$c" rm -f "$AUTH_DIR/$name.auth"
    restart_tor "$c"
    echo "Revoked '$name'. The tor container was restarted; existing circuits are dropped."
    if [[ -z "$("$ENGINE" exec "$c" sh -c "ls '$AUTH_DIR' | grep '\.auth$'" 2>/dev/null || true)" ]]; then
        echo "WARNING: no authorized clients remain -- the .onion is open to anyone with the address again."
    fi
}

cmd_list() {
    local c
    c=$(find_container)
    "$ENGINE" exec "$c" sh -c "ls '$AUTH_DIR' 2>/dev/null | sed -n 's/\.auth$//p'"
}

case "${1:-}" in
    add)    [[ $# -eq 2 ]] || die "usage: $0 add <name>";    cmd_add "$2" ;;
    remove) [[ $# -eq 2 ]] || die "usage: $0 remove <name>"; cmd_remove "$2" ;;
    list)   cmd_list ;;
    *)      die "usage: $0 {add <name>|remove <name>|list}" ;;
esac

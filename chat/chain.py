import hashlib

# The hash a message's prev_hash must equal when it's the first message in a
# chat -- there's nothing before it to hash.
GENESIS_HASH = "0" * 64


def compute_chain_hash(message):
    """Deterministic hash binding a message to its position in the chat's
    transcript. Both the server and any client can independently rederive
    this from fields that are already stored/transmitted -- nothing about it
    is itself persisted for a normal message, so there's no denormalized
    value to keep in sync there.

    Chaining prev_hash into this (and prev_hash into what senders MAC, see
    chatbox.html) is what turns "dropped/reordered/replayed message" into a
    detectable break instead of something a client would silently trust.

    Exception: a message that's been tombstoned by disappearing-messages
    expiry (issue #64, see Message.tombstone_hash) has this exact value
    persisted from the moment its content was wiped -- returned directly
    here rather than recomputed, since recomputing from the now-nulled
    encrypted_text/aes_nonce/aes_tag/mac would produce a different hash
    than what every later message's prev_hash actually chained against,
    which would misreport an expired message as a broken/tampered link."""
    if message.tombstone_hash:
        return message.tombstone_hash
    parts = [
        message.prev_hash,
        str(message.seq),
        str(message.sender_id),
        message.encrypted_text or "",
        message.aes_nonce or "",
        message.aes_tag or "",
        message.mac or "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()

import hashlib

# The hash a message's prev_hash must equal when it's the first message in a
# chat -- there's nothing before it to hash.
GENESIS_HASH = "0" * 64


def compute_chain_hash(message):
    """Deterministic hash binding a message to its position in the chat's
    transcript. Both the server and any client can independently rederive
    this from fields that are already stored/transmitted -- nothing about it
    is itself persisted, so there's no denormalized value to keep in sync.

    Chaining prev_hash into this (and prev_hash into what senders MAC, see
    chatbox.html) is what turns "dropped/reordered/replayed message" into a
    detectable break instead of something a client would silently trust."""
    parts = [
        message.prev_hash,
        str(message.seq),
        str(message.sender_id),
        message.encrypted_text,
        message.aes_nonce or "",
        message.aes_tag or "",
        message.mac or "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()

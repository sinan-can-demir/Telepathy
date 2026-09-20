from rest_framework import serializers
from .models import Message


class MessageSerializer(serializers.ModelSerializer):
    # Display names are chosen per-chat and not required to be unique (there's
    # no account to enforce global uniqueness against anymore), so the
    # frontend must tell "is this my message" apart by sender_id, not by
    # comparing display-name strings.
    sender_id = serializers.IntegerField(read_only=True)
    sender_public_key = serializers.CharField(source="sender.public_key",         read_only=True)
    sender_username = serializers.CharField(source="sender.display_name",       read_only=True)
    my_encrypted_symmetric_key = serializers.SerializerMethodField()
    # Bucketed to the minute -- see issue #59: a full (microsecond-precision)
    # timestamp lets anyone observing the API response correlate an exact
    # send moment against other signals (network traffic timing, a
    # participant's own out-of-band account of when they sent something).
    # The stored value keeps full precision (ordering/indexing still uses
    # it); only what's exposed here is coarsened. Nothing user-visible is
    # lost -- chatbox.html's renderMsg only ever displays hour:minute anyway.
    timestamp = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "encrypted_text",
            "my_encrypted_symmetric_key",
            "aes_nonce",
            "aes_tag",
            "mac",
            "seq",
            "prev_hash",
            "sender_chain_epoch",
            "chain_index",
            "timestamp",
            "sender_id",
            "sender_public_key",
            "sender_username",
            # Disappearing messages (issue #64): ttl_seconds is null for an
            # ordinary, non-expiring message. tombstone_hash is only ever
            # set once this message's content has been wiped (see
            # services.sweep_expired_messages) -- its presence is what
            # chatbox.html uses to render an "expired" placeholder instead
            # of attempting to decrypt now-null encrypted_text/aes_nonce/
            # aes_tag/mac, and to short-circuit its own chain-hash walk to
            # this persisted value instead of recomputing from those nulls.
            "ttl_seconds",
            "tombstone_hash",
        ]

    def get_my_encrypted_symmetric_key(self, obj):
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return None
        key = next(
            (k for k in obj.wrapped_keys.all() if k.recipient_id == request.user.id),
            None,
        )
        return key.encrypted_symmetric_key if key else None

    def get_timestamp(self, obj):
        return obj.timestamp.replace(second=0, microsecond=0).isoformat()

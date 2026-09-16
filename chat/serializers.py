from rest_framework import serializers
from .models import Message


class MessageSerializer(serializers.ModelSerializer):
    # Display names are chosen per-chat and not required to be unique (there's
    # no account to enforce global uniqueness against anymore), so the
    # frontend must tell "is this my message" apart by sender_id, not by
    # comparing display-name strings.
    sender_id = serializers.IntegerField(read_only=True)
    sender_public_key = serializers.CharField(source="sender.public_key",         read_only=True)
    sender_signing_public_key = serializers.CharField(source="sender.signing_public_key", read_only=True)
    sender_username = serializers.CharField(source="sender.display_name",       read_only=True)
    my_encrypted_symmetric_key = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            "id",
            "encrypted_text",
            "my_encrypted_symmetric_key",
            "aes_nonce",
            "aes_tag",
            "signature",
            "timestamp",
            "sender_id",
            "sender_public_key",
            "sender_signing_public_key",
            "sender_username",
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

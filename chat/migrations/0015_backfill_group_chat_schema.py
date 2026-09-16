import logging

from django.db import migrations

logger = logging.getLogger(__name__)


def backfill(apps, schema_editor):
    Chat = apps.get_model("chat", "Chat")
    ChatParticipant = apps.get_model("chat", "ChatParticipant")
    Message = apps.get_model("chat", "Message")
    MessageKey = apps.get_model("chat", "MessageKey")

    # 1) Create a ChatParticipant for each legacy user1/user2 slot.
    for chat in Chat.objects.all():
        if chat.user1_id:
            ChatParticipant.objects.get_or_create(chat=chat, user_id=chat.user1_id)
        if chat.user2_id:
            ChatParticipant.objects.get_or_create(chat=chat, user_id=chat.user2_id)

    # 2) Link each Message to the Chat containing exactly {sender, receiver}.
    #    Prefer the most recently created matching chat if more than one exists.
    orphaned = 0
    for message in Message.objects.all().iterator():
        if not message.receiver_id:
            orphaned += 1
            message_id = message.pk
            Message.objects.filter(pk=message_id).delete()
            continue

        candidate = (
            Chat.objects.filter(participants__user_id=message.sender_id)
            .filter(participants__user_id=message.receiver_id)
            .order_by("-created_at")
            .first()
        )
        if candidate is None:
            orphaned += 1
            Message.objects.filter(pk=message.pk).delete()
            continue

        message.chat_id = candidate.pk
        message.save(update_fields=["chat"])

    if orphaned:
        logger.warning(
            "[group-chat-migration] Deleted %d message(s) that couldn't be "
            "matched to a chat during backfill (no resolvable sender/receiver "
            "chat pairing).",
            orphaned,
        )

    # 3) Create MessageKey rows from the legacy wrapped-key fields.
    keys_to_create = []
    for message in Message.objects.exclude(chat_id=None).iterator():
        if message.encrypted_symmetric_key and message.receiver_id:
            keys_to_create.append(
                MessageKey(
                    message_id=message.pk,
                    recipient_id=message.receiver_id,
                    encrypted_symmetric_key=message.encrypted_symmetric_key,
                )
            )
        if message.sender_encrypted_symmetric_key:
            keys_to_create.append(
                MessageKey(
                    message_id=message.pk,
                    recipient_id=message.sender_id,
                    encrypted_symmetric_key=message.sender_encrypted_symmetric_key,
                )
            )
    MessageKey.objects.bulk_create(keys_to_create, ignore_conflicts=True)


def noop_reverse(apps, schema_editor):
    # Not reversible: the legacy fields are still present at this point in
    # the migration history, so reversal is a no-op rather than attempting
    # to un-backfill.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0014_chatparticipant_messagekey_chat_is_group_and_more"),
    ]

    operations = [
        migrations.RunPython(backfill, noop_reverse),
    ]

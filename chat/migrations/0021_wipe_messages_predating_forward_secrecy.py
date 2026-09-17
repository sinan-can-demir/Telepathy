from django.db import migrations


def wipe_messages_predating_forward_secrecy(apps, schema_editor):
    # Existing messages from a participant other than the reader were
    # encrypted under the old "RSA-wrap this message's key for every active
    # recipient" scheme. Forward secrecy (0022) removes that path entirely
    # for non-self recipients in favor of a locally-derived sending-chain
    # ratchet -- there is no ChainKey history to backfill these older
    # messages into, so they'd become permanently undecryptable garbage
    # rather than a clean cutover. Same single-cutover precedent as 0015/
    # 0018: no real production user base, and message history is already
    # ephemeral by design.
    Message = apps.get_model("chat", "Message")
    Message.objects.all().delete()


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0020_remove_chat_is_active'),
    ]

    operations = [
        migrations.RunPython(wipe_messages_predating_forward_secrecy, noop_reverse),
    ]

from django.db import migrations, models
import django.db.models.deletion


def wipe_chat_data(apps, schema_editor):
    """Existing Chat/ChatParticipant/Message/MessageKey rows are incompatible
    with the new identity model (a ChatParticipant row created under the old
    schema has no display_name/public_key/auth_token_hash, and there's no
    account left to derive them from once User loses those fields). Per the
    project's established single-cutover precedent (see 0015's docstring/
    commit history) there is no real production user base to preserve here,
    so this clears the slate rather than papering over incompatible rows
    with meaningless placeholder values. Cascades: deleting Chat removes its
    ChatParticipant/Message/MessageKey rows too."""
    Chat = apps.get_model("chat", "Chat")
    Chat.objects.all().delete()


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0016_remove_message_msg_recv_time_idx_remove_chat_user1_and_more"),
    ]

    operations = [
        migrations.RunPython(wipe_chat_data, noop_reverse),
        migrations.AlterUniqueTogether(
            name="chatparticipant",
            unique_together=set(),
        ),
        migrations.RemoveField(
            model_name="chatparticipant",
            name="user",
        ),
        migrations.AddField(
            model_name="chatparticipant",
            name="display_name",
            field=models.CharField(default="", max_length=32),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="chatparticipant",
            name="public_key",
            field=models.TextField(default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="chatparticipant",
            name="signing_public_key",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="chatparticipant",
            name="auth_token_hash",
            field=models.CharField(default="", max_length=64, unique=True, db_index=True),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="message",
            name="sender",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="sent_messages",
                to="chat.chatparticipant",
            ),
        ),
        migrations.AlterField(
            model_name="messagekey",
            name="recipient",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="message_keys",
                to="chat.chatparticipant",
            ),
        ),
        migrations.RemoveField(
            model_name="user",
            name="public_key",
        ),
        migrations.RemoveField(
            model_name="user",
            name="signing_public_key",
        ),
        migrations.RemoveField(
            model_name="user",
            name="totp_secret",
        ),
        migrations.RemoveField(
            model_name="user",
            name="is_2fa_enabled",
        ),
    ]

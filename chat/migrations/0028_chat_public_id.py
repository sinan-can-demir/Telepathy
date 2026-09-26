import secrets

from django.db import migrations, models

import chat.models


def fill_public_ids(apps, schema_editor):
    # Existing chats get an id too, but their clients have the PIN stored as
    # chat_id, which no longer resolves: they see "Chat ended" and return to
    # the dashboard, and the reaper deletes the rows once idle (#101 stage 1).
    Chat = apps.get_model("chat", "Chat")
    for chat in Chat.objects.all():
        chat.public_id = secrets.token_urlsafe(12)
        chat.save(update_fields=["public_id"])


class Migration(migrations.Migration):

    dependencies = [
        ("chat", "0027_remove_messagekey"),
    ]

    operations = [
        migrations.AddField(
            model_name="chat",
            name="public_id",
            field=models.CharField(editable=False, max_length=16, null=True),
        ),
        migrations.RunPython(fill_public_ids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="chat",
            name="public_id",
            field=models.CharField(default=chat.models.new_chat_public_id, editable=False, max_length=16, unique=True),
        ),
    ]

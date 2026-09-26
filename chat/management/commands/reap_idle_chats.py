import logging
import time

from django.core.management.base import BaseCommand

from chat import services
from chat.realtime import notify_chat

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = (
        "Expire participants idle past IDLE_TIMEOUT and delete chats left with "
        "no active participant (issue #97). Runs once, or forever with --every."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--every", type=int, metavar="SECONDS",
            help="Keep running, reaping every SECONDS (the compose `reaper` service uses 300).",
        )

    def handle(self, *args, every=None, **options):
        if not every:
            self.reap_once()
            return
        while True:
            # A failed pass (database still starting, a migration not yet
            # applied) is logged and retried next time rather than ending
            # the loop and relying on the container restart policy.
            try:
                self.reap_once()
            except Exception:
                logger.exception("[REAPER] pass failed")
            time.sleep(every)

    def reap_once(self):
        expired, deleted, changed_ids = services.reap_idle_chats()
        for chat_id in changed_ids:
            try:
                notify_chat(chat_id, "roster_changed")
            except Exception:
                # Only a nudge; remaining members' 15s poll catches it anyway.
                logger.warning("[REAPER] could not notify chat %s", chat_id)
        if expired or deleted:
            logger.info(f"[REAPER] expired {expired} idle participant(s), deleted {deleted} empty chat(s).")

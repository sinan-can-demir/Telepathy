"""
ASGI config for pc project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pc.settings')

# get_asgi_application() must run first -- it populates Django's app registry,
# which chat.routing (and the consumers/models it imports) depends on.
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402

import chat.routing  # noqa: E402

# No AuthMiddlewareStack: that wraps django.contrib.auth sessions/cookies,
# which this app doesn't use for chat participants -- ChatConsumer validates
# the bearer token itself, the same way ParticipantTokenAuthentication does
# for HTTP (see chat/consumers.py).
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": URLRouter(chat.routing.websocket_urlpatterns),
})

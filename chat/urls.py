# chat/urls.py

from django.urls import path

from . import views
from .views import (
    CheckChatView,
    LeaveChatView,
    auth_page,
    SendMessageView,
    GetMessagesView,
    user_menu,
    CreateChatView,
    JoinChatView,
    GetChatParticipantsView,
    chatbox,
)

urlpatterns = [
    #  User Menu (renders usermenu.html)
    path("usermenu/", user_menu, name="user_menu"),

    #  Chat‐related API endpoints
    path("check-chat/<str:chat_id>/", CheckChatView.as_view(), name="check-chat"),
    path(
        "leave-chat/",
        LeaveChatView.as_view(),
        name="leave_chat_body"
    ),
    path('send-message/<str:chat_id>/', views.SendMessageView.as_view(), name='send_message'),
    path('get-messages/<str:chat_id>/', views.GetMessagesView.as_view(), name='get_messages'),
    path('get-chat-participants/<str:chat_id>/', GetChatParticipantsView.as_view(), name='get-chat-participants'),

    path("create-chat/",    CreateChatView.as_view(),   name="create-chat"),
    path("join-chat/",      JoinChatView.as_view(),     name="join-chat"),

    # Chatbox page (renders chatbox.html)
    path("chatbox/", chatbox, name="chatbox"),

    #  Root of /chat/ serves your auth page (landing page; no login/register anymore)
    path("", views.auth_page, name="auth_page"),
]

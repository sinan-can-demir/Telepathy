from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, Chat, ChatParticipant, Message, MessageReadReceipt, ChainKey, ChainKeyWrap,
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Operator/staff accounts only (Django admin login) -- end users never
    have a User row anymore; see ChatParticipant."""
    list_display = ('username', 'email', 'is_staff')
    search_fields = ('username', 'email')


class ChatParticipantInline(admin.TabularInline):
    model = ChatParticipant
    extra = 0
    readonly_fields = ('joined_at', 'auth_token_hash')
    fields = ('display_name', 'joined_at', 'left_at', 'auth_token_hash')


@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    # No is_active column -- a Chat row's existence is its active flag now;
    # ended chats are hard-deleted (see LeaveChatView) to free their PIN.
    list_display = ('pin', 'is_group', 'max_participants', 'created_at')
    list_filter = ('is_group',)
    search_fields = ('pin', 'participants__display_name')
    inlines = [ChatParticipantInline]


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'chat', 'timestamp', 'ttl_seconds', 'tombstoned_at')
    list_filter = ('timestamp', 'tombstoned_at')
    search_fields = ('sender__display_name', 'chat__pin')
    readonly_fields = ('id', 'timestamp', 'tombstone_hash', 'tombstoned_at')


@admin.register(MessageReadReceipt)
class MessageReadReceiptAdmin(admin.ModelAdmin):
    list_display = ('message', 'participant', 'read_at')
    search_fields = ('participant__display_name', 'message__id')


class ChainKeyWrapInline(admin.TabularInline):
    model = ChainKeyWrap
    extra = 0
    readonly_fields = ('recipient',)
    fields = ('recipient',)


@admin.register(ChainKey)
class ChainKeyAdmin(admin.ModelAdmin):
    list_display = ('sender', 'epoch', 'chat', 'created_at')
    list_filter = ('epoch',)
    search_fields = ('sender__display_name', 'chat__pin')
    inlines = [ChainKeyWrapInline]

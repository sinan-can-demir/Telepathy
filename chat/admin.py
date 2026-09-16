from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Chat, ChatParticipant, Message, MessageKey


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Encryption Keys', {
            'fields': ('public_key', 'signing_public_key'),
        }),
        ('Two-Factor Auth', {
            'fields': ('totp_secret', 'is_2fa_enabled'),
        }),
    )
    list_display = ('username', 'email', 'is_2fa_enabled', 'is_staff')
    search_fields = ('username', 'email')


class ChatParticipantInline(admin.TabularInline):
    model = ChatParticipant
    extra = 0
    readonly_fields = ('joined_at',)


@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    list_display = ('pin', 'is_group', 'max_participants', 'is_active', 'created_at')
    list_filter = ('is_active', 'is_group')
    search_fields = ('pin', 'participants__user__username')
    inlines = [ChatParticipantInline]


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'chat', 'timestamp')
    list_filter = ('timestamp',)
    search_fields = ('sender__username', 'chat__pin')
    readonly_fields = ('id', 'timestamp')


@admin.register(MessageKey)
class MessageKeyAdmin(admin.ModelAdmin):
    list_display = ('message', 'recipient')
    search_fields = ('recipient__username', 'message__id')

from django.contrib import admin
from .models import UserAccount, EmailOTP, OwnerJobPost, WorkerAvailability

@admin.register(UserAccount)
class UserAccountAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'role', 'phone_number', 'tag', 'created_at')
    search_fields = ('email', 'name', 'phone_number', 'tag')
    list_filter = ('role', 'created_at')

@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ('email', 'code', 'is_verified', 'created_at', 'expires_at')
    search_fields = ('email', 'code')
    list_filter = ('is_verified', 'created_at')

@admin.register(OwnerJobPost)
class OwnerJobPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'district', 'price', 'is_completed', 'created_at', 'posted_by')
    search_fields = ('title', 'district', 'posted_by__email')
    list_filter = ('district', 'is_completed', 'created_at')

@admin.register(WorkerAvailability)
class WorkerAvailabilityAdmin(admin.ModelAdmin):
    list_display = ('job_type', 'district', 'price', 'created_at', 'posted_by')
    search_fields = ('job_type', 'district', 'posted_by__email')
    list_filter = ('district', 'created_at')

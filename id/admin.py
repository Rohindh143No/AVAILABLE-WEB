from django.contrib import admin
from django.utils import timezone
from .models import UserAccount, EmailOTP, OwnerJobPost, WorkerAvailability, PaymentTransaction, PayoutRequest


@admin.register(UserAccount)
class UserAccountAdmin(admin.ModelAdmin):
    list_display = ['email', 'name', 'role', 'phone_number', 'created_at']
    list_filter = ['role', 'created_at']
    search_fields = ['email', 'name', 'phone_number']
    ordering = ['-created_at']


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ['email', 'code', 'is_verified', 'created_at', 'expires_at']
    list_filter = ['is_verified', 'created_at']
    search_fields = ['email']
    ordering = ['-created_at']


@admin.register(OwnerJobPost)
class OwnerJobPostAdmin(admin.ModelAdmin):
    list_display = ['title', 'posted_by', 'price', 'district', 'is_completed', 'created_at']
    list_filter = ['is_completed', 'district', 'created_at']
    search_fields = ['title', 'posted_by__email', 'district']
    ordering = ['-created_at']


@admin.register(WorkerAvailability)
class WorkerAvailabilityAdmin(admin.ModelAdmin):
    list_display = ['job_type', 'posted_by', 'price', 'district', 'place', 'created_at']
    list_filter = ['job_type', 'district', 'created_at']
    search_fields = ['job_type', 'posted_by__email', 'district', 'place']
    ordering = ['-created_at']


# NEW PAYMENT ADMIN CLASSES
@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display = ['transaction_id', 'user_email', 'amount', 'payment_type', 'status', 'created_at']
    list_filter = ['status', 'payment_type', 'created_at']
    search_fields = ['transaction_id', 'user_email', 'job_id']
    ordering = ['-created_at']
    actions = ['mark_as_completed', 'mark_as_failed']
    
    def mark_as_completed(self, request, queryset):
        queryset.update(status='completed')
        self.message_user(request, f'{queryset.count()} transactions marked as completed.')
    mark_as_completed.short_description = "Mark selected transactions as completed"
    
    def mark_as_failed(self, request, queryset):
        queryset.update(status='failed')
        self.message_user(request, f'{queryset.count()} transactions marked as failed.')
    mark_as_failed.short_description = "Mark selected transactions as failed"


@admin.register(PayoutRequest)
class PayoutRequestAdmin(admin.ModelAdmin):
    list_display = ['worker_email', 'worker_upi', 'amount', 'job_id', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['worker_email', 'worker_upi', 'job_id']
    ordering = ['-created_at']
    actions = ['mark_as_processed']
    
    def mark_as_processed(self, request, queryset):
        queryset.update(status='processed', processed_at=timezone.now())
        self.message_user(request, f'{queryset.count()} payout requests marked as processed.')
    mark_as_processed.short_description = "Mark selected payouts as processed"

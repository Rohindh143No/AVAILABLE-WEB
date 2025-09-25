from django.db import models
from django.utils import timezone

# Role choices
ROLE_CHOICES = [
    ('worker', 'Worker'),
    ('owner', 'Owner'),
]

class UserAccount(models.Model):
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    password_plain = models.CharField(max_length=128, blank=True, null=True)  # TITLE: DEV ONLY (plain text for local HTML reveal, do not use in production)
    name = models.CharField(max_length=80, blank=True, default='')
    bio = models.CharField(max_length=100, blank=True, default='')
    profile_image = models.ImageField(upload_to='profiles/', blank=True, null=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, blank=True, default='')  # TITLE: Profile
    phone_number = models.CharField(max_length=20, blank=True, default='')
    tag = models.CharField(max_length=30, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

class EmailOTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=5)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.email} - {self.code}"

# --- Booking status choices used for two-way acceptance ---
BOOKING_STATUS_CHOICES = [
    ('available', 'Available'),
    ('pending_accept', 'Pending Acceptance'),
    ('accepted', 'Accepted'),
    ('rejected', 'Rejected'),
]

class OwnerJobPost(models.Model):
    posted_by = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    district = models.CharField(max_length=60)
    address = models.CharField(max_length=200)
    description = models.TextField(blank=True, default='')
    is_completed = models.BooleanField(default=False)
    is_paid = models.BooleanField(default=False)  # Track if job is paid
    status = models.CharField(max_length=20, choices=BOOKING_STATUS_CHOICES, default='available')  # NEW: Booking status
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} - {self.posted_by.email}"

class WorkerAvailability(models.Model):
    posted_by = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    job_type = models.CharField(max_length=120)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    district = models.CharField(max_length=60)
    place = models.CharField(max_length=120)
    time_info = models.CharField(max_length=60)
    description = models.TextField(blank=True, default='')
    is_paid = models.BooleanField(default=False)  # Track if availability is paid
    status = models.CharField(max_length=20, choices=BOOKING_STATUS_CHOICES, default='available')  # NEW: Booking status
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.job_type} - {self.posted_by.email}"

class PaymentTransaction(models.Model):
    PAYMENT_TYPES = [
        ('owner_booking', 'Owner Booking Worker'),
        ('worker_booking', 'Worker Booking Job'),
        ('advance', 'Advance Payment'),
        ('full', 'Full Payment'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
        ('accepted', 'Accepted'),  # Extended for two-way accept
        ('rejected', 'Rejected'),  # Extended for two-way reject
    ]

    # Razorpay fields
    razorpay_order_id = models.CharField(max_length=100, blank=True, null=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True, null=True)
    razorpay_signature = models.CharField(max_length=200, blank=True, null=True)

    # Transaction details
    transaction_id = models.CharField(max_length=100, unique=True)
    user_email = models.EmailField()
    job_id = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Additional fields
    currency = models.CharField(max_length=3, default='INR')
    description = models.TextField(blank=True, default='')
    metadata = models.JSONField(default=dict, blank=True)

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.transaction_id} - ₹{self.amount} - {self.status}"

    def mark_completed(self):
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.save()

class PayoutRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processed', 'Processed'),
        ('failed', 'Failed'),
    ]

    worker_email = models.EmailField()
    worker_upi = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    job_id = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Razorpay payout fields
    razorpay_payout_id = models.CharField(max_length=100, blank=True, null=True)
    failure_reason = models.TextField(blank=True, default='')

    # Timestamps
    processed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.worker_email} - ₹{self.amount} - {self.status}"

class PaymentRefund(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processed', 'Processed'),
        ('failed', 'Failed'),
    ]
    transaction = models.ForeignKey(PaymentTransaction, on_delete=models.CASCADE)
    refund_amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.TextField(blank=True, default='')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # Razorpay refund fields
    razorpay_refund_id = models.CharField(max_length=100, blank=True, null=True)
    failure_reason = models.TextField(blank=True, default='')

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    processed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Refund for {self.transaction.transaction_id} - ₹{self.refund_amount}"

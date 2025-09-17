from django.db import models

ROLE_CHOICES = (
    ('worker', 'Worker'),
    ('owner', 'Owner'),
)

class UserAccount(models.Model):
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    # DEV ONLY: plain text for local HTML reveal (do not use in production)
    password_plain = models.CharField(max_length=128, blank=True, null=True)

    # Profile
    name = models.CharField(max_length=80, blank=True, default='')
    bio = models.CharField(max_length=100, blank=True, default='')
    profile_image = models.ImageField(upload_to='profiles/', blank=True, null=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, blank=True, default='')

    # New fields
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

class OwnerJobPost(models.Model):
    posted_by = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='owner_posts')
    title = models.CharField(max_length=120)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    district = models.CharField(max_length=60)
    address = models.CharField(max_length=200)
    description = models.TextField(blank=True, default='')
    is_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[OwnerJob] {self.title} - {self.district}"

class WorkerAvailability(models.Model):
    posted_by = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='worker_posts')
    job_type = models.CharField(max_length=120)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    district = models.CharField(max_length=60)
    place = models.CharField(max_length=120)
    time_info = models.CharField(max_length=60)
    description = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[Worker] {self.job_type} - {self.district}"

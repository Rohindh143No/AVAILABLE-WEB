# id/models.py
from django.db import models

class UserAccount(models.Model):
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    # DEV ONLY: plain view in HTML dashboard; do not use in production
    password_plain = models.CharField(max_length=128, blank=True, null=True)

    # Profile fields
    name = models.CharField(max_length=80, blank=True, default='')
    bio = models.CharField(max_length=100, blank=True, default='')
    profile_image = models.ImageField(upload_to='profiles/', blank=True, null=True)

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

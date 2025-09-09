# id/models.py
from django.db import models

class UserAccount(models.Model):
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    # DEV ONLY: for local HTML reveal; do not use in production
    password_plain = models.CharField(max_length=128, blank=True, null=True)
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

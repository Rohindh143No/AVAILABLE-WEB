# id/utils.py
import secrets
import string
from datetime import timedelta
from django.utils import timezone

def generate_otp_5():
    digits = string.digits
    return ''.join(secrets.choice(digits) for _ in range(5))

def expiry_in(minutes=10):
    return timezone.now() + timedelta(minutes=minutes)

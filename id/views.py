# id/views.py
import json, base64, uuid
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.shortcuts import render
from django.core.paginator import Paginator
from django.core.files.base import ContentFile
from django.conf import settings
from .models import UserAccount, EmailOTP
from .utils import generate_otp_5, expiry_in

def _json_error(message, status=400):
    return JsonResponse({'success': False, 'message': message}, status=status)

def admin_page(request):
    users_qs = UserAccount.objects.order_by('-created_at')
    otps_qs = EmailOTP.objects.order_by('-created_at')
    users_page = Paginator(users_qs, 20).get_page(request.GET.get('u', 1))
    otps_page = Paginator(otps_qs, 20).get_page(request.GET.get('o', 1))
    return render(request, 'id.html', {'users_page': users_page, 'otps_page': otps_page})

@csrf_exempt
def signup_view(request):
    if request.method != 'POST':
        return _json_error('POST required', 405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        password = payload.get('password') or ''
        if not email or not password:
            return _json_error('Email and password required')
        if UserAccount.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'message': 'Email already created, login with password'})
        ua = UserAccount.objects.create(
            email=email, password_hash=make_password(password), password_plain=password
        )
        return JsonResponse({'success': True, 'message': 'Account created', 'email': ua.email})
    except Exception as e:
        return _json_error(f'Error: {e}')

@csrf_exempt
def login_view(request):
    if request.method != 'POST':
        return _json_error('POST required', 405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        password = payload.get('password') or ''
        if not email or not password:
            return _json_error('Email and password required')
        try:
            ua = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return _json_error('Invalid credentials', 401)
        if not check_password(password, ua.password_hash):
            return _json_error('Invalid credentials', 401)
        return JsonResponse({'success': True, 'message': 'Login successful', 'email': ua.email})
    except Exception as e:
        return _json_error(f'Error: {e}')

@csrf_exempt
def forgot_password_view(request):
    if request.method != 'POST':
        return _json_error('POST required', 405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        if not email:
            return _json_error('Email required')
        code = generate_otp_5()
        EmailOTP.objects.create(email=email, code=code, expires_at=expiry_in(10))
        subject = 'AVAILABLE OTP (Password Reset)'
        msg = f'Your 5-digit OTP is: {code}\nThis code expires in 10 minutes.\nEmail: {email}'
        send_mail(subject, msg, None, [email], fail_silently=False)
        return JsonResponse({'success': True, 'message': 'OTP sent to email'})
    except Exception as e:
        return _json_error(f'Error: {e}')

@csrf_exempt
def verify_otp_view(request):
    if request.method != 'POST':
        return _json_error('POST required', 405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        otp = (payload.get('otp') or '').strip()
        new_password = payload.get('new_password') or ''
        if not email or not otp or not new_password:
            return _json_error('Email, OTP, and new_password required')
        rec = EmailOTP.objects.filter(email=email, code=otp).order_by('-created_at').first()
        if not rec:
            return _json_error('Invalid OTP', 400)
        if rec.is_verified:
            return _json_error('OTP already used', 400)
        if timezone.now() > rec.expires_at:
            return _json_error('OTP expired', 400)
        try:
            ua = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return _json_error('Account not found', 404)
        ua.password_hash = make_password(new_password)
        ua.password_plain = new_password  # DEV ONLY
        ua.save(update_fields=['password_hash', 'password_plain'])
        rec.is_verified = True
        rec.save(update_fields=['is_verified'])
        return JsonResponse({'success': True, 'message': 'Password updated'})
    except Exception as e:
        return _json_error(f'Error: {e}')

@csrf_exempt
def delete_user_view(request):
    if request.method != 'POST':
        return _json_error('POST required', 405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        if not email:
            return _json_error('Email required')
        deleted, _ = UserAccount.objects.filter(email=email).delete()
        if deleted == 0:
            return _json_error('User not found', 404)
        return JsonResponse({'success': True, 'message': 'User deleted', 'email': email})
    except Exception as e:
        return _json_error(f'Error: {e}')

@csrf_exempt
def delete_otp_view(request):
    if request.method != 'POST':
        return _json_error('POST required', 405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        oid = payload.get('id')
        if not oid:
            return _json_error('OTP id required')
        deleted, _ = EmailOTP.objects.filter(id=oid).delete()
        if deleted == 0:
            return _json_error('OTP not found', 404)
        return JsonResponse({'success': True, 'message': 'OTP deleted', 'id': oid})
    except Exception as e:
        return _json_error(f'Error: {e}')

def _profile_to_dict(u: UserAccount, request):
    img_url = ''
    if u.profile_image:
      # absolute URL
      img_url = request.build_absolute_uri(u.profile_image.url)
    return {'email': u.email, 'name': u.name, 'bio': u.bio, 'profile_image_url': img_url}

@csrf_exempt
def profile_view(request):
    if request.method == 'GET':
        email = (request.GET.get('email') or '').strip().lower()
        if not email:
            return _json_error('Email required')
        try:
            u = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return JsonResponse({'success': True, 'profile': {'email': email, 'name': '', 'bio': '', 'profile_image_url': ''}})
        return JsonResponse({'success': True, 'profile': _profile_to_dict(u, request)})

    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8'))
            email = (payload.get('email') or '').strip().lower()
            name = (payload.get('name') or '').strip()
            bio = (payload.get('bio') or '').strip()
            b64 = payload.get('profile_image_base64')
            if not email:
                return _json_error('Email required')
            try:
                u = UserAccount.objects.get(email=email)
            except UserAccount.DoesNotExist:
                return _json_error('Account not found', 404)
            if len(bio) > 100:
                return _json_error('Bio must be <= 100 chars')
            u.name = name[:80]
            u.bio = bio[:100]
            if b64:
                try:
                    data = base64.b64decode(b64)
                    fname = f"{uuid.uuid4().hex}.png"
                    u.profile_image.save(fname, ContentFile(data), save=False)
                except Exception:
                    return _json_error('Invalid image data')
            u.save()
            return JsonResponse({'success': True, 'profile': _profile_to_dict(u, request)})
        except Exception as e:
            return _json_error(f'Error: {e}')

    return _json_error('Method not allowed', 405)

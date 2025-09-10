# id/views.py
import json
import base64
import uuid
from decimal import Decimal, InvalidOperation

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.shortcuts import render
from django.core.paginator import Paginator
from django.core.files.base import ContentFile
from django.db.models import Sum, Q

from .models import UserAccount, EmailOTP, OwnerJobPost, WorkerAvailability
from .utils import generate_otp_5, expiry_in

# Acceptable roles for "WANT" selection
VALID_ROLES = {"worker", "owner"}

def _json_error(message, status=400):
    return JsonResponse({'success': False, 'message': message}, status=status)

def admin_page(request):
    """
    Renders the HTML dashboard with paginated users and OTPs (20 per page).
    Query params:
    - u: users page number
    - o: otps page number
    """
    users_qs = UserAccount.objects.order_by('-created_at')
    otps_qs = EmailOTP.objects.order_by('-created_at')

    users_page = Paginator(users_qs, 20).get_page(request.GET.get('u', 1))
    otps_page = Paginator(otps_qs, 20).get_page(request.GET.get('o', 1))

    return render(request, 'id.html', {
        'users_page': users_page,
        'otps_page': otps_page,
    })

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
            email=email,
            password_hash=make_password(password),
            # DEV ONLY: store plain password for local dashboard view; remove for production
            password_plain=password,
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
    """
    Serializes profile with absolute image URL and computed stats.
    """
    img_url = ''
    if u.profile_image:
        img_url = request.build_absolute_uri(u.profile_image.url)
    jobs_posted = OwnerJobPost.objects.filter(posted_by=u).count()
    jobs_completed = OwnerJobPost.objects.filter(posted_by=u, is_completed=True).count()
    earnings_dec = OwnerJobPost.objects.filter(posted_by=u, is_completed=True).aggregate(total=Sum('price'))['total'] or Decimal('0.00')
    return {
        'email': u.email,
        'name': u.name,
        'bio': u.bio,
        'role': getattr(u, 'role', ''),
        'phone_number': getattr(u, 'phone_number', ''),
        'tag': getattr(u, 'tag', ''),
        'profile_image_url': img_url,
        'jobs_posted': jobs_posted,
        'jobs_completed': jobs_completed,
        'earnings': float(earnings_dec),
    }

@csrf_exempt
def profile_view(request):
    """
    GET /api/auth/profile/?email=... -> { success, profile{...} }
    POST /api/auth/profile/ -> { success, profile{...} }
    POST body (JSON):
    email (required), name, bio (<=100), role in {'worker','owner'}, phone_number (required), tag (optional), profile_image_base64
    """
    if request.method == 'GET':
        email = (request.GET.get('email') or '').strip().lower()
        if not email:
            return _json_error('Email required')
        try:
            u = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return JsonResponse({
                'success': True,
                'profile': {
                    'email': email,
                    'name': '',
                    'bio': '',
                    'role': '',
                    'phone_number': '',
                    'tag': '',
                    'profile_image_url': '',
                    'jobs_posted': 0,
                    'jobs_completed': 0,
                    'earnings': 0.0,
                }
            })
        return JsonResponse({'success': True, 'profile': _profile_to_dict(u, request)})

    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8'))
            email = (payload.get('email') or '').strip().lower()
            name = (payload.get('name') or '').strip()
            bio = (payload.get('bio') or '').strip()
            role = (payload.get('role') or '').strip()
            phone_number = (payload.get('phone_number') or '').strip()
            tag = (payload.get('tag') or '').strip()
            b64 = payload.get('profile_image_base64')

            if not email:
                return _json_error('Email required')
            try:
                u = UserAccount.objects.get(email=email)
            except UserAccount.DoesNotExist:
                return _json_error('Account not found', 404)

            if len(bio) > 100:
                return _json_error('Bio must be <= 100 chars')
            if not phone_number:
                return _json_error('Phone number required')
            compact = phone_number.replace('+', '').replace('-', '').replace(' ', '')
            if not compact.isdigit():
                return _json_error('Invalid phone number')

            if role and role not in VALID_ROLES:
                return _json_error('Invalid role')

            u.name = name[:80]
            u.bio = bio[:100]
            if role:
                u.role = role
            u.phone_number = phone_number[:20]
            u.tag = tag[:30]

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

def _paginate(request, qs, page_size=20):
    page = int(request.GET.get('page', 1) or 1)
    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(page)
    return page_obj, paginator

def _serialize_user_brief(u: UserAccount, request):
    img_url = ''
    if u.profile_image:
        img_url = request.build_absolute_uri(u.profile_image.url)
    return {
        'email': u.email,
        'name': u.name,
        'bio': u.bio,
        'tag': getattr(u, 'tag', ''),
        'profile_image_url': img_url,
    }

def _serialize_owner_job(j: OwnerJobPost, request):
    return {
        'id': j.id,
        'title': j.title,
        'price': float(j.price),
        'district': j.district,
        'address': j.address,
        'description': j.description,
        'created_at': j.created_at.isoformat(),
        'is_completed': j.is_completed,
        'posted_by': _serialize_user_brief(j.posted_by, request),
    }

def _serialize_worker_avail(w: WorkerAvailability, request):
    return {
        'id': w.id,
        'job_type': w.job_type,
        'price': float(w.price),
        'district': w.district,
        'place': w.place,
        'time_info': w.time_info,
        'description': w.description,
        'created_at': w.created_at.isoformat(),
        'posted_by': _serialize_user_brief(w.posted_by, request),
    }

@csrf_exempt
def work_view(request):
    """
    GET /api/auth/work/?q=&district=&min_price=&max_price=&page=
    POST /api/auth/work/ (owner only)
    body: { email, title, price, district, address, description }
    """
    if request.method == 'GET':
        qs = OwnerJobPost.objects.all().order_by('-created_at')
        q = (request.GET.get('q') or '').strip()
        district = (request.GET.get('district') or '').strip()
        min_price = (request.GET.get('min_price') or '').strip()
        max_price = (request.GET.get('max_price') or '').strip()

        if q:
            qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q) | Q(address__icontains=q))
        if district:
            qs = qs.filter(district__icontains=district)

        try:
            if min_price:
                qs = qs.filter(price__gte=Decimal(min_price))
            if max_price:
                qs = qs.filter(price__lte=Decimal(max_price))
        except InvalidOperation:
            return _json_error('Invalid price filter')

        page_obj, paginator = _paginate(request, qs, page_size=20)
        return JsonResponse({
            'success': True,
            'results': [_serialize_owner_job(j, request) for j in page_obj.object_list],
            'page': page_obj.number,
            'num_pages': paginator.num_pages
        })

    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8'))
            email = (payload.get('email') or '').strip().lower()
            title = (payload.get('title') or '').strip()
            price_raw = (payload.get('price') or '').strip()
            district = (payload.get('district') or '').strip()
            address = (payload.get('address') or '').strip()
            description = (payload.get('description') or '').strip()

            if not email:
                return _json_error('Email required')
            try:
                u = UserAccount.objects.get(email=email)
            except UserAccount.DoesNotExist:
                return _json_error('Account not found', 404)

            if u.role != 'owner':
                return _json_error('Only owners can create work')

            if not title or not price_raw or not district or not address:
                return _json_error('title, price, district, address required')

            try:
                price = Decimal(price_raw)
            except InvalidOperation:
                return _json_error('Invalid price')

            j = OwnerJobPost.objects.create(
                posted_by=u,
                title=title[:120],
                price=price,
                district=district[:60],
                address=address[:200],
                description=description,
            )
            return JsonResponse({'success': True, 'job': _serialize_owner_job(j, request)})
        except Exception as e:
            return _json_error(f'Error: {e}')

    return _json_error('Method not allowed', 405)

@csrf_exempt
def workers_view(request):
    """
    GET /api/auth/workers/?q=&district=&min_price=&max_price=&page=
    POST /api/auth/workers/ (worker only)
    body: { email, job_type, price, district, place, time_info, description }
    """
    if request.method == 'GET':
        qs = WorkerAvailability.objects.all().order_by('-created_at')
        q = (request.GET.get('q') or '').strip()
        district = (request.GET.get('district') or '').strip()
        min_price = (request.GET.get('min_price') or '').strip()
        max_price = (request.GET.get('max_price') or '').strip()

        if q:
            qs = qs.filter(Q(job_type__icontains=q) | Q(description__icontains=q) | Q(place__icontains=q))
        if district:
            qs = qs.filter(district__icontains=district)

        try:
            if min_price:
                qs = qs.filter(price__gte=Decimal(min_price))
            if max_price:
                qs = qs.filter(price__lte=Decimal(max_price))
        except InvalidOperation:
            return _json_error('Invalid price filter')

        page_obj, paginator = _paginate(request, qs, page_size=20)
        return JsonResponse({
            'success': True,
            'results': [_serialize_worker_avail(w, request) for w in page_obj.object_list],
            'page': page_obj.number,
            'num_pages': paginator.num_pages
        })

    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8'))
            email = (payload.get('email') or '').strip().lower()
            job_type = (payload.get('job_type') or '').strip()
            price_raw = (payload.get('price') or '').strip()
            district = (payload.get('district') or '').strip()
            place = (payload.get('place') or '').strip()
            time_info = (payload.get('time_info') or '').strip()
            description = (payload.get('description') or '').strip()

            if not email:
                return _json_error('Email required')
            try:
                u = UserAccount.objects.get(email=email)
            except UserAccount.DoesNotExist:
                return _json_error('Account not found', 404)

            if u.role != 'worker':
                return _json_error('Only workers can create availability')

            if not job_type or not price_raw or not district or not place or not time_info:
                return _json_error('job_type, price, district, place, time_info required')

            try:
                price = Decimal(price_raw)
            except InvalidOperation:
                return _json_error('Invalid price')

            w = WorkerAvailability.objects.create(
                posted_by=u,
                job_type=job_type[:120],
                price=price,
                district=district[:60],
                place=place[:120],
                time_info=time_info[:60],
                description=description,
            )
            return JsonResponse({'success': True, 'worker': _serialize_worker_avail(w, request)})
        except Exception as e:
            return _json_error(f'Error: {e}')

    return _json_error('Method not allowed', 405)

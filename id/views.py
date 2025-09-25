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
from .models import UserAccount, EmailOTP, OwnerJobPost, WorkerAvailability, PaymentTransaction, PayoutRequest, PaymentRefund
from .utils import generate_otp_5, expiry_in

import razorpay
import hmac
import hashlib
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

# Razorpay configuration - REPLACE WITH YOUR ACTUAL CREDENTIALS
RAZORPAY_KEY_ID = 'rzp_live_RJjVAhSF0TYRxX'  # Replace with your test key
RAZORPAY_KEY_SECRET = 'u0ToZ5Wb44xoozWM0usepuRK'  # Replace with your secret key

client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
@csrf_exempt
def get_user_bookings(request):
    """
    GET /api/auth/bookings/?email=...&role=...
    Returns all bookings/orders (both sent and received, owner or worker).
    """
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)

    user_email = request.GET.get('email', '').strip().lower()
    role = (request.GET.get('role') or '').strip().lower()
    if not user_email or role not in ['owner', 'worker']:
        return JsonResponse({'success': False, 'error': 'Email and valid role required'}, status=400)

    # For OWNER: bookings they've made (outgoing)
    # For WORKER: bookings received (incoming)
    outgoing = PaymentTransaction.objects.filter(user_email=user_email)
    incoming = []

    if role == 'owner':
        incoming = PaymentTransaction.objects.filter(
            job_id__in=WorkerAvailability.objects.filter(posted_by__email=user_email).values_list('id', flat=True)
        )
    else:
        incoming = PaymentTransaction.objects.filter(
            job_id__in=OwnerJobPost.objects.filter(posted_by__email=user_email).values_list('id', flat=True)
        )

    # combine and dedupe
    bookings = outgoing | incoming
    bookings = bookings.distinct().order_by('-created_at')

    result = []
    for txn in bookings:
        # Find if this is an incoming or outgoing for this user
        is_outgoing = (txn.user_email == user_email)
        # Find status (pending, accepted, etc.) from related job or txn
        status = getattr(txn, 'status', 'pending')
        # (You might have a status field on job/txn for two-way acceptance logic)
        result.append({
            'transaction_id': txn.transaction_id,
            'job_id': txn.job_id,
            'user_email': txn.user_email,
            'payment_type': txn.payment_type,
            'is_outgoing': is_outgoing,
            'status': status,
            'created_at': txn.created_at.isoformat(),
        })

    return JsonResponse({'success': True, 'bookings': result})

# RAZORPAY PAYMENT VIEWS
@csrf_exempt
def create_razorpay_order(request):
    """Create a Razorpay order for payment"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        amount = data.get('amount')  # Amount in paise
        job_id = data.get('job_id')
        user_email = data.get('user_email')
        payment_type = data.get('payment_type', 'advance')
        currency = data.get('currency', 'INR')
        
        if not all([amount, job_id, user_email]):
            return JsonResponse({
                'success': False, 
                'error': 'Missing required fields: amount, job_id, user_email'
            }, status=400)
        
        # Generate unique transaction ID
        transaction_id = f"TXN_{uuid.uuid4().hex[:8].upper()}"
        
        # Create order with Razorpay
        order_data = {
            'amount': int(amount),  # Razorpay expects integer
            'currency': currency,
            'receipt': f'job_{job_id}_{payment_type}',
            'notes': {
                'job_id': job_id,
                'user_email': user_email,
                'payment_type': payment_type,
                'transaction_id': transaction_id
            }
        }
        
        order = client.order.create(data=order_data)
        
        # Create transaction record in database
        transaction = PaymentTransaction.objects.create(
            transaction_id=transaction_id,
            razorpay_order_id=order['id'],
            user_email=user_email,
            job_id=job_id,
            amount=Decimal(str(amount / 100)),  # Convert from paise to rupees
            payment_type=payment_type,
            currency=currency,
            status='pending',
            metadata=order_data['notes']
        )
        
        return JsonResponse({
            'success': True,
            'order': order,
            'transaction_id': transaction_id
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Order creation failed: {str(e)}'
        }, status=400)

@csrf_exempt
def verify_razorpay_payment(request):
    """Verify Razorpay payment signature and update transaction"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)

    transaction = None  # Always define this at top!
    try:
        data = json.loads(request.body)
        payment_id = data.get('payment_id')
        order_id = data.get('order_id')
        signature = data.get('signature')
        transaction_id = data.get('transaction_id')

        if not all([payment_id, order_id, signature]):
            return JsonResponse({
                'success': False,
                'error': 'Missing payment verification data'
            }, status=400)

        # Verify signature
        body = order_id + "|" + payment_id
        expected_signature = hmac.new(
            RAZORPAY_KEY_SECRET.encode('utf-8'),
            body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if expected_signature != signature:
            return JsonResponse({
                'success': False,
                'error': 'Invalid payment signature'
            }, status=400)

        # Get transaction from database
        try:
            if transaction_id:
                transaction = PaymentTransaction.objects.get(transaction_id=transaction_id)
            else:
                transaction = PaymentTransaction.objects.get(razorpay_order_id=order_id)
        except PaymentTransaction.DoesNotExist:
            try:
                transaction = PaymentTransaction.objects.get(razorpay_order_id=order_id)
            except PaymentTransaction.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': f'Transaction not found for order_id: {order_id}'
                }, status=404)

        # Update transaction with payment details
        transaction.razorpay_payment_id = payment_id
        transaction.razorpay_signature = signature
        transaction.status = 'completed'
        transaction.completed_at = timezone.now()
        transaction.save()

        # Mark job as paid and set status to pending_accept, as per your update
        try:
            if transaction.payment_type in ['owner_booking', 'advance']:
                job = OwnerJobPost.objects.get(id=transaction.job_id)
                job.is_paid = True  # prevent double booking
                job.status = 'pending_accept'  # NEW: waiting for worker acceptance
                job.save()
            elif transaction.payment_type in ['worker_booking', 'full']:
                job = WorkerAvailability.objects.get(id=transaction.job_id)
                job.is_paid = True
                job.status = 'pending_accept'  # NEW: waiting for owner acceptance
                job.save()
        except (OwnerJobPost.DoesNotExist, WorkerAvailability.DoesNotExist):
            pass  # Job might not exist, but payment is still valid

        return JsonResponse({
            'success': True,
            'message': 'Payment verified successfully',
            'transaction_id': transaction.transaction_id
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Payment verification failed: {str(e)}'
        }, status=400)

@csrf_exempt
def handle_payment_failure(request):
    """Handle failed/cancelled payments"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        order_id = data.get('order_id')
        reason = data.get('reason', 'Payment cancelled by user')
        
        if not order_id:
            return JsonResponse({
                'success': False,
                'error': 'Order ID required'
            }, status=400)
        
        # Find transaction and mark as failed
        try:
            transaction = PaymentTransaction.objects.get(razorpay_order_id=order_id)
            transaction.status = 'failed'
            transaction.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Payment marked as failed'
            })
        except PaymentTransaction.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Transaction not found'
            }, status=404)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error handling payment failure: {str(e)}'
        }, status=500)

@csrf_exempt
def get_payment_status(request, transaction_id):
    """Get payment status for a transaction"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        transaction = PaymentTransaction.objects.get(transaction_id=transaction_id)
        
        return JsonResponse({
            'success': True,
            'transaction': {
                'transaction_id': transaction.transaction_id,
                'status': transaction.status,
                'amount': float(transaction.amount),
                'currency': transaction.currency,
                'payment_type': transaction.payment_type,
                'created_at': transaction.created_at.isoformat(),
                'completed_at': transaction.completed_at.isoformat() if transaction.completed_at else None,
                'razorpay_payment_id': transaction.razorpay_payment_id,
                'razorpay_order_id': transaction.razorpay_order_id,
            }
        })
        
    except PaymentTransaction.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Transaction not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error fetching payment status: {str(e)}'
        }, status=500)

@csrf_exempt
def get_payment_history(request):
    """Get payment history for a user"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        user_email = request.GET.get('email')
        if not user_email:
            return JsonResponse({
                'success': False,
                'error': 'Email parameter required'
            }, status=400)
        
        transactions = PaymentTransaction.objects.filter(
            user_email=user_email
        ).order_by('-created_at')
        
        payment_list = []
        for transaction in transactions:
            payment_list.append({
                'transaction_id': transaction.transaction_id,
                'status': transaction.status,
                'amount': float(transaction.amount),
                'currency': transaction.currency,
                'payment_type': transaction.payment_type,
                'job_id': transaction.job_id,
                'created_at': transaction.created_at.isoformat(),
                'completed_at': transaction.completed_at.isoformat() if transaction.completed_at else None,
            })
        
        return JsonResponse({
            'success': True,
            'payments': payment_list,
            'count': len(payment_list)
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error fetching payment history: {str(e)}'
        }, status=500)

@csrf_exempt
def process_refund(request):
    """Process refund for a payment"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        payment_id = data.get('payment_id')
        amount = data.get('amount')  # Amount in paise
        reason = data.get('reason', 'Refund requested')
        
        if not payment_id or not amount:
            return JsonResponse({
                'success': False,
                'error': 'Payment ID and amount required'
            }, status=400)
        
        # Get transaction
        try:
            transaction = PaymentTransaction.objects.get(razorpay_payment_id=payment_id)
        except PaymentTransaction.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Transaction not found'
            }, status=404)
        
        # Create refund with Razorpay
        refund_data = {
            'amount': int(amount),
            'notes': {
                'reason': reason,
                'transaction_id': transaction.transaction_id
            }
        }
        
        refund = client.payment.refund(payment_id, refund_data)
        
        # Create refund record
        refund_record = PaymentRefund.objects.create(
            transaction=transaction,
            refund_amount=Decimal(str(amount / 100)),
            reason=reason,
            razorpay_refund_id=refund['id'],
            status='processed'
        )
        
        # Update transaction status
        transaction.status = 'refunded'
        transaction.save()
        
        return JsonResponse({
            'success': True,
            'refund_id': refund['id'],
            'message': 'Refund processed successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Refund processing failed: {str(e)}'
        }, status=500)

@csrf_exempt
def request_payout(request):
    """Request payout for workers"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        worker_email = data.get('worker_email')
        worker_upi = data.get('worker_upi')
        amount = data.get('amount')
        job_id = data.get('job_id')
        
        if not all([worker_email, worker_upi, amount, job_id]):
            return JsonResponse({
                'success': False,
                'error': 'Missing required fields'
            }, status=400)
        
        # Create payout request
        payout = PayoutRequest.objects.create(
            worker_email=worker_email,
            worker_upi=worker_upi,
            amount=Decimal(str(amount)),
            job_id=job_id,
            status='pending'
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Payout request submitted. You will receive payment within 24 hours.',
            'payout_id': payout.id
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Payout request failed: {str(e)}'
        }, status=500)

# EXISTING VIEWS (keeping all your existing code)
VALID_ROLES = ['worker', 'owner']

def json_error(message, status=400):
    return JsonResponse({'success': False, 'message': message}, status=status)

def admin_page(request):
    """Renders the HTML dashboard with paginated users and OTPs (20 per page).
    Query params:
    - u: users page number  
    - o: otps page number
    """
    users_qs = UserAccount.objects.order_by('-created_at')
    otps_qs = EmailOTP.objects.order_by('-created_at')
    
    users_page = Paginator(users_qs, 20).get_page(request.GET.get('u', 1))
    otps_page = Paginator(otps_qs, 20).get_page(request.GET.get('o', 1))
    
    # Add posts count to each user
    for user in users_page.object_list:
        owner_posts_count = OwnerJobPost.objects.filter(posted_by=user).count()
        worker_posts_count = WorkerAvailability.objects.filter(posted_by=user).count()
        user.posts_count = owner_posts_count + worker_posts_count
        
    return render(request, 'id.html', {
        'users_page': users_page,
        'otps_page': otps_page,
    })

@csrf_exempt
def get_user_posts(request):
    """GET /api/auth/admin/user-posts?email=...
    - success, posts...
    Returns all posts (both owner jobs and worker availability) for a user.
    """
    if request.method != 'GET':
        return JsonResponse({'success': False, 'message': 'GET method required'})
    
    email = request.GET.get('email')
    if not email:
        return JsonResponse({'success': False, 'message': 'Email parameter required'})
    
    try:
        user = UserAccount.objects.get(email=email)
    except UserAccount.DoesNotExist:
        return JsonResponse({'success': False, 'message': f'User not found: {email}'})
    
    try:
        posts = []
        
        # Get owner job posts
        owner_posts = OwnerJobPost.objects.filter(posted_by=user).order_by('-created_at')
        for post in owner_posts:
            posts.append({
                'id': post.id,
                'type': 'work',
                'title': post.title,
                'price': str(post.price),
                'district': post.district,
                'address': post.address,
                'description': post.description,
                'created_at': post.created_at.isoformat(),
                'is_completed': post.is_completed,
                'is_paid': post.is_paid,
            })
        
        # Get worker availability posts
        worker_posts = WorkerAvailability.objects.filter(posted_by=user).order_by('-created_at')
        for post in worker_posts:
            posts.append({
                'id': post.id,
                'type': 'worker',
                'title': post.job_type,
                'price': str(post.price),
                'district': post.district,
                'place': post.place,
                'time_info': post.time_info,
                'description': post.description,
                'created_at': post.created_at.isoformat(),
                'is_paid': post.is_paid,
            })
        
        # Sort by creation date (newest first)
        posts.sort(key=lambda x: x['created_at'], reverse=True)
        
        return JsonResponse({
            'success': True,
            'posts': posts,
            'count': len(posts)
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error fetching posts: {str(e)}'})

@csrf_exempt
def delete_work_post(request, post_id):
    """DELETE /api/auth/work/<post_id>/
    - success
    Delete a specific work post
    """
    if request.method != 'DELETE':
        return JsonResponse({'success': False, 'message': 'DELETE method required'}, status=405)
    
    try:
        post = OwnerJobPost.objects.get(id=post_id)
        post.delete()
        return JsonResponse({'success': True, 'message': 'Post deleted successfully'})
    except OwnerJobPost.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Work post not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Delete error: {str(e)}'}, status=500)

@csrf_exempt
def delete_worker_post(request, post_id):
    """DELETE /api/auth/workers/<post_id>/
    - success
    Delete a specific worker post
    """
    if request.method != 'DELETE':
        return JsonResponse({'success': False, 'message': 'DELETE method required'}, status=405)
    
    try:
        post = WorkerAvailability.objects.get(id=post_id)
        post.delete()
        return JsonResponse({'success': True, 'message': 'Post deleted successfully'})
    except WorkerAvailability.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Worker post not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Delete error: {str(e)}'}, status=500)

@csrf_exempt
def update_work_post(request, post_id):
    """PUT /api/auth/work/<post_id>/update/
    - success, post
    Update a specific work post
    """
    if request.method != 'PUT':
        return JsonResponse({'success': False, 'message': 'PUT method required'}, status=405)
    
    try:
        post = OwnerJobPost.objects.get(id=post_id)
        data = json.loads(request.body.decode('utf-8'))
        
        # Update fields
        if 'title' in data:
            post.title = data['title']
        if 'price' in data:
            post.price = Decimal(str(data['price']))
        if 'district' in data:
            post.district = data['district']
        if 'address' in data:
            post.address = data['address']
        if 'description' in data:
            post.description = data['description']
        
        post.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Post updated successfully',
            'post': {
                'id': post.id,
                'title': post.title,
                'price': str(post.price),
                'district': post.district,
                'address': post.address,
                'description': post.description,
                'type': 'work',
                'is_paid': post.is_paid,
            }
        })
    except OwnerJobPost.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Work post not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Update error: {str(e)}'}, status=500)

@csrf_exempt
def update_worker_post(request, post_id):
    """PUT /api/auth/workers/<post_id>/update/
    - success, post
    Update a specific worker post
    """
    if request.method != 'PUT':
        return JsonResponse({'success': False, 'message': 'PUT method required'}, status=405)
    
    try:
        post = WorkerAvailability.objects.get(id=post_id)
        data = json.loads(request.body.decode('utf-8'))
        
        # Update fields
        if 'job_type' in data:
            post.job_type = data['job_type']
        if 'price' in data:
            post.price = Decimal(str(data['price']))
        if 'district' in data:
            post.district = data['district']
        if 'place' in data:
            post.place = data['place']
        if 'time_info' in data:
            post.time_info = data['time_info']
        if 'description' in data:
            post.description = data['description']
            
        post.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Post updated successfully',
            'post': {
                'id': post.id,
                'job_type': post.job_type,
                'price': str(post.price),
                'district': post.district,
                'place': post.place,
                'time_info': post.time_info,
                'description': post.description,
                'type': 'worker',
                'is_paid': post.is_paid,
            }
        })
    except WorkerAvailability.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Worker post not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Update error: {str(e)}'}, status=500)

@csrf_exempt
def signup_view(request):
    if request.method != 'POST':
        return json_error('POST required', 405)
    
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        password = (payload.get('password') or '')
        
        if not email or not password:
            return json_error('Email and password required')
        
        if UserAccount.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'message': 'Email already created, login with password'})
        
        ua = UserAccount.objects.create(
            email=email,
            password_hash=make_password(password),
            password_plain=password,  # DEV ONLY
        )
        
        return JsonResponse({'success': True, 'message': 'Account created', 'email': ua.email})
        
    except Exception as e:
        return json_error(f'Error: {e}')

@csrf_exempt  
def login_view(request):
    if request.method != 'POST':
        return json_error('POST required', 405)
    
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        password = (payload.get('password') or '')
        
        if not email or not password:
            return json_error('Email and password required')
        
        try:
            ua = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return json_error('Invalid credentials', 401)
        
        if not check_password(password, ua.password_hash):
            return json_error('Invalid credentials', 401)
        
        return JsonResponse({'success': True, 'message': 'Login successful', 'email': ua.email})
        
    except Exception as e:
        return json_error(f'Error: {e}')

@csrf_exempt
def forgot_password_view(request):
    if request.method != 'POST':
        return json_error('POST required', 405)
    
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        
        if not email:
            return json_error('Email required')
        
        code = generate_otp_5()
        EmailOTP.objects.create(email=email, code=code, expires_at=expiry_in(10))
        
        subject = 'AVAILABLE OTP - Password Reset'
        msg = f'Your 5-digit OTP is {code} (expires in 10 minutes).'
        send_mail(subject, msg, None, [email], fail_silently=False)
        
        return JsonResponse({'success': True, 'message': f'OTP sent to {email}'})
        
    except Exception as e:
        return json_error(f'Error: {e}')

@csrf_exempt
def verify_otp_view(request):
    if request.method != 'POST':
        return json_error('POST required', 405)
    
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        otp = (payload.get('otp') or '').strip()
        new_password = (payload.get('new_password') or '')
        
        if not email or not otp or not new_password:
            return json_error('Email, OTP, and new_password required')
        
        rec = EmailOTP.objects.filter(email=email, code=otp).order_by('-created_at').first()
        if not rec:
            return json_error('Invalid OTP', 400)
        
        if rec.is_verified:
            return json_error('OTP already used', 400)
        
        if timezone.now() > rec.expires_at:
            return json_error('OTP expired', 400)
        
        try:
            ua = UserAccount.objects.get(email=email)
        except UserAccount.DoesNotExist:
            return json_error('Account not found', 404)
        
        ua.password_hash = make_password(new_password)
        ua.password_plain = new_password  # DEV ONLY
        ua.save(update_fields=['password_hash', 'password_plain'])
        
        rec.is_verified = True
        rec.save(update_fields=['is_verified'])
        
        return JsonResponse({'success': True, 'message': 'Password updated'})
        
    except Exception as e:
        return json_error(f'Error: {e}')

@csrf_exempt
def delete_user_view(request):
    if request.method != 'POST':
        return json_error('POST required', 405)
    
    try:
        payload = json.loads(request.body.decode('utf-8'))
        email = (payload.get('email') or '').strip().lower()
        
        if not email:
            return json_error('Email required')
        
        deleted, _ = UserAccount.objects.filter(email=email).delete()
        if deleted == 0:
            return json_error('User not found', 404)
        
        return JsonResponse({'success': True, 'message': 'User deleted', 'email': email})
        
    except Exception as e:
        return json_error(f'Error: {e}')

@csrf_exempt
def delete_otp_view(request):
    if request.method != 'POST':
        return json_error('POST required', 405)
    
    try:
        payload = json.loads(request.body.decode('utf-8'))
        oid = payload.get('id')
        
        if not oid:
            return json_error('OTP id required')
        
        deleted, _ = EmailOTP.objects.filter(id=oid).delete()
        if deleted == 0:
            return json_error('OTP not found', 404)
        
        return JsonResponse({'success': True, 'message': 'OTP deleted', 'id': oid})
        
    except Exception as e:
        return json_error(f'Error: {e}')

def profile_to_dict(u: UserAccount, request):
    """Serializes profile with absolute image URL and computed stats."""
    img_url = ""
    if u.profile_image:
        img_url = request.build_absolute_uri(u.profile_image.url)
    
    jobs_posted = OwnerJobPost.objects.filter(posted_by=u).count()
    jobs_completed = OwnerJobPost.objects.filter(posted_by=u, is_completed=True).count()
    
    # Calculate real earnings from successful payments received for their job posts
    earnings_transactions = PaymentTransaction.objects.filter(
        job_id__in=OwnerJobPost.objects.filter(posted_by=u).values_list('id', flat=True),
        status='completed'
    )
    total_earnings = earnings_transactions.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    
    # Calculate real spends (money paid by this user for others' job posts)
    spend_transactions = PaymentTransaction.objects.filter(
        user_email=u.email,
        status='completed'
    )
    total_spends = spend_transactions.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    
    # Calculate available balance
    available_balance = total_earnings - total_spends
    
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
        'earnings': float(total_earnings),
        'spends': float(total_spends),
        'available_balance': float(available_balance),
    }

@csrf_exempt
def profile_view(request):
    """GET /api/auth/profile?email=...
    - success, profile...
    
    POST /api/auth/profile
    - success, profile...
    POST body JSON: {email: required, name, bio: <100, role: in ['worker','owner'], phone_number: required, tag: optional, profile_image_base64}
    """
    if request.method == 'GET':
        email = (request.GET.get('email') or '').strip().lower()
        if not email:
            return json_error('Email required')
        
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
                    'spends': 0.0,
                    'available_balance': 0.0,
                }
            })
        
        return JsonResponse({'success': True, 'profile': profile_to_dict(u, request)})
    
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
                return json_error('Email required')
            
            try:
                u = UserAccount.objects.get(email=email)
            except UserAccount.DoesNotExist:
                return json_error('Account not found', 404)
            
            if len(bio) > 100:
                return json_error('Bio must be â‰¤100 chars')
            
            if not phone_number:
                return json_error('Phone number required')
            
            # Basic phone validation
            compact = phone_number.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            if not compact.isdigit():
                return json_error('Invalid phone number')
            
            if role and role not in VALID_ROLES:
                return json_error('Invalid role')
            
            # Update fields
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
                    return json_error('Invalid image data')
            
            u.save()
            
            return JsonResponse({'success': True, 'profile': profile_to_dict(u, request)})
            
        except Exception as e:
            return json_error(f'Error: {e}')
    
    return json_error('Method not allowed', 405)

def paginate(request, qs, page_size=20):
    page = int(request.GET.get('page', 1) or 1)
    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(page)
    return page_obj, paginator

def serialize_user_brief(u: UserAccount, request):
    img_url = ""
    if u.profile_image:
        img_url = request.build_absolute_uri(u.profile_image.url)
    
    return {
        'email': u.email,
        'name': u.name,
        'bio': u.bio,
        'tag': getattr(u, 'tag', ''),
        'profile_image_url': img_url,
    }

def serialize_owner_job(j: OwnerJobPost, request):
    return {
        'id': j.id,
        'title': j.title,
        'price': float(j.price),
        'district': j.district,
        'address': j.address,
        'description': j.description,
        'created_at': j.created_at.isoformat(),
        'is_completed': j.is_completed,
        'is_paid': j.is_paid,
        'posted_by': serialize_user_brief(j.posted_by, request),
    }

def serialize_worker_avail(w: WorkerAvailability, request):
    return {
        'id': w.id,
        'job_type': w.job_type,
        'price': float(w.price),
        'district': w.district,
        'place': w.place,
        'time_info': w.time_info,
        'description': w.description,
        'created_at': w.created_at.isoformat(),
        'is_paid': w.is_paid,
        'posted_by': serialize_user_brief(w.posted_by, request),
    }

@csrf_exempt
def work_view(request):
    if request.method == 'GET':
        jobs = OwnerJobPost.objects.filter(is_paid=False, status='available').order_by('-created_at')
        resp = []
        for job in jobs:
            resp.append({
                'id': job.id,
                'title': job.title,
                'posted_by': {
                    'email': job.posted_by.email,
                    'name': job.posted_by.name,
                    'tag': job.posted_by.tag,
                    'profile_image_url': job.posted_by.profile_image.url if job.posted_by.profile_image else '',
                },
                'price': float(job.price),
                'district': job.district,
                'address': job.address,
                'description': job.description,
                'created_at': job.created_at.isoformat(),
                'is_paid': job.is_paid,
                'status': job.status,
            })
        return JsonResponse({'success': True, 'results': resp})

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_email = data.get('email')
            user = UserAccount.objects.get(email=user_email)
            job = OwnerJobPost.objects.create(
                posted_by=user,
                title=data.get('title', ''),
                price=float(data.get('price', 0)),
                district=data.get('district', ''),
                address=data.get('address', ''),
                description=data.get('description', ''),
                is_completed=False,
                is_paid=False,
                status='available'
            )
            return JsonResponse({'success': True, 'job_id': job.id})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

    else:
        return JsonResponse({'success': False, 'error': 'GET or POST method required'}, status=405)
    

@csrf_exempt
def workers_view(request):
    if request.method == 'GET':
        workers = WorkerAvailability.objects.filter(is_paid=False, status='available').order_by('-created_at')
        resp = []
        for worker in workers:
            resp.append({
                'id': worker.id,
                'job_type': worker.job_type,
                'posted_by': {
                    'email': worker.posted_by.email,
                    'name': worker.posted_by.name,
                    'tag': worker.posted_by.tag,
                    'profile_image_url': worker.posted_by.profile_image.url if worker.posted_by.profile_image else '',
                },
                'price': float(worker.price),
                'district': worker.district,
                'place': worker.place,
                'time_info': worker.time_info,
                'description': worker.description,
                'created_at': worker.created_at.isoformat(),
                'is_paid': worker.is_paid,
                'status': worker.status,
            })
        return JsonResponse({'success': True, 'results': resp})

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_email = data.get('email')
            user = UserAccount.objects.get(email=user_email)
            worker = WorkerAvailability.objects.create(
                posted_by=user,
                job_type=data.get('job_type', ''),
                price=float(data.get('price', 0)),
                district=data.get('district', ''),
                place=data.get('place', ''),
                time_info=data.get('time_info', ''),
                description=data.get('description', ''),
                is_paid=False,
                status='available'
            )
            return JsonResponse({'success': True, 'worker_id': worker.id})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)

    else:
        return JsonResponse({'success': False, 'error': 'GET or POST method required'}, status=405)

@csrf_exempt
def payment_dashboard(request):
    """GET /api/auth/payment/dashboard/ - Get all payment transactions with booking details"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        # Get all transactions with related job details
        transactions = PaymentTransaction.objects.select_related().all().order_by('-created_at')
        
        payments = []
        for transaction in transactions:
            try:
                # Get job details - try both OwnerJobPost and WorkerAvailability
                job = None
                job_owner = None
                job_title = "Unknown Job"
                
                # First try OwnerJobPost
                try:
                    job = OwnerJobPost.objects.get(id=transaction.job_id)
                    job_owner = job.posted_by
                    job_title = job.title
                except OwnerJobPost.DoesNotExist:
                    # Try WorkerAvailability
                    try:
                        job = WorkerAvailability.objects.get(id=transaction.job_id)
                        job_owner = job.posted_by
                        job_title = job.job_type
                    except WorkerAvailability.DoesNotExist:
                        # Job not found in either table
                        job_owner = None
                        job_title = f"Job ID: {transaction.job_id} (Not Found)"
                
                # Get user details
                try:
                    user_account = UserAccount.objects.get(email=transaction.user_email)
                    booker_name = user_account.name if user_account.name else transaction.user_email.split('@')[0]
                except UserAccount.DoesNotExist:
                    booker_name = transaction.user_email.split('@')[0]
                
                # Get job owner details
                if job_owner:
                    job_owner_name = job_owner.name if job_owner.name else job_owner.email.split('@')[0]
                    job_owner_email = job_owner.email
                else:
                    job_owner_name = "Unknown"
                    job_owner_email = "Unknown"
                
                # Determine booking relationship
                is_owner_booking = job_owner and job_owner.email == transaction.user_email
                
                payments.append({
                    'transaction_id': transaction.transaction_id,
                    'user_email': transaction.user_email,
                    'amount': float(transaction.amount),
                    'payment_type': transaction.payment_type,
                    'status': transaction.status,
                    'job_id': transaction.job_id,
                    'job_title': job_title,
                    'job_owner_email': job_owner_email,
                    'job_owner_name': job_owner_name,
                    'booker_name': booker_name,
                    'is_owner_booking': is_owner_booking,
                    'booking_relationship': f"{'Owner' if is_owner_booking else 'Worker'} â†’ {'Worker' if is_owner_booking else 'Owner'}",
                    'razorpay_payment_id': transaction.razorpay_payment_id,
                    'razorpay_order_id': transaction.razorpay_order_id,
                    'created_at': transaction.created_at.isoformat(),
                    'completed_at': transaction.completed_at.isoformat() if transaction.completed_at else None,
                })
            except Exception as e:
                # Handle any other errors
                print(f"Error processing transaction {transaction.transaction_id}: {e}")
                payments.append({
                    'transaction_id': transaction.transaction_id,
                    'user_email': transaction.user_email,
                    'amount': float(transaction.amount),
                    'payment_type': transaction.payment_type,
                    'status': transaction.status,
                    'job_id': transaction.job_id,
                    'job_title': f"Error: {str(e)}",
                    'job_owner_email': 'Unknown',
                    'job_owner_name': 'Unknown',
                    'booker_name': transaction.user_email.split('@')[0],
                    'is_owner_booking': False,
                    'booking_relationship': 'Unknown',
                    'razorpay_payment_id': transaction.razorpay_payment_id,
                    'razorpay_order_id': transaction.razorpay_order_id,
                    'created_at': transaction.created_at.isoformat(),
                    'completed_at': transaction.completed_at.isoformat() if transaction.completed_at else None,
                })
        
        # Calculate stats
        total_transactions = len(payments)
        total_amount = sum(p['amount'] for p in payments)
        completed_payments = len([p for p in payments if p['status'] == 'completed'])
        pending_payments = len([p for p in payments if p['status'] == 'pending'])
        failed_payments = len([p for p in payments if p['status'] == 'failed'])
        
        stats = {
            'total_transactions': total_transactions,
            'total_amount': total_amount,
            'completed_payments': completed_payments,
            'pending_payments': pending_payments,
            'failed_payments': failed_payments,
        }
        
        return JsonResponse({
            'success': True,
            'payments': payments,
            'stats': stats
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error loading payment data: {str(e)}'
        }, status=500)

def payment_dashboard_view(request):
    """Render payment dashboard HTML page"""
    return render(request, 'id/payment.html')

@csrf_exempt
def get_my_jobs_booked(request):
    """GET /api/auth/my-jobs-booked/?email=... - Get jobs booked by current user"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        user_email = request.GET.get('email')
        if not user_email:
            return JsonResponse({
                'success': False,
                'error': 'Email parameter required'
            }, status=400)
        
        # Get ALL transactions for this user (both as booker and as job owner)
        transactions = PaymentTransaction.objects.filter(
            user_email=user_email,
            status='completed'
        ).order_by('-created_at')
        
        bookings = []
        for transaction in transactions:
            try:
                # Get job details - try both OwnerJobPost and WorkerAvailability
                job = None
                job_owner = None
                job_title = "Unknown Job"
                
                # First try OwnerJobPost
                try:
                    job = OwnerJobPost.objects.get(id=transaction.job_id)
                    job_owner = job.posted_by
                    job_title = job.title
                except OwnerJobPost.DoesNotExist:
                    # Try WorkerAvailability
                    try:
                        job = WorkerAvailability.objects.get(id=transaction.job_id)
                        job_owner = job.posted_by
                        job_title = job.job_type
                    except WorkerAvailability.DoesNotExist:
                        # Job not found in either table
                        job_owner = None
                        job_title = f"Job ID: {transaction.job_id} (Not Found)"
                
                # Get user details
                try:
                    user_account = UserAccount.objects.get(email=transaction.user_email)
                    booker_name = user_account.name if user_account.name else transaction.user_email.split('@')[0]
                except UserAccount.DoesNotExist:
                    booker_name = transaction.user_email.split('@')[0]
                
                # Get job owner details
                if job_owner:
                    job_owner_name = job_owner.name if job_owner.name else job_owner.email.split('@')[0]
                    job_owner_email = job_owner.email
                else:
                    job_owner_name = "Unknown"
                    job_owner_email = "Unknown"
                
                # Determine if user is the booker or job owner
                is_job_owner = job_owner and job_owner.email == user_email
                is_accepted = job.is_paid if job else False
                
                if is_job_owner:
                    # User is the job owner - show who booked this job
                    bookings.append({
                        'id': transaction.id,
                        'job_title': job_title,
                        'booker_name': booker_name,
                        'booker_email': transaction.user_email,
                        'job_owner_name': job_owner_name,
                        'job_owner_email': job_owner_email,
                        'advance_amount': float(transaction.amount),
                        'remaining_amount': float(job.price - transaction.amount) if job else 0.0,
                        'status': 'accepted' if is_accepted else 'pending',
                        'transaction_type': 'owner_hiring',
                        'created_at': transaction.created_at.isoformat(),
                    })
                else:
                    # User is the booker - show jobs they booked
                    bookings.append({
                        'id': transaction.id,
                        'job_title': job_title,
                        'booker_name': booker_name,
                        'booker_email': transaction.user_email,
                        'job_owner_name': job_owner_name,
                        'job_owner_email': job_owner_email,
                        'advance_amount': float(transaction.amount),
                        'remaining_amount': float(job.price - transaction.amount) if job else 0.0,
                        'status': 'accepted' if is_accepted else 'pending',
                        'transaction_type': 'worker_booking',
                        'created_at': transaction.created_at.isoformat(),
                    })
            except Exception as e:
                print(f"Error processing transaction {transaction.transaction_id}: {e}")
                continue
        
        return JsonResponse({
            'success': True,
            'bookings': bookings
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error loading bookings: {str(e)}'
        }, status=500)

@csrf_exempt
def get_earnings_data(request):
    """GET /api/auth/earnings/?email=... - Get user earnings and spends"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        user_email = request.GET.get('email')
        if not user_email:
            return JsonResponse({
                'success': False,
                'error': 'Email parameter required'
            }, status=400)
        
        # Calculate earnings (money received)
        earnings_transactions = PaymentTransaction.objects.filter(
            job_id__in=OwnerJobPost.objects.filter(posted_by__email=user_email).values_list('id', flat=True),
            status='completed'
        )
        total_earnings = earnings_transactions.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Calculate spends (money paid)
        spend_transactions = PaymentTransaction.objects.filter(
            user_email=user_email,
            status='completed'
        )
        total_spends = spend_transactions.aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Calculate available balance
        available_balance = total_earnings - total_spends
        
        return JsonResponse({
            'success': True,
            'earnings': {
                'total_earnings': float(total_earnings),
                'total_spends': float(total_spends),
                'available_balance': float(available_balance),
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error loading earnings: {str(e)}'
        }, status=500)

@csrf_exempt
def accept_booking(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    try:
        data = json.loads(request.body)
        booking_id = data.get('booking_id')
        accepted = data.get('accepted', False)  # if you pass accepted: true/false from frontend

        if not booking_id:
            return JsonResponse({'success': False, 'error': 'Booking ID required'}, status=400)

        try:
            transaction = PaymentTransaction.objects.get(transactionid=booking_id)
        except PaymentTransaction.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Booking not found'}, status=404)

        # Example: mark as accepted, paid, etc. - adjust as per your logic
        transaction.status = 'accepted' if accepted else 'rejected'
        transaction.save()

        # Optionally update job/worker status too
        try:
            if transaction.payment_type in ['owner_booking', 'advance']:
                job = OwnerJobPost.objects.get(id=transaction.job_id)
                job.status = 'accepted' if accepted else 'rejected'
                job.save()
            elif transaction.payment_type in ['worker_booking', 'full']:
                worker = WorkerAvailability.objects.get(id=transaction.job_id)
                worker.status = 'accepted' if accepted else 'rejected'
                worker.save()
        except Exception as job_err:
            pass  # If job/work is missing, still allow booking update

        return JsonResponse({'success': True, 'message': 'Booking updated'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Booking acceptance failed: {str(e)}'}, status=400)

@csrf_exempt
def get_accepted_orders(request):
    """GET /api/auth/accepted-orders/?email=... - Get accepted orders for job owners"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        user_email = request.GET.get('email')
        if not user_email:
            return JsonResponse({
                'success': False,
                'error': 'Email parameter required'
            }, status=400)
        
        # Get accepted transactions where user is the job poster
        accepted_transactions = PaymentTransaction.objects.filter(
            job_id__in=OwnerJobPost.objects.filter(posted_by__email=user_email).values_list('id', flat=True),
            status='completed'
        ).filter(
            job_id__in=OwnerJobPost.objects.filter(is_paid=True).values_list('id', flat=True)
        ).order_by('-created_at')
        
        accepted_orders = []
        for transaction in accepted_transactions:
            try:
                # Get job details
                job = OwnerJobPost.objects.get(id=transaction.job_id)
                if job.is_paid:  # Only show accepted jobs
                    # Get user details
                    try:
                        user_account = UserAccount.objects.get(email=transaction.user_email)
                        booker_name = user_account.name if user_account.name else transaction.user_email.split('@')[0]
                    except UserAccount.DoesNotExist:
                        booker_name = transaction.user_email.split('@')[0]
                    
                    # Get job owner details
                    job_owner_name = job.posted_by.name if job.posted_by.name else job.posted_by.email.split('@')[0]
                    
                    accepted_orders.append({
                        'id': transaction.id,
                        'job_title': job.title,
                        'booker_name': booker_name,
                        'booker_email': transaction.user_email,
                        'job_owner_name': job_owner_name,
                        'job_owner_email': job.posted_by.email,
                        'advance_amount': float(transaction.amount),
                        'remaining_amount': float(job.price - transaction.amount),
                        'status': 'accepted',
                        'transaction_type': 'owner_hiring',
                        'created_at': transaction.created_at.isoformat(),
                    })
            except OwnerJobPost.DoesNotExist:
                continue
        
        return JsonResponse({
            'success': True,
            'accepted_orders': accepted_orders
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error loading accepted orders: {str(e)}'
        }, status=500)

@csrf_exempt
def debug_transaction(request):
    """GET /api/auth/debug-transaction/?transaction_id=... - Debug specific transaction"""
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        transaction_id = request.GET.get('transaction_id')
        if not transaction_id:
            return JsonResponse({'success': False, 'error': 'Transaction ID required'}, status=400)
        
        # Get transaction
        try:
            transaction = PaymentTransaction.objects.get(transaction_id=transaction_id)
        except PaymentTransaction.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Transaction not found'}, status=404)
        
        # Try to find job
        job_info = {}
        try:
            job = OwnerJobPost.objects.get(id=transaction.job_id)
            job_info = {
                'found': True,
                'type': 'OwnerJobPost',
                'title': job.title,
                'owner_email': job.posted_by.email,
                'owner_name': job.posted_by.name,
            }
        except OwnerJobPost.DoesNotExist:
            try:
                job = WorkerAvailability.objects.get(id=transaction.job_id)
                job_info = {
                    'found': True,
                    'type': 'WorkerAvailability',
                    'title': job.job_type,
                    'owner_email': job.posted_by.email,
                    'owner_name': job.posted_by.name,
                }
            except WorkerAvailability.DoesNotExist:
                job_info = {
                    'found': False,
                    'error': 'Job not found in either table',
                }
        
        # Get user info
        try:
            user = UserAccount.objects.get(email=transaction.user_email)
            user_info = {
                'found': True,
                'name': user.name,
                'email': user.email,
            }
        except UserAccount.DoesNotExist:
            user_info = {
                'found': False,
                'error': 'User not found',
            }
        
        return JsonResponse({
            'success': True,
            'transaction': {
                'transaction_id': transaction.transaction_id,
                'user_email': transaction.user_email,
                'job_id': transaction.job_id,
                'amount': float(transaction.amount),
                'status': transaction.status,
                'payment_type': transaction.payment_type,
            },
            'job_info': job_info,
            'user_info': user_info,
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Debug error: {str(e)}'
        }, status=500)
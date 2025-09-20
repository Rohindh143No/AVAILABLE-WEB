from django.urls import path
from .views import (
    signup_view, login_view, forgot_password_view, verify_otp_view, delete_user_view, delete_otp_view,
    profile_view, work_view, workers_view, admin_page, get_user_posts,
    delete_work_post, delete_worker_post, update_work_post, update_worker_post,
    # Razorpay payment views
    create_razorpay_order, verify_razorpay_payment, get_payment_status,
    get_payment_history, process_refund, request_payout, payment_dashboard, payment_dashboard_view,
    handle_payment_failure, get_my_jobs_booked, get_earnings_data, accept_booking,
    get_accepted_orders,debug_transaction
)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import PaymentTransaction, OwnerJobPost
from django.db.models import Sum, Q
from decimal import Decimal


urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('forgot-password/', forgot_password_view, name='forgot-password'),
    path('verify-otp/', verify_otp_view, name='verify-otp'),
    path('delete-user/', delete_user_view, name='delete-user'),
    path('delete-otp/', delete_otp_view, name='delete-otp'),
    path('profile/', profile_view, name='profile'),
    path('work/', work_view, name='work'),
    path('workers/', workers_view, name='workers'),
    path('admin/', admin_page, name='admin-page'),
    path('admin/user-posts/', get_user_posts, name='get-user-posts'),
    
    # CRUD endpoints for posts
    path('work/<int:post_id>/', delete_work_post, name='delete-work-post'),
    path('workers/<int:post_id>/', delete_worker_post, name='delete-worker-post'),
    path('work/<int:post_id>/update/', update_work_post, name='update-work-post'),
    path('workers/<int:post_id>/update/', update_worker_post, name='update-worker-post'),
    
    # Razorpay Payment endpoints
    path('payment/create-order/', create_razorpay_order, name='create-razorpay-order'),
    path('payment/verify/', verify_razorpay_payment, name='verify-razorpay-payment'),
    path('payment/failed/', handle_payment_failure, name='handle-payment-failure'),
    path('payment/status/<str:transaction_id>/', get_payment_status, name='get-payment-status'),
    path('payment/history/', get_payment_history, name='get-payment-history'),
    path('payment/refund/', process_refund, name='process-refund'),
    path('payment/payout/', request_payout, name='request-payout'),
    
    # Payment dashboard
    path('payment/dashboard/', payment_dashboard, name='payment-dashboard-api'),
    path('payment-dashboard/', payment_dashboard_view, name='payment-dashboard'),
    
    # My Orders endpoints
    path('my-jobs-booked/', get_my_jobs_booked, name='my-jobs-booked'),
    path('earnings/', get_earnings_data, name='earnings'),
    path('accept-booking/', accept_booking, name='accept-booking'),
    path('accepted-orders/', get_accepted_orders, name='accepted-orders'),
    path('debug-transaction/', debug_transaction, name='debug-transaction'),
]

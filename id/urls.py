from django.urls import path
from .views import (
    signup_view, login_view, forgot_password_view, verify_otp_view,
    delete_user_view, delete_otp_view, profile_view,
    work_view, workers_view, admin_page, get_user_posts,
    delete_work_post, delete_worker_post, update_work_post, update_worker_post
)

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
    # Delete endpoints
    path('work/<int:post_id>/', delete_work_post, name='delete-work-post'),
    path('workers/<int:post_id>/', delete_worker_post, name='delete-worker-post'),
    # Update endpoints
    path('work/<int:post_id>/update/', update_work_post, name='update-work-post'),
    path('workers/<int:post_id>/update/', update_worker_post, name='update-worker-post'),
]

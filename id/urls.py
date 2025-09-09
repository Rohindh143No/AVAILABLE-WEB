# id/urls.py
from django.urls import path
from .views import (
    signup_view, login_view, forgot_password_view, verify_otp_view,
    delete_user_view, delete_otp_view, profile_view
)

urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('forgot-password/', forgot_password_view, name='forgot-password'),
    path('verify-otp/', verify_otp_view, name='verify-otp'),
    path('delete-user/', delete_user_view, name='delete-user'),
    path('delete-otp/', delete_otp_view, name='delete-otp'),
    path('profile/', profile_view, name='profile'),  # GET/POST
]

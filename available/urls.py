# available_backend/urls.py
from django.contrib import admin
from django.urls import path, include
from id.views import admin_page  # id.html dashboard

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('id.urls')),  # our API
    path('id/', admin_page, name='id-admin'),  # HTML page to display credentials and OTPs
]



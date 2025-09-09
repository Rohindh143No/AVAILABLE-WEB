# available_backend/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from id.views import admin_page

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('id.urls')),
    path('id/', admin_page, name='id-admin'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

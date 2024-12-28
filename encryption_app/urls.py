from django.urls import path, include
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.filesharing_home, name='filesharing_home'),
    path('encrypt/', views.encrypt_file, name='encrypt'),
    path('decrypt/', views.decrypt_file, name='decrypt'),
    path('files/', views.file_list, name='file_list'),
    path('share/<int:file_id>/', views.share_file, name='share_file'),
    path('download/<int:file_id>/', views.download_encrypted_file, name='download'),
    path('revoke-access/<int:file_id>/<int:user_id>/', views.revoke_access, name='revoke_access'),
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import start, enter, forma, profile, EventListCreateAPIView, EventDetailAPIView, event_detail, edit_event, delete_event, register, CustomLogoutView

urlpatterns = [
    path('', start, name='start'),
    path('enter/', enter, name='enter'),
    path('forma/', forma, name='forma'),
    path('profile/', profile, name='profile'),
    path('register/', register, name='register'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('event/<int:event_id>/edit/', edit_event, name='edit_event'),
    path('event/<int:event_id>/delete/', delete_event, name='delete_event'),
    path('event/<int:event_id>/', event_detail, name='event_detail'),
    path('api/events/', EventListCreateAPIView.as_view(), name='event-list-create'),
    path('api/events/<int:pk>/', EventDetailAPIView.as_view(), name='event-detail'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
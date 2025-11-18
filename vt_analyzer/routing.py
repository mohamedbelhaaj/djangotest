from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Route pour les notifications utilisateur
    re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),
    
    # Route pour le dashboard admin
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
]
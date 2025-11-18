import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import vt_analyzer.routing # Importe le bon fichier routing.py

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'virus_analyzer.settings')

# 'application' est ce que le serveur (comme Daphne ou Uvicorn) exécute.
application = ProtocolTypeRouter({
    
    # 1. Gestion des requêtes HTTP et HTTPS (votre API)
    "http": get_asgi_application(),
    
    # 2. Gestion des connexions WebSocket
    "websocket": AuthMiddlewareStack(
        URLRouter(
            # Utilise les routes définies dans votre application
            vt_analyzer.routing.websocket_urlpatterns
        )
    ),
})
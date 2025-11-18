from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Permission personnalisée pour autoriser uniquement les utilisateurs avec le rôle 'admin'.
    """
    def has_permission(self, request, view):
        # L'utilisateur doit être authentifié ET avoir le rôle 'admin'
        return request.user and request.user.is_authenticated and request.user.role == 'admin'

class IsAnalystUser(permissions.BasePermission):
    """
    Permission personnalisée pour autoriser uniquement les utilisateurs avec le rôle 'analyst'.
    """
    def has_permission(self, request, view):
        # L'utilisateur doit être authentifié ET avoir le rôle 'analyst'
        return request.user and request.user.is_authenticated and request.user.role == 'analyst'

class IsAdminOrOwner(permissions.BasePermission):
    """
    Autorise l'accès si l'utilisateur est admin,
    OU s'il est le 'analyst' (propriétaire) du rapport.
    """
    def has_object_permission(self, request, view, obj):
        # Si l'utilisateur est admin, toujours autoriser
        if request.user.role == 'admin':
            return True
        
        # Si c'est un rapport, vérifiez si l'utilisateur est l'analyste
        if hasattr(obj, 'analyst'):
            return obj.analyst == request.user
            
        # Si c'est une tâche, vérifiez si l'utilisateur est le créateur
        if hasattr(obj, 'created_by'):
             return obj.created_by == request.user

        return False
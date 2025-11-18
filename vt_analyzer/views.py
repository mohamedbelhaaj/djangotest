import logging
from django.conf import settings
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from pathlib import Path
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from datetime import datetime
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny


from .models import (
    User, ThreatReport, Task, MitigationAction, AWSConfiguration, Notification
)
from .serializers import (
    AnalysisInputSerializer,
    ThreatReportSerializer,
    TaskSerializer,
    MitigationActionSerializer,
    AWSConfigurationSerializer,
    NotificationSerializer
)
from .permissions import IsAdminUser, IsAnalystUser, IsAdminOrOwner
from .utils import (
    detect_input_type, vt_scan_file, vt_scan_url, vt_scan_ip, vt_scan_hash, vt_scan_domain,
    otx_scan_url, otx_scan_ip, otx_scan_hash, get_ip_info
)
from .aws_integration import AWSManager

# Pour la génération de PDF
# Vous devrez créer ces fichiers ou commenter les importations
# from .pdf_generator import generate_pdf_report 
# from .notifications import send_notification

# --- Début des fonctions factices pour les importations ---
# Commentez/Supprimez ceci lorsque vous créez les vrais fichiers
def generate_pdf_report(report):
    logger.warning("pdf_generator.py n'est pas implémenté.")
    return None
def send_notification(user_id, message):
    logger.warning("notifications.py n'est pas implémenté.")
    pass
# --- Fin des fonctions factices ---


logger = logging.getLogger(__name__)

# ===================================================================
# VUE DE L'UTILISATEUR (Remplace celle de dj-rest-auth)
# ===================================================================
# (Assurez-vous que 'UserDetailsSerializer' est configuré dans settings.py)
# Aucune vue n'est nécessaire ici si 'USER_DETAILS_SERIALIZER' est défini.

# ===================================================================
# VUE D'AUTHENTIFICATION ET UTILISATEURS
# ===================================================================
class CustomLoginView(APIView):
    """
    Custom login view without CSRF protection
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # Disable authentication for this view
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response(
                {'error': 'Please provide both username and password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': getattr(user, 'role', None),
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
            })
        else:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class UserListView(APIView):
    """
    API endpoint to list users based on role
    GET /api/users/ - Returns all users
    GET /api/users/?role=admin - Returns only admin users
    GET /api/users/?role=analyst - Returns only analyst users
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        role = request.GET.get('role')  # Get the role parameter from query string
        
        try:
            if role == 'admin':
                # Filter users with admin role
                users = User.objects.filter(role='admin')
            elif role == 'analyst':
                # Filter users with analyst role
                users = User.objects.filter(role='analyst')
            else:
                # Return all users if no role specified
                users = User.objects.all()
            
            user_data = [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': getattr(user, 'role', None),
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                }
                for user in users
            ]
            
            return Response(user_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return Response(
                {'error': f'Error fetching users: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ===================================================================
# VUE D'ANALYSE PERSONNALISÉE
# ===================================================================
class AnalyzeView(APIView):
    """
    Point de terminaison API personnalisé pour lancer une nouvelle analyse.
    Accessible uniquement aux Analystes.
    """
    permission_classes = [IsAnalystUser]

    def post(self, request, *args, **kwargs):
        # Étape 1 : Valider l'entrée
        serializer = AnalysisInputSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        input_value = validated_data.get('input_value', '').strip()
        uploaded_file = validated_data.get('file')
        engine_choice = validated_data.get('engine_choice', 'vt')

        # Étape 2 : Déterminer le type d'entrée
        if uploaded_file:
            input_type = 'file'
            input_value = uploaded_file.name
        elif input_value:
            input_type = detect_input_type(input_value)
            if input_type == 'unknown':
                return Response({'error': 'Type d\'indicateur inconnu.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
             return Response({'error': 'Entrée ou fichier requis.'}, status=status.HTTP_400_BAD_REQUEST)

        # Étape 3 : Créer l'objet Rapport initial
        report = ThreatReport.objects.create(
            analyst=request.user,
            input_type=input_type,
            input_value=input_value,
            file_name=uploaded_file.name if uploaded_file else None,
            engine_used=engine_choice,
            status='pending'
        )

        # Étape 4 : Lancer les scans (Logique déplacée depuis l'ancienne vue)
        # C'EST UNE OPÉRATION LONGUE !
        # Idéalement, ceci devrait être une tâche Celery (asynchrone).
        # Pour l'instant, nous le faisons de manière synchrone.
        vt_result, otx_result, ipinfo_result = None, None, None
        
        try:
            if engine_choice == 'vt':
                if input_type == 'file':
                    vt_result = vt_scan_file(uploaded_file)
                elif input_type == 'url':
                    vt_result = vt_scan_url(input_value) # Attention : peut nécessiter un délai
                elif input_type == 'ip':
                    vt_result = vt_scan_ip(input_value)
                elif input_type == 'hash':
                    vt_result = vt_scan_hash(input_value)
                elif input_type == 'domain':
                    vt_result = vt_scan_domain(input_value)
                
                if vt_result and 'error' in vt_result:
                    raise Exception(f"VirusTotal Error: {vt_result.get('error', 'Unknown')}")
                report.vt_data = vt_result

            elif engine_choice == 'otx':
                if input_type == 'ip':
                    otx_result = otx_scan_ip(input_value)
                elif input_type == 'url':
                    otx_result = otx_scan_url(input_value)
                elif input_type == 'hash':
                    otx_result = otx_scan_hash(input_value)
                
                if otx_result and 'error' in otx_result:
                    raise Exception(f"OTX Error: {otx_result.get('error', 'Unknown')}")
                report.otx_data = otx_result

            if input_type == 'ip':
                ipinfo_result = get_ip_info(input_value)
                if ipinfo_result and 'error' not in ipinfo_result:
                    report.ipinfo_data = ipinfo_result

            # Étape 5 : Calculer le score et sauvegarder
            report.calculate_threat_score()
            report.save()

            # Étape 6 : Renvoyer le rapport complet
            output_serializer = ThreatReportSerializer(report)
            return Response(output_serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Nettoyer si l'analyse échoue
            report.delete()
            logger.error(f"Erreur d'analyse API : {e}")
            return Response({'error': f"Erreur d'analyse : {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===================================================================
# VIEWSETS API POUR LES MODÈLES
# ===================================================================

class ThreatReportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API pour lister et récupérer les ThreatReports.
    - Analystes : voient leurs propres rapports.
    - Admins : voient les rapports qui leur sont assignés.
    """
    serializer_class = ThreatReportSerializer
    permission_classes = [permissions.IsAuthenticated] # La permission est dans le queryset

    def get_queryset(self):
        user = self.request.user
        if not hasattr(user, 'role'): # Au cas où l'utilisateur n'est pas entièrement configuré
             return ThreatReport.objects.none()
             
        if user.role == 'admin':
            # Les admins voient les rapports qui leur sont assignés
            return ThreatReport.objects.filter(assigned_to=user)
        elif user.role == 'analyst':
            # Les analystes voient les rapports qu'ils ont créés
            return ThreatReport.objects.filter(analyst=user)
        return ThreatReport.objects.none()

    @action(detail=True, methods=['post'], permission_classes=[IsAnalystUser])
    def send_to_admin(self, request, pk=None):
        """
        Action personnalisée : POST /api/v1/reports/{id}/send_to_admin/
        Attribution du rapport à un admin.
        """
        report = self.get_object() # Utilise get_queryset, donc l'analyste doit être propriétaire
        admin_id = request.data.get('admin_id')
        notes = request.data.get('notes', '')

        if not admin_id:
            return Response({'error': 'admin_id requis.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            admin = User.objects.get(id=admin_id, role='admin')
        except User.DoesNotExist:
            return Response({'error': 'Administrateur non trouvé.'}, status=status.HTTP_404_NOT_FOUND)

        report.assigned_to = admin
        report.notes = f"[Analyst Note]: {notes}"
        report.status = 'pending'
        report.save()
        
        Notification.objects.create(
            recipient=admin,
            notification_type='new_report',
            title=f'Nouveau Rapport de Menace: {report.input_type.upper()}',
            message=f"L'analyste {request.user.username} vous a envoyé un rapport ({report.severity}) pour examen.",
            report=report
        )
        
        return Response({'success': True, 'message': f'Rapport assigné à {admin.username}'})
    
    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def update_status(self, request, pk=None):
        """
        Action personnalisée : POST /api/v1/reports/{id}/update_status/
        Permet à un admin de changer le statut d'un rapport.
        """
        report = self.get_object() # Vérifie que l'admin est assigné
        status_val = request.data.get('status')
        notes = request.data.get('notes', '')

        if not status_val in ['reviewed', 'mitigated', 'false_positive']:
            return Response({'error': 'Statut non valide.'}, status=status.HTTP_400_BAD_REQUEST)
            
        report.status = status_val
        report.notes += f"\n\n[Admin Note]: {notes}"
        report.reviewed_at = datetime.now()
        report.save()
        
        # Notifier l'analyste
        Notification.objects.create(
            recipient=report.analyst,
            notification_type='report_updated',
            title=f'Rapport mis à jour : {report.input_value[:20]}...',
            message=f"L'administrateur {request.user.username} a mis à jour le statut de votre rapport à : {report.get_status_display()}.",
            report=report
        )
        
        return Response(ThreatReportSerializer(report).data)


    @action(detail=True, methods=['get'], permission_classes=[IsAdminOrOwner])
    def download_pdf(self, request, pk=None):
        """
        Action personnalisée : GET /api/v1/reports/{id}/download_pdf/
        """
        report = self.get_object()
        if report.pdf_report:
            try:
                return FileResponse(report.pdf_report.open(), as_attachment=True, filename=f'report_{report.id}.pdf')
            except FileNotFoundError:
                return Response({'error': 'Fichier PDF non trouvé.'}, status=status.HTTP_404_NOT_FOUND)
        
        # Si le PDF n'existe pas, générez-le
        try:
            pdf_path = generate_pdf_report(report) # Assurez-vous d'avoir importé pdf_generator.py
            report.pdf_report = pdf_path
            report.save()
            return FileResponse(report.pdf_report.open(), as_attachment=True, filename=f'report_{report.id}.pdf')
        except Exception as e:
            logger.error(f"Erreur lors de la génération du PDF (à la volée) : {e}")
            return Response({'error': f'Erreur de génération PDF : {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TaskViewSet(viewsets.ModelViewSet):
    """
    API pour gérer les Tâches (CRUD complet).
    """
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrOwner]

    def get_queryset(self):
        user = self.request.user
        if not hasattr(user, 'role'):
             return Task.objects.none()

        if user.role == 'admin':
            # Les admins voient les tâches liées aux rapports qui leur sont assignés
            return Task.objects.filter(report__assigned_to=user)
        elif user.role == 'analyst':
            # Les analystes voient les tâches liées aux rapports qu'ils ont créés
            return Task.objects.filter(report__analyst=user)
        return Task.objects.none()

    def get_serializer_context(self):
        # Transmet 'request' au serializer pour 'created_by'
        return {'request': self.request}


class MitigationActionViewSet(viewsets.ModelViewSet):
    """
    API pour gérer les Actions de Mitigation.
    Accessible uniquement aux Admins.
    """
    serializer_class = MitigationActionSerializer
    permission_classes = [IsAdminUser] # Seuls les admins peuvent gérer les mitigations

    def get_queryset(self):
        # Les admins voient toutes les mitigations
        return MitigationAction.objects.all()

    def get_serializer_context(self):
        return {'request': self.request}

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """
        Action personnalisée : POST /api/v1/mitigations/{id}/execute/
        Exécute l'action AWS.
        """
        mitigation = self.get_object()
        if mitigation.status == 'completed':
            return Response({'warning': 'Cette mitigation a déjà été exécutée.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # La logique est dans une fonction séparée pour la réutilisation
        result = execute_mitigation(mitigation)
        
        if result['success']:
            return Response({'success': True, 'message': result.get('message', 'Action exécutée.')})
        else:
            return Response({'error': result.get('error', 'Erreur inconnue.')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AWSConfigurationViewSet(viewsets.ViewSet):
    """
    API pour gérer la Configuration AWS.
    Accessible uniquement aux Admins.
    Utilise ViewSet car nous n'avons qu'un seul objet 'default_config'.
    """
    serializer_class = AWSConfigurationSerializer
    permission_classes = [IsAdminUser]
    
    def get_object(self):
        # Obtient ou crée la configuration nommée 'default_config'
        config, created = AWSConfiguration.objects.get_or_create(
            name='default_config',
            defaults={'aws_region': 'us-east-1', 'is_active': True}
        )
        return config

    def list(self, request):
        """
        GET /api/v1/aws-config/
        Récupère la configuration 'default_config'.
        """
        config = self.get_object()
        serializer = self.serializer_class(config)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """
        PUT /api/v1/aws-config/default_config/
        Met à jour la configuration 'default_config'.
        (pk est ignoré, nous utilisons toujours 'default_config')
        """
        config = self.get_object()
        serializer = self.serializer_class(config, data=request.data, partial=True) # partial=True
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def test_credentials(self, request):
        """
        POST /api/v1/aws-config/test_credentials/
        Teste les credentials AWS actuellement sauvegardés.
        """
        config = self.get_object()
        aws_manager = AWSManager(config)
        test_result = aws_manager.test_credentials()
        if test_result['success']:
            return Response(test_result)
        else:
            return Response(test_result, status=status.HTTP_400_BAD_REQUEST)


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API pour lister les notifications non lues de l'utilisateur.
    """
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Renvoie uniquement les notifications non lues pour l'utilisateur connecté
        return Notification.objects.filter(recipient=self.request.user, is_read=False)
        
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """
        Action personnalisée : POST /api/v1/notifications/{id}/mark_as_read/
        """
        notification = self.get_object()
        if notification.recipient == request.user:
            notification.is_read = True
            notification.save()
            return Response({'success': True, 'message': 'Notification marquée comme lue.'})
        else:
            return Response({'error': 'Permission refusée.'}, status=status.HTTP_403_FORBIDDEN)


# ===================================================================
# LOGIQUE D'EXÉCUTION (déplacée depuis l'ancienne vue)
# ===================================================================
def execute_mitigation(mitigation):
    """
    Exécute une action de mitigation en utilisant le AWSManager.
    Met à jour l'objet mitigation avec le résultat.
    """
    logger.info(f"Exécution de la mitigation ID {mitigation.id}...")
    
    try:
        aws_config = AWSConfiguration.objects.get(name='default_config', is_active=True)
        logger.info(f"Utilisation de la configuration AWS : {aws_config.name}")
    except AWSConfiguration.DoesNotExist:
        error_msg = "Aucune configuration AWS active nommée 'default_config' trouvée."
        logger.error(error_msg)
        mitigation.status = 'failed'
        mitigation.error_message = error_msg
        mitigation.save()
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f"Erreur lors de la récupération de la configuration AWS : {e}"
        logger.error(error_msg)
        mitigation.status = 'failed'
        mitigation.error_message = str(e)
        mitigation.save()
        return {'success': False, 'error': str(e)}

    # Initialiser le Manager AWS
    aws_manager = AWSManager(aws_config)
    result = {'success': False, 'error': 'Type d\'action inconnu'}
    try:
        if mitigation.action_type == 'block_ip':
            result = aws_manager.block_ip_in_security_group(
                ip_address=mitigation.target_value,
                description=mitigation.description
            )
        
        elif mitigation.action_type == 'allow_ip': # Action pour autoriser
             result = aws_manager.allow_ip_in_security_group(
                ip_address=mitigation.target_value,
                description=mitigation.description
            )

        elif mitigation.action_type == 'block_domain':
            # Vous devez d'abord résoudre le domaine en IP
            # import socket
            # try:
            #   ip_address = socket.gethostbyname(mitigation.target_value)
            #   result = aws_manager.block_ip_in_waf(ip_address)
            # except socket.gaierror:
            #   result = {'success': False, 'error': 'Impossible de résoudre le domaine'}
            result = {'success': False, 'error': 'Le blocage de domaine (WAF) n\'est pas encore implémenté.'}
        
        # ... (Appels aux autres fonctions de aws_integration.py) ...
        
        if result['success']:
            mitigation.status = 'completed'
            mitigation.completed_at = datetime.now()
            if mitigation.report:
                mitigation.report.status = 'mitigated'
                mitigation.report.save()
        else:
            mitigation.status = 'failed'
            mitigation.error_message = result.get('error', 'Erreur inconnue')
            
        mitigation.save()
        return result

    except Exception as e:
        error_msg = f"Erreur système : {e}"
        logger.error(f"Erreur critique lors de l'exécution de la mitigation {mitigation.id}: {e}")
        mitigation.status = 'failed'
        mitigation.error_message = error_msg
        mitigation.save()
        return {'success': False, 'error': error_msg}
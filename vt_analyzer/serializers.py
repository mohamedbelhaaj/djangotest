from rest_framework import serializers
from dj_rest_auth.serializers import UserDetailsSerializer as BaseUserDetailsSerializer
from .models import (
    User, ThreatReport, Task, MitigationAction, AWSConfiguration, Notification
)

class UserSimpleSerializer(serializers.ModelSerializer):
    """
    Un serializer simple pour n'afficher que le nom de l'utilisateur.
    Utilisé pour l'imbrication.
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'role']

class UserDetailsSerializer(BaseUserDetailsSerializer):
    """
    Remplace le serializer UserDetails de dj-rest-auth
    pour inclure votre champ 'role' personnalisé.
    """
    class Meta(BaseUserDetailsSerializer.Meta):
        fields = BaseUserDetailsSerializer.Meta.fields + ('role', 'department', 'phone')
        # Remove the duplicate role field definition


# ===================================================================
# SERIALIZERS POUR LES POINTS DE TERMINAISON D'ANALYSE
# ===================================================================
class AnalysisInputSerializer(serializers.Serializer):
    """
    Valide l'entrée pour la nouvelle analyse.
    """
    input_value = serializers.CharField(required=False, allow_blank=True)
    file = serializers.FileField(required=False, allow_null=True)
    engine_choice = serializers.ChoiceField(choices=['vt', 'otx'], default='vt')

    def validate(self, data):
        if not data.get('input_value') and not data.get('file'):
            raise serializers.ValidationError("Please provide either an input value or upload a file")
        return data

# ===================================================================
# SERIALIZERS POUR LES MODÈLES DE BASE
# ===================================================================

class ThreatReportSerializer(serializers.ModelSerializer):
    """
    Traduit le modèle ThreatReport en JSON (pour LECTURE).
    """
    analyst = UserSimpleSerializer(read_only=True)
    assigned_to = UserSimpleSerializer(read_only=True)
    
    # Utilise les méthodes get_..._display() du modèle
    severity = serializers.CharField(source='get_severity_display', read_only=True)
    status = serializers.CharField(source='get_status_display', read_only=True)
    input_type = serializers.CharField(source='get_input_type_display', read_only=True)
    
    class Meta:
        model = ThreatReport
        fields = [
            'id', 'analyst', 'assigned_to', 'input_type', 'input_value', 
            'file_name', 'engine_used', 'vt_data', 'otx_data', 'ipinfo_data',
            'severity', 'threat_score', 'status', 'notes', 'created_at', 'reviewed_at'
        ]

class TaskSerializer(serializers.ModelSerializer):
    """
    Serializer pour créer, lister et mettre à jour les Tâches.
    """
    created_by = UserSimpleSerializer(read_only=True)
    assigned_to = UserSimpleSerializer(read_only=True)
    
    # Champs inscriptibles pour la création/mise à jour
    assigned_to_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), source='assigned_to', write_only=True
    )
    report_id = serializers.PrimaryKeyRelatedField(
        queryset=ThreatReport.objects.all(), source='report', write_only=True
    )
    
    class Meta:
        model = Task
        fields = [
            'id', 'report', 'title', 'description', 'priority', 'status',
            'created_by', 'assigned_to', 'due_date', 'created_at',
            'assigned_to_id', 'report_id' # Champs d'écriture
        ]
        read_only_fields = ('report', 'created_by', 'assigned_to')

    def create(self, validated_data):
        # Définit automatiquement 'created_by' lors de la création
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)

class MitigationActionSerializer(serializers.ModelSerializer):
    """
    Serializer pour créer et lister les Actions de Mitigation.
    """
    initiated_by = UserSimpleSerializer(read_only=True)
    status = serializers.CharField(read_only=True)
    
    # Champs inscriptibles
    report_id = serializers.PrimaryKeyRelatedField(
        queryset=ThreatReport.objects.all(), source='report', write_only=True, required=False
    )

    class Meta:
        model = MitigationAction
        fields = [
            'id', 'report', 'action_type', 'target_value', 'aws_region', 
            'description', 'status', 'initiated_by', 'created_at', 'error_message',
            'report_id'
        ]
        read_only_fields = ('report', 'initiated_by', 'status', 'error_message', 'created_at')

    def create(self, validated_data):
        validated_data['initiated_by'] = self.context['request'].user
        return super().create(validated_data)

class AWSConfigurationSerializer(serializers.ModelSerializer):
    """
    Serializer pour voir et mettre à jour la Configuration AWS.
    """
    # Masque la clé secrète lors de la lecture
    aws_secret_key = serializers.CharField(write_only=True, required=False, allow_blank=True)
    
    class Meta:
        model = AWSConfiguration
        fields = [
            'name', 'aws_access_key', 'aws_secret_key', 'aws_region',
            'vpc_id', 'security_group_id', 'network_firewall_arn',
            'auto_block_enabled', 'auto_block_threshold', 'is_active'
        ]
    
    def update(self, instance, validated_data):
        # Ne met pas à jour la clé secrète si elle est laissée vide
        if not validated_data.get('aws_secret_key'):
            validated_data.pop('aws_secret_key', None)
        return super().update(instance, validated_data)

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = [
            'id', 'notification_type', 'title', 'message', 'is_read', 'created_at'
        ]
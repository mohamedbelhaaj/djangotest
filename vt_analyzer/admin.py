from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, 
    ThreatReport, 
    MitigationAction, 
    Task, 
    Notification, 
    ThreatIntelligenceLog, 
    AWSConfiguration
)

# Créez une classe d'administration personnalisée qui hérite de UserAdmin
class CustomUserAdmin(UserAdmin):
    
    # Ajoute vos champs personnalisés à la page "Ajouter un utilisateur"
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Rôle et infos personnalisées', {
            'fields': ('role', 'department', 'phone'),
        }),
    )
    
    # Ajoute vos champs personnalisés à la page "Modifier un utilisateur"
    fieldsets = UserAdmin.fieldsets + (
        ('Rôle et infos personnalisées', {
            'fields': ('role', 'department', 'phone'),
        }),
    )

# Enregistrez votre modèle User AVEC la classe personnalisée
admin.site.register(User, CustomUserAdmin)

# Enregistrez tous vos autres modèles (cette partie est la même qu'avant)
@admin.register(ThreatReport)
class ThreatReportAdmin(admin.ModelAdmin):
    list_display = ('input_value', 'input_type', 'severity', 'status', 'analyst', 'assigned_to', 'created_at')
    list_filter = ('status', 'severity', 'input_type', 'engine_used')
    search_fields = ('input_value', 'analyst__username', 'assigned_to__username')

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'priority', 'status', 'assigned_to', 'report')
    list_filter = ('status', 'priority')

@admin.register(MitigationAction)
class MitigationActionAdmin(admin.ModelAdmin):
    list_display = ('action_type', 'target_value', 'status', 'initiated_by', 'created_at')
    list_filter = ('status', 'action_type')

@admin.register(AWSConfiguration)
class AWSConfigurationAdmin(admin.ModelAdmin):
    list_display = ('name', 'aws_region', 'vpc_id', 'security_group_id', 'is_active')

admin.site.register(Notification)
admin.site.register(ThreatIntelligenceLog)
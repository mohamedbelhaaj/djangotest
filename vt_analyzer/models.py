from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid

class User(AbstractUser):
    ROLE_CHOICES = [
        ('analyst', 'Security Analyst'),
        ('admin', 'Administrator'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='analyst')
    department = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    
    # Note : Nous n'utilisons plus db_table = 'auth_user'
    class Meta:
        db_table = 'vt_analyzer_user' # Nom de table correct

class ThreatReport(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('reviewed', 'Reviewed'),
        ('mitigated', 'Mitigated'),
        ('false_positive', 'False Positive'),
    ]
    
    TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('url', 'URL'),
        ('hash', 'File Hash'),
        ('file', 'File Upload'),
        ('domain', 'Domain'), # Ajouté pour plus de clarté
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    analyst = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    
    # Input data
    input_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    input_value = models.TextField()
    file_name = models.CharField(max_length=255, blank=True, null=True)
    
    # Analysis results
    engine_used = models.CharField(max_length=10)  # 'vt' or 'otx'
    vt_data = models.JSONField(null=True, blank=True)
    otx_data = models.JSONField(null=True, blank=True)
    ipinfo_data = models.JSONField(null=True, blank=True)
    
    # Threat assessment
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')
    malicious_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    undetected_count = models.IntegerField(default=0)
    threat_score = models.FloatField(default=0.0)  # 0-100
    
    # Report metadata
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    notes = models.TextField(blank=True)
    pdf_report = models.FileField(upload_to='reports/pdf/', null=True, blank=True)
    csv_logged = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    
    # Admin assignment
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                      related_name='assigned_reports')
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.input_type.upper()}: {self.input_value[:50]} - {self.severity}"
    
    def calculate_threat_score(self):
        """Calculate threat score based on detection results"""
        if self.engine_used == 'vt' and self.vt_data and 'data' in self.vt_data:
            stats = self.vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            if total > 0:
                self.threat_score = ((malicious * 2 + suspicious) / total) * 100
            
            self.malicious_count = malicious
            self.suspicious_count = suspicious
            self.undetected_count = stats.get('undetected', 0)
            
            # Determine severity
            if malicious > 10:
                self.severity = 'critical'
            elif malicious > 5:
                self.severity = 'high'
            elif malicious > 0 or suspicious > 5:
                self.severity = 'medium'
            elif suspicious > 0:
                self.severity = 'low'
            else:
                self.severity = 'info'
        
        elif self.engine_used == 'otx' and self.otx_data:
            pulse_count = self.otx_data.get('pulse_count', 0)
            
            if pulse_count > 20:
                self.severity = 'critical'
                self.threat_score = 90
            elif pulse_count > 10:
                self.severity = 'high'
                self.threat_score = 70
            elif pulse_count > 5:
                self.severity = 'medium'
                self.threat_score = 50
            elif pulse_count > 0:
                self.severity = 'low'
                self.threat_score = 30
            else:
                self.severity = 'info'
                self.threat_score = 0
        
        # N'appelle pas self.save() ici, la vue s'en chargera
        # self.save()

class MitigationAction(models.Model):
    ACTION_TYPES = [
        ('block_ip', 'Block IP Address'),
        ('block_domain', 'Block Domain'),
        ('quarantine', 'Quarantine File'),
        ('alert', 'Send Alert'),
        ('investigate', 'Further Investigation'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(ThreatReport, on_delete=models.CASCADE, related_name='mitigations', null=True, blank=True)
    
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    
    # AWS integration details
    target_value = models.CharField(max_length=255)  # IP, domain, etc.
    aws_resource_id = models.CharField(max_length=255, blank=True)  # Security Group ID, Rule ID
    aws_region = models.CharField(max_length=20, default='us-east-1')
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    
    description = models.TextField()
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action_type} - {self.target_value} ({self.status})"

class Task(models.Model):
    PRIORITY_CHOICES = [
        ('urgent', 'Urgent'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(ThreatReport, on_delete=models.CASCADE, related_name='tasks')
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_tasks')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, 
                                      related_name='assigned_tasks')
    
    due_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-priority', '-created_at']
    
    def __str__(self):
        return f"{self.title} - {self.priority} ({self.status})"

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('new_report', 'New Report'),
        ('task_assigned', 'Task Assigned'),
        ('action_completed', 'Action Completed'),
        ('report_updated', 'Report Updated'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    
    report = models.ForeignKey(ThreatReport, on_delete=models.CASCADE, null=True, blank=True)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, null=True, blank=True)
    
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.notification_type} - {self.recipient.username}"

class ThreatIntelligenceLog(models.Model):
    """CSV-compatible model for threat intelligence logging"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.OneToOneField(ThreatReport, on_delete=models.CASCADE)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    indicator = models.CharField(max_length=255)
    indicator_type = models.CharField(max_length=20)
    
    threat_score = models.FloatField()
    severity = models.CharField(max_length=20)
    malicious_count = models.IntegerField()
    suspicious_count = models.IntegerField()
    
    country = models.CharField(max_length=50, blank=True)
    asn = models.CharField(max_length=50, blank=True)
    
    pulse_count = models.IntegerField(default=0)
    vt_positives = models.IntegerField(default=0)
    
    analyst = models.CharField(max_length=150)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.indicator} - {self.severity}"

class AWSConfiguration(models.Model):
    """Store AWS configuration for automated mitigation"""
    name = models.CharField(max_length=100, unique=True)
    
    aws_access_key = models.CharField(max_length=100, blank=True)
    aws_secret_key = models.CharField(max_length=100, blank=True)
    aws_region = models.CharField(max_length=20, default='us-east-1')
    
    vpc_id = models.CharField(max_length=50)
    security_group_id = models.CharField(max_length=50)
    network_firewall_arn = models.CharField(max_length=255, blank=True)
    
    auto_block_enabled = models.BooleanField(default=False)
    auto_block_threshold = models.IntegerField(default=10)  # Malicious count threshold
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'AWS Configuration'
        verbose_name_plural = 'AWS Configurations'
    
    def __str__(self):
        return f"{self.name} - {self.vpc_id}"
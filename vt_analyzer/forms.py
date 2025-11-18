from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User, Task, MitigationAction, AWSConfiguration

class AnalysisForm(forms.Form):
    ENGINE_CHOICES = [
        ('vt', 'VirusTotal'),
        ('otx', 'AlienVault OTX'),
    ]
    
    input_value = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter URL, IP, or Hash',
            'id': 'input_value'
        }),
        label='URL, IP Address, or Hash'
    )
    
    file = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'id': 'file_input',
            'accept': '*/*'
        }),
        label='Or upload a file'
    )
    
    engine_choice = forms.ChoiceField(
        choices=ENGINE_CHOICES,
        initial='vt',
        widget=forms.Select(attrs={
            'class': 'form-select',
            'id': 'engine_choice'
        }),
        label='Analysis Engine'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        input_value = cleaned_data.get('input_value')
        file = cleaned_data.get('file')
        
        if not input_value and not file:
            raise forms.ValidationError("Please provide either an input value or upload a file")
        
        return cleaned_data


class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['title', 'description', 'priority', 'assigned_to', 'due_date']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter task title'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter task description'
            }),
            'priority': forms.Select(attrs={
                'class': 'form-select'
            }),
            'assigned_to': forms.Select(attrs={
                'class': 'form-select'
            }),
            'due_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            })
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only show admin users in assignment dropdown
        self.fields['assigned_to'].queryset = User.objects.filter(role='admin')


class MitigationActionForm(forms.ModelForm):
    execute_now = forms.BooleanField(
        required=False,
        initial=False,
        label='Execute immediately',
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )
    
    class Meta:
        model = MitigationAction
        fields = ['action_type', 'target_value', 'aws_region', 'description', 'execute_now']
        widgets = {
            'action_type': forms.Select(attrs={
                'class': 'form-select'
            }),
            'target_value': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'IP address, domain, or file hash'
            }),
            'aws_region': forms.Select(attrs={
                'class': 'form-select'
            }, choices=[
                ('us-east-1', 'US East (N. Virginia)'),
                ('us-west-2', 'US West (Oregon)'),
                ('eu-west-1', 'EU (Ireland)'),
                ('eu-central-1', 'EU (Frankfurt)'),
                ('ap-southeast-1', 'Asia Pacific (Singapore)'),
            ]),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Describe the mitigation action'
            })
        }


class ReportStatusUpdateForm(forms.Form):
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('reviewed', 'Reviewed'),
        ('mitigated', 'Mitigated'),
        ('false_positive', 'False Positive'),
    ]
    
    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select'
        })
    )
    
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Add notes about this status change'
        })
    )


class AWSConfigurationForm(forms.ModelForm):
    class Meta:
        model = AWSConfiguration
        fields = [
            'name', 'aws_access_key', 'aws_secret_key', 'aws_region',
            'vpc_id', 'security_group_id', 'network_firewall_arn',
            'auto_block_enabled', 'auto_block_threshold'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Configuration name'
            }),
            'aws_access_key': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'AWS Access Key ID'
            }),
            'aws_secret_key': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'AWS Secret Access Key'
            }),
            'aws_region': forms.Select(attrs={
                'class': 'form-select'
            }, choices=[
                ('us-east-1', 'US East (N. Virginia)'),
                ('us-west-2', 'US West (Oregon)'),
                ('eu-west-1', 'EU (Ireland)'),
                ('eu-central-1', 'EU (Frankfurt)'),
                ('ap-southeast-1', 'Asia Pacific (Singapore)'),
            ]),
            'vpc_id': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'vpc-xxxxxxxxx'
            }),
            'security_group_id': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'sg-xxxxxxxxx'
            }),
            'network_firewall_arn': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'arn:aws:network-firewall:...'
            }),
            'auto_block_enabled': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'auto_block_threshold': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '1',
                'max': '50'
            })
        }


class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email address'
        })
    )
    
    department = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Department'
        })
    )
    
    phone = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Phone number'
        })
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'role', 'department', 'phone']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Username'
            }),
            'role': forms.Select(attrs={
                'class': 'form-select'
            })
        }


class SearchFilterForm(forms.Form):
    SEVERITY_CHOICES = [
        ('', 'All Severities'),
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('', 'All Statuses'),
        ('pending', 'Pending Review'),
        ('reviewed', 'Reviewed'),
        ('mitigated', 'Mitigated'),
        ('false_positive', 'False Positive'),
    ]
    
    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search indicators, notes...'
        })
    )
    
    severity = forms.ChoiceField(
        required=False,
        choices=SEVERITY_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select'
        })
    )
    
    status = forms.ChoiceField(
        required=False,
        choices=STATUS_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select'
        })
    )
    
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
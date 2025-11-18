from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

def send_notification(user_id, notification_data):
    """
    Send real-time notification to a user
    
    Args:
        user_id: User ID to send notification to
        notification_data: Dict containing notification data
    """
    channel_layer = get_channel_layer()
    group_name = f'user_{user_id}'
    
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            'type': 'notification',
            'notification': notification_data
        }
    )

def broadcast_dashboard_update(stats):
    """
    Broadcast dashboard stats update to all admins
    
    Args:
        stats: Dict containing dashboard statistics
    """
    channel_layer = get_channel_layer()
    
    async_to_sync(channel_layer.group_send)(
        'admin_dashboard',
        {
            'type': 'stats_update',
            'stats': stats
        }
    )

def send_critical_alert(report):
    """
    Send critical alert to all admins
    
    Args:
        report: ThreatReport instance
    """
    channel_layer = get_channel_layer()
    
    async_to_sync(channel_layer.group_send)(
        'admin_dashboard',
        {
            'type': 'new_critical_alert',
            'report_id': str(report.id),
            'message': f'Critical threat detected: {report.input_value}',
            'severity': report.severity
        }
    )
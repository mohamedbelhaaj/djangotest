import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model

User = get_user_model()

class NotificationConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time notifications"""
    
    async def connect(self):
        """Handle WebSocket connection"""
        self.user = self.scope['user']
        
        if self.user.is_authenticated:
            # Create a group for this user
            self.group_name = f'user_{self.user.id}'
            
            # Join user's notification group
            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )
            
            await self.accept()
            
            # Send connection confirmation
            await self.send(text_data=json.dumps({
                'type': 'connection_established',
                'message': 'Connected to notification system'
            }))
        else:
            await self.close()
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong'
                }))
            
            elif message_type == 'mark_read':
                notification_id = data.get('notification_id')
                await self.mark_notification_read(notification_id)
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON'
            }))
    
    async def notification(self, event):
        """Handle notification event from channel layer"""
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'notification': event['notification']
        }))
    
    async def new_report(self, event):
        """Handle new report notification"""
        await self.send(text_data=json.dumps({
            'type': 'new_report',
            'report_id': event['report_id'],
            'severity': event['severity'],
            'analyst': event['analyst'],
            'timestamp': event.get('timestamp')
        }))
    
    async def task_assigned(self, event):
        """Handle task assignment notification"""
        await self.send(text_data=json.dumps({
            'type': 'task_assigned',
            'task_id': event['task_id'],
            'title': event['title'],
            'priority': event['priority'],
            'assigned_by': event['assigned_by']
        }))
    
    async def action_completed(self, event):
        """Handle mitigation action completion"""
        await self.send(text_data=json.dumps({
            'type': 'action_completed',
            'action_id': event['action_id'],
            'status': event['status'],
            'message': event['message']
        }))
    
    @database_sync_to_async
    def mark_notification_read(self, notification_id):
        """Mark notification as read in database"""
        from .models import Notification
        try:
            notification = Notification.objects.get(id=notification_id, recipient=self.user)
            notification.is_read = True
            notification.save()
            return True
        except Notification.DoesNotExist:
            return False


class DashboardConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time dashboard updates"""
    
    async def connect(self):
        """Handle WebSocket connection"""
        self.user = self.scope['user']
        
        if self.user.is_authenticated and self.user.role == 'admin':
            # Join admin dashboard group
            self.group_name = 'admin_dashboard'
            
            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )
            
            await self.accept()
            
            # Send initial dashboard data
            stats = await self.get_dashboard_stats()
            await self.send(text_data=json.dumps({
                'type': 'initial_data',
                'stats': stats
            }))
        else:
            await self.close()
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
    
    async def receive(self, text_data):
        """Handle incoming messages"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'refresh_stats':
                stats = await self.get_dashboard_stats()
                await self.send(text_data=json.dumps({
                    'type': 'stats_update',
                    'stats': stats
                }))
                
        except json.JSONDecodeError:
            pass
    
    async def stats_update(self, event):
        """Handle stats update event"""
        await self.send(text_data=json.dumps({
            'type': 'stats_update',
            'stats': event['stats']
        }))
    
    async def new_critical_alert(self, event):
        """Handle critical alert"""
        await self.send(text_data=json.dumps({
            'type': 'critical_alert',
            'report_id': event['report_id'],
            'message': event['message'],
            'severity': event['severity']
        }))
    
    @database_sync_to_async
    def get_dashboard_stats(self):
        """Get current dashboard statistics"""
        from .models import ThreatReport, Task
        from django.db.models import Count
        
        # Get stats for this admin
        pending_reports = ThreatReport.objects.filter(
            assigned_to=self.user,
            status='pending'
        ).count()
        
        critical_reports = ThreatReport.objects.filter(
            assigned_to=self.user,
            severity='critical'
        ).count()
        
        open_tasks = Task.objects.filter(
            assigned_to=self.user,
            status='open'
        ).count()
        
        # Severity distribution
        severity_dist = dict(
            ThreatReport.objects.filter(
                assigned_to=self.user
            ).values('severity').annotate(count=Count('severity')).values_list('severity', 'count')
        )
        
        return {
            'pending_reports': pending_reports,
            'critical_reports': critical_reports,
            'open_tasks': open_tasks,
            'severity_distribution': severity_dist
        }
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from vt_analyzer import views

# Create router for ViewSets
router = DefaultRouter()
router.register(r'reports', views.ThreatReportViewSet, basename='report')
router.register(r'tasks', views.TaskViewSet, basename='task')
router.register(r'mitigations', views.MitigationActionViewSet, basename='mitigation')
router.register(r'aws-config', views.AWSConfigurationViewSet, basename='aws-config')
router.register(r'notifications', views.NotificationViewSet, basename='notification')

urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),
    
    # Custom Authentication endpoints (CSRF-free)
    path('api/auth/login/', views.CustomLoginView.as_view(), name='custom-login'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/users/', views.UserListView.as_view(), name='user-list'),

    # Other dj-rest-auth endpoints (if you need them)
    path('api/auth/', include('dj_rest_auth.urls')),  # Includes logout, user, password change
    
    # API endpoints
    path('api/', include(router.urls)),
    path('api/analyze/', views.AnalyzeView.as_view(), name='analyze'),
]
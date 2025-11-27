from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from django.contrib.auth import get_user_model
User = get_user_model()

class BasicModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
    def test_user_creation(self):
        """Test de création d'utilisateur"""
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertTrue(self.user.check_password('testpass123'))
        
    def test_user_string_representation(self):
        """Test de la représentation string de l'utilisateur"""
        self.assertEqual(str(self.user), 'testuser')


class UserAPITest(APITestCase):
    """Tests pour l'API utilisateur"""
    
    def setUp(self):
        """Préparation du client API"""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='apiuser',
            email='api@example.com',
            password='apipass123'
        )
        
    def test_api_client_exists(self):
        """Test que le client API existe"""
        self.assertIsNotNone(self.client)
        
    def test_user_exists(self):
        """Test que l'utilisateur existe"""
        self.assertIsNotNone(self.user)
        self.assertEqual(User.objects.count(), 1)


class DatabaseTest(TestCase):
    """Tests de base de données"""
    
    def test_database_connection(self):
        """Test de connexion à la base de données"""
        user_count = User.objects.count()
        self.assertGreaterEqual(user_count, 0)
        
    def test_create_multiple_users(self):
        """Test de création de plusieurs utilisateurs"""
        User.objects.create_user(username='user1', password='pass1')
        User.objects.create_user(username='user2', password='pass2')
        User.objects.create_user(username='user3', password='pass3')
        
        self.assertEqual(User.objects.count(), 3)


class AuthenticationTest(TestCase):
    """Tests d'authentification"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='authuser',
            password='authpass123'
        )
        
    def test_password_hashing(self):
        """Test que le mot de passe est haché"""
        self.assertNotEqual(self.user.password, 'authpass123')
        self.assertTrue(self.user.check_password('authpass123'))
        
    def test_wrong_password(self):
        """Test avec un mauvais mot de passe"""
        self.assertFalse(self.user.check_password('wrongpassword'))
from django.urls import reverse

from rest_framework.test import (
    APITestCase, 
    APIRequestFactory, 
    force_authenticate
)
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status


class UserAPITestCase(APITestCase):
    """ 
    Test class to verify the user endpoints
    """
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user_token = RefreshToken()
        self.url_register = reverse("userapiview-register")
        self.url_login = reverse("userapiview-login")
        self.url_logout = reverse("userapiview-logout")
        # self.url_reset_password = reverse('')

    def test_register_and_login_flow(self):
        register_data = {
            "username": "augustopontes",
            "full_name": "Augusto Mello",
            "email": "novoemail@gmail.com",
            "password": "testing-123",
            "password2": "testing-123",
        }
        response = self.client.post(self.url_register, register_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        login_data = {
            "email": "novoemail@gmail.com",
            "password": "testing-123",
        }
        response = self.client.post(self.url_login, login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout(self):
        ...

    def test_reset_password(self):
        ...

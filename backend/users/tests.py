from django.core import mail
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


class UserAPITestCase(TestCase):
    """
    Test class to verify the user endpoints
    """

    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            "username": "augustopontesmcp",
            "full_name": "Augusto Mello. C",
            "email": "example123@gmail.com",
            "password": "testing-1234",
            "password2": "testing-1234",
        }
        self.login_data = {
            "email": "example123@gmail.com",
            "password": "testing-1234",
        }
        self.reset_credentials_data = {
            "password": "testing-123456789"
        }

        # self.user_token = RefreshToken()
        self.url_register = reverse("userapiview-register")
        self.url_login = reverse("userapiview-login")
        self.url_logout = reverse("userapiview-logout")
        self.url_reset_password = reverse("userapiview-send-email-reset-password")

    def test_create_user(self):
        response = self.client.post(self.url_register, self.user_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_login_user(self):
        self.client.post(self.url_register, self.user_data, format="json")
        response = self.client.post(self.url_login, self.login_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout(self):
        # register + login
        self.client.post(self.url_register, self.user_data, format="json")
        login_response = self.client.post(
            self.url_login, self.login_data, format="json"
        )
        refresh = login_response.data["refresh"]
        access = login_response.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        logout_response = self.client.post(
            self.url_logout, {"refresh_token": refresh}, format="json"
        )
        self.assertEqual(logout_response.status_code, 205)

    def test_send_email_reset_password(self):
        self.client.post(self.url_register, self.user_data, format="json")
        self.client.post(self.url_login, self.login_data, format="json")
        
        response = self.client.post(
            self.url_reset_password,
            {"email": self.user_data["email"]},
            format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["detail"],
            "Email de mudança de senha enviado com sucesso!"
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.user_data["email"]])
        self.assertIn("rest-password-confirm", mail.outbox[0].body)

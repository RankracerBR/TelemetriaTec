from rest_framework.test import APITestCase,  force_authenticate

from .models import User


class UserAPITestCase(APITestCase):
    """ 
    UserAPITestCase
    """
    def setUp(self):
        User.objects.create(
            name="Augusto", 
            last_name="Mello", 
            email="augusto@gmail.com", 
            password="testing-123"
        )
    
    def test_register():
        ...
 
    def test_login():
        ...
    
    def test_logout():
        ...

    def test_rest_password():
        ...
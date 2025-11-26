from django.shortcuts import render
from rest_framework.viewsets import ViewSet

from .models import User


class UserAPI(ViewSet):
    """
    This class makes the logic to manage the user
    """
    def register(self):
        ...
        
    def login(self):
        ...
    
    def logout(self):
        ...
    
    def reset_password(self):
        ...
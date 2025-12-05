from rest_framework.viewsets import ViewSet
from rest_framework.response import Response
from rest_framework import status, exceptions
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import action

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from .models import User
from .serializers import UserSerializer


class UserAPIView(ViewSet):
    """
    This class makes the logic to manage the user
    """
    user_serializer = UserSerializer
    
    @action(detail=False, methods=["post"])
    def register(self, request):
        serializer = self.user_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "mensagem": "Usuário registrado com sucesso!"
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"])
    def login(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({
                "detail": "Campos obrigatórios faltando."}, 
                status=400
            )
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('Usuário não encontrado')
        if not user.check_password_user(password):
            raise exceptions.AuthenticationFailed('Senha incorreta')

        refresh = RefreshToken.for_user(user)

        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }, status=200)

    @action(detail=False, methods=["post"])
    def logout(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(e, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"])
    def reset_password(self, request):
        email = request.data['data']
        user = User.objects.filter(email__iexact=email).first()

        if not user:
            return Response({
                "detail": "Se esse e-mail existir, será enviado por um link"
            }, status=status.HTTP_200_OK)

        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        
        reset_link = f"http://example-front/rest-password-confirm/{uidb64}/{token}" # TODO: MUDAR PARA URL REAL
 
        send_mail(
            subject="Redefinir senha",
            message=f"Link para redefinição da sua senha: {reset_link}",
            from_email="no-reply@email.com",
            recipient_list=[user.email]
        )

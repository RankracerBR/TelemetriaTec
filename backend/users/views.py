from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import exceptions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .serializers import UserSerializer


class UserAPIView(ViewSet):
    """
    This class makes the logic to manage the user
    """

    user_serializer = UserSerializer

    @action(detail=False, methods=["post"]) # TODO: ENVIAR EMAIL DE CONFIRMAÇÃO PARA O USUÁRIO
    def register(self, request):
        serializer = self.user_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"mensagem": "Usuário registrado com sucesso!"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"])
    def login(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response({"detail": "Campos obrigatórios faltando."}, status=400)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("Usuário não encontrado")
        if not user.check_password_user(password):
            raise exceptions.AuthenticationFailed("Senha incorreta")

        refresh = RefreshToken.for_user(user)

        return Response(
            {"refresh": str(refresh), "access": str(refresh.access_token)}, status=200
        )

    @action(detail=False, methods=["post"])
    def logout(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"detail": "refresh_token inválido"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"detail": "Logout realizado com sucesso!"},
                status=status.HTTP_205_RESET_CONTENT,
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["post"]) # TODO: FAZER O USUÁRIO DESLOGAR DA CONTA DEPOIS DE MUDAR A SENHA
    def send_email_reset_password(self, request):
        email = request.data.get("email")
        user = User.objects.filter(email__iexact=email).first()

        if not user:
            return Response(
                {"detail": "Email de usuário não encontrado"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token = PasswordResetTokenGenerator().make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        reset_link = f"http://example-front/rest-password-confirm/{uidb64}/{token}"  # TODO: MUDAR PARA URL REAL

        send_mail(
            subject="Redefinir senha",
            message=f"Link para redefinição da sua senha: {reset_link}",
            from_email="no-reply@email.com",
            recipient_list=[user.email],
        )
        
        return Response(
            {"detail": "Email de mudança de senha enviado com sucesso!"}
        )

    @action(detail=False, methods=["post"])
    def reset_password(self, request):
        password = request.data.get('password')
        
        generate_new_password = ...
        
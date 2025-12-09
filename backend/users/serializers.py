from rest_framework.serializers import (CharField,
                                        ModelSerializer,
                                        ValidationError,
                                        Serializer,
                                        RegexField)

from .models import User


class UserSerializer(ModelSerializer):
    password2 = CharField(write_only=True)

    class Meta:
        model = User
        fields = ["username", "full_name", "email", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise ValidationError({"password": "Passwords must match"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class ResetPasswordSerializer(Serializer):
    new_password = RegexField(
        reger=r"(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        write_only=True,
        error_messages={"invalid": (
            "A senha precisa ter pelo menos 8 caractéres com pelo menos uma letra maiúscula e simbolo"
        )})
    confirm_password = CharField(write_only=True, required=True)

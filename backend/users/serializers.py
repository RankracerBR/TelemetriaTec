from rest_framework.serializers import ModelSerializer, CharField, ValidationError

from .models import User


class UserSerializer(ModelSerializer):
    password2 = CharField(write_only=True)

    class Meta:
        model = User
        fields = ["username", "full_name", "email", "password", "password2"]
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise ValidationError({"password": "Passwords must match"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)  # correto!
        user.save()
        return user

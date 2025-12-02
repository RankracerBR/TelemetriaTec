from rest_framework.serializers import ModelSerializer, CharField, ValidationError

from .models import User


class UserSerializer(ModelSerializer):
    password2 = CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True}
        }
        read_only_fields = ["id"]

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise ValidationError({
                "senha": "A senha tem que ser a mesma para os dois campos"
            })
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            name=validated_data["name"],
            last_name=validated_data["last_name"],
            email=validated_data["email"],
            password=validated_data["password"]
        )
        return user

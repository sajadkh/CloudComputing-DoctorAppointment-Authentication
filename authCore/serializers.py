from django.contrib.auth import get_user_model
from rest_framework import serializers


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        user = get_user_model().objects.create(
            username=validated_data['username'],
            role=validated_data['role']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'password', 'role', "email"]


class UserListSerializer(serializers.Serializer):
    id = serializers.CharField(required=True)
    username = serializers.CharField(required=True)
    email = serializers.CharField(required=False)
    role = serializers.CharField(required=True)

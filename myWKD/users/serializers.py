from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    def get_public(self):
        return self.public_key

    def get_encrypt(self):
        return self.encrypt_key

    class Meta:
        model = User
        fields = ('username', 'fullname', 'public_key', 'encrypt_key')

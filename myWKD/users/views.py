# users/views.py
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.decorators import action
from .models import User
from .serializers import UserSerializer
from django.http import HttpResponse, Http404



class UsersList(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class UserDetails(generics.RetrieveUpdateDestroyAPIView):

    """
    Retrieve, update or delete a user instance.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        user = self.get_object(pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_public(self,request, pk, format=None):
        user = self.get_object(pk)
        public = user.get_public()
        return Response(public)


'''
class UserDetails(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @action(detail=True, methods=['get'])
    def get_public(self,request,pk=None):
        user = self.get_object()
        return Response(user.get_public())


class MultiKeyGetObject(generics.GenericAPIView):
    def __init__(self):
        if not hasattr(self, 'lookup_fields'):
            raise AssertionError("Expected view {} to have `.lookup_fields` attribute".format(self.__class__.__name__))

    def get_object(self):
        for field in self.lookup_fields:
            if field in self.kwargs:
                self.lookup_field = field
                break
        else:
            raise AssertionError(
                'Expected view %s to be called with one of the lookup_fields: %s' %
                (self.__class__.__name__, self.lookup_fields))

        return super().get_object()



@api_view(['GET','PUT','DELETE'])
def user_details(request,pk):
    """
    Retrieve, update or delete a users
    """
    try:
        user= User.object.get(pk=pk)
        print(pk)
    except Exception:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if (request.method == 'GET'):
        serializer = UserSerializer(user)
        return Response(serializer.data)
    elif (request.method == 'PUT'):
        serializer = UserSerializer(user,data=request.data)
        if (serializer.is_valid()):
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif (request.method == 'DELETE'):
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
'''

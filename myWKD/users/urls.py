# users/urls.py
from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from users import views

urlpatterns = [
    path('users/', views.UsersList.as_view()),
    #path('users/<int:pk>/', views.UserDetail.as_view()),
    #path(r'^users/\w+|[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]+$/', views.UserDetail.as_view()),
    path('users/<str:pk>', views.UserDetails.as_view()),
    #path('users/<str:pk>', views.UserDetails.get_public()),
    #path('users/<str:pk>/enc', views.UserPub.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)

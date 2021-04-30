from django.urls import path
from . import views

urlpatterns = [
    path('auth/users', views.user, name='signup'),
    path('auth/users/<int:pk>', views.user_detail, name='show the user info'),
    path('auth/login', views.login, name='login'),
    path('auth/logout', views.logout, name='logout'),
    path('auth/verify', views.verify_token, name='verify token')
]
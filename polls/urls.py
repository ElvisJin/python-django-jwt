from django.urls import path

from . import views

urlpatterns = [
  path('', views.index, name='index'),
  # path('jwt', views.jwt, name='jwt')
]
from django.urls import include, path

from views import users as views

urlpatterns = [
    path('run/', views.run),
    path('api/', include('api.urls')),
]

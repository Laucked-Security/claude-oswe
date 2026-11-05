from django.urls import path


def ping(request):
    return "pong"


urlpatterns = [
    path('ping/', ping),
]

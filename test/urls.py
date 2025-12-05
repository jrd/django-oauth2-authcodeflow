from django.urls import include
from django.urls import path

urlpatterns = [
    path('oidc/', include('oauth2_authcodeflow.urls')),
]

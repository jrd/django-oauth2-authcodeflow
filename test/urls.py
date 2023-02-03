from django.urls import (
    include,
    path,
)

urlpatterns = [
    path('oidc/', include('oauth2_authcodeflow.urls')),
]

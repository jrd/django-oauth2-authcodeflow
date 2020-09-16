from django.urls import path

from .conf import (
    constants,
    settings,
)

urlpatterns = [
    path('authenticate', settings.OIDC_VIEW_AUTHENTICATE.as_view(), name=constants.OIDC_URL_AUTHENTICATION_NAME),
    path('callback', settings.OIDC_VIEW_CALLBACK.as_view(), name=constants.OIDC_URL_CALLBACK_NAME),
    path('logout', settings.OIDC_VIEW_LOGOUT.as_view(), name=constants.OIDC_URL_LOGOUT_NAME),
    path('total_logout', settings.OIDC_VIEW_TOTAL_LOGOUT.as_view(), name=constants.OIDC_URL_TOTAL_LOGOUT_NAME),
    path('logout_by_op', settings.OIDC_VIEW_LOGOUT_BY_OP.as_view(), name=constants.OIDC_URL_LOGOUT_BY_OP_NAME),
]

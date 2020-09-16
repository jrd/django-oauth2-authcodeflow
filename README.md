Setup
-----

- add `oauth2_authcodeflow` to the `INSTALLED_APPS` (after `django.contrib.auth` and `django.contrib.session` apps)
- add `path('oidc/', include('oauth2_authcodeflow.urls')),` in your global `urls.py` file.
    You can change the path prefix to what you want
- add `oauth2_authcodeflow.auth.AuthenticationBackend` ot the `AUTHENTICATION_BACKENDS` config.
    You can keep `django.contrib.auth.backends.ModelBackend` as a second-fallback auth mechanism.
- get your callback urls by doing:
```sh
./manage.py oidc_urls <HOST_NAME> [--secure]
```
- Configure your application on the OpenId Connect Provider.
  This should give you a `client_id` and a `secret_id`.
  You will need to fill the `redirect_url` and `logout_url` there.
- Ensue to include the email, first name, last name and `sid` parameters in the id token claims on the OP.
- Ensure that `django.contrib.sessions.middleware.SessionMiddleware` is in `MIDDLEWARE`

Configuration
-------------

- configure your `SESSION_ENGINE` to store the session NOT in the database:
    - `django.contrib.sessions.backends.cache` and set your `CACHES` config to sane values
    - `django.contrib.sessions.backends.cached_db` to use both cache and db
    - `django.contrib.sessions.backends.file` and set your `SESSION_FILE_PATH` config
    - `django.contrib.sessions.backends.signed_cookies` but **not recommended**
- configure your session cookie settings:
    - `SESSION_COOKIE_AGE`
    - `SESSION_COOKIE_HTTPONLY` should **always** be `True`
    - `SESSION_COOKIE_PATH` be sure to use `/` to prevent some weird behavior
    - `SESSION_COOKIE_SAMESITE` **should** be `Lax`
    - `SESSION_COOKIE_SECURE` should **always** be `True`
- define either `OIDC_OP_DISCOVERY_DOCUMENT_URL` or the following configs:
    - `OIDC_OP_AUTHORIZATION_URL`
    - `OIDC_OP_TOKEN_URL`
    - `OIDC_OP_JWKS_URL`
    - `OIDC_OP_END_SESSION_URL`
- define `OIDC_RP_CLIENT_ID` and `OIDC_RP_CLIENT_SECRET` configs
- define, if your OP parameters are different that the following default:
    - `OIDC_EMAIL_CLAIM`: `email`
    - `OIDC_FIRSTNAME_CLAIM`: `given_name`
    - `OIDC_LASTNAME_CLAIM`: `family_name`

Optional middlewares
--------------------
TODO

Login
-----

Get your browser/frontend to go to the `oidc_authentication` page name (`/oidc/authenticate`) with the following parameters:
    - `next`: the url to redirect on success
    - `fail`: the url to redirect on failure, `error` query string may contain an error description

Logout
------

Get your browser/frontend to go to the `oidc_logout` page name (`/oidc/logout`) with the following parameters:
    - `next`: the url to redirect on success
    - `fail`: the url to redirect on failure, `error` query string may contain an error description

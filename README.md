Summary
=======

[![pypi downloads][dl-image]][pypi-url]
[![pypi status][status-image]][pypi-url]
[![python versions][py-image]][pypi-url]
[![django versions][django-image]][pypi-url]
[![pipeline status][pipeline-image]][pipeline-url]
[![license][license-image]](./LICENSE)

[pypi-url]: https://pypi.org/project/django-oauth2-authcodeflow/
[dl-image]: https://img.shields.io/pypi/dm/django-oauth2-authcodeflow
[status-image]: https://img.shields.io/pypi/status/django-oauth2-authcodeflow
[py-image]: https://img.shields.io/pypi/pyversions/django-oauth2-authcodeflow.svg
[django-image]: https://img.shields.io/pypi/djversions/django-oauth2-authcodeflow.svg
[pipeline-image]: https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/badges/master/pipeline.svg?ignore_skipped=true
[pipeline-url]: https://gitlab.com/systra/qeto/lib/django-oauth2-authcodeflow/-/commits/master
[license-image]: https://img.shields.io/pypi/l/django-oauth2-authcodeflow.svg

Authenticate with any OpenId Connect/Oauth2 provider through authorization code flow with [Django](https://www.djangoproject.com/).

PKCE is also supported.

Wording
-------

- OP = OpenId Connect Provider, the auth server
- RP = Relying Party, the client, your application

Setup
-----

- add `oauth2_authcodeflow` to the `INSTALLED_APPS` (after `django.contrib.auth` and `django.contrib.session` apps)
- add `path('oidc/', include('oauth2_authcodeflow.urls')),` in your global `urls.py` file.

    You can change the path prefix to what you want

- add `oauth2_authcodeflow.auth.AuthenticationBackend` to the `AUTHENTICATION_BACKENDS` config.

    You can keep `django.contrib.auth.backends.ModelBackend` as a second-fallback auth mechanism.

- get your callback urls by doing:
```sh
./manage.py oidc_urls [--secure] <HOST_NAME>
```
- Configure your application on the OpenId Connect Provider.

    This should give you a `client_id` and a `secret_id`.

    You will need to fill the `redirect_url` and `logout_url` there.

- Ensue to include the `sid`, email, first name, last name (if applicable) parameters in the id token claims on the OP.
- Ensure that `django.contrib.sessions.middleware.SessionMiddleware` is in `MIDDLEWARE`

Minimal configuration
---------------------

- `SESSION_COOKIE_SECURE` to `True` if your Django is served through *HTTPS*
- `OIDC_OP_DISCOVERY_DOCUMENT_URL` to the well-known openid configuration url of the OP
- `OIDC_RP_CLIENT_ID` client id provided by the OP
- `OIDC_RP_CLIENT_SECRET` secrect id provided by the OP

Login
-----

Get your browser/frontend to go to the `oidc_authentication` page name (`/oidc/authenticate` by default) with the following parameters:

- `next`: the url to redirect on success
- `fail`: the url to redirect on failure, `error` query string may contain an error description

Logout
------

Get your browser/frontend to go to the `oidc_logout` page name (`/oidc/logout` by default) with the following parameters:

- `next`: the url to redirect on success
- `fail`: the url to redirect on failure, `error` query string may contain an error description

Logout from the OP as well
--------------------------

This will logout the user from the application but also from the OP (if user say yes) and the OP should also logout the user from all other apps connected to this OP.

The spec is not well followed by the OP, so you mileage may vary.

Get your browser/frontend to go to the `oidc_total_logout` page name (`/oidc/total_logout` by default) with the following parameters:

- `next`: the url to redirect on success
- `fail`: the url to redirect on failure, `error` query string may contain an error description

Protect your urls
-----------------

At least three options are possible.

1. Use default django way to [limit access to logged-in users](https://docs.djangoproject.com/en/4.1/topics/auth/default/#limiting-access-to-logged-in-users) by defining `LOGIN_URL` in your settings and and `login_required` decorators in your views.  
  ```python
  # settings.py
  from django.urls import reverse_lazy
  from django.utils.text import format_lazy
  LOGIN_URL = format_lazy('{url}?fail=/', url=reverse_lazy(OIDC_URL_AUTHENTICATION_NAME))
  # urls.py
  from django.contrib.auth.decorators import login_required
  path('restricted_url/', login_required(your_view)),
  ```
2. A slightly different version, by directly and only using the `login_required` from `oauth2_authcodeflow.utils`.
3. Use the `LoginRequiredMiddleware` with `OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS` configuration.

Optional middlewares
--------------------

You can add some middlewares to add some features:

- `oauth2_authcodeflow.middleware.LoginRequiredMiddleware` to automaticaly force a login request to urls not in `OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS` if not authenticated.
- `oauth2_authcodeflow.middleware.RefreshAccessTokenMiddleware` to automaticaly refresh the access token when it’s expired.
- `oauth2_authcodeflow.middleware.RefreshSessionMiddleware` to automaticaly ask for a new id token when it’s considered expired.
- `oauth2_authcodeflow.middleware.BearerAuthMiddleware` to authenticate the user using `Authorization` HTTP header (API, scripts, CLI usage).

`LoginRequiredMiddleware` will refresh to the original page uppon user logged-in.

`RefreshAccessTokenMiddleware` and `RefreshSessionMiddleware` will try the refresh and return a redirect to the same page (or the one configured as next in the login phase) if the refresh cannot happen.

Use them to silently refresh your access/id tokens.

BearerAuthMiddleware will use `oauth2_authcodeflow.auth.BearerAuthenticationBackend` to authenticate the user based on `Authorization` HTTP header instead of using the sessions.

Use this to allow to authenticate without cookies/session. You then need to login with `from_cli=1` in your `login` url. You then needs to go to the displayed url with a browser and copy the result http header to make further requests.


Full configuration
------------------
Secure session cookie settings:

- `SESSION_COOKIE_AGE` to a reasonable time (default 2 weeks)
- `SESSION_COOKIE_HTTPONLY` **must** be `True` (default `True`)
- `SESSION_COOKIE_PATH` be sure to use `/` to prevent some weird behavior (default `/`)
- `SESSION_COOKIE_SAMESITE` **should** be `Lax` (default `Lax`)
- `SESSION_COOKIE_SECURE` **should** be `True` in *https* context (default `False`)

Specific OIDC settings:

| Settings | Description | Default |
| -------- | ----------- | ------- |
| `OIDC_OP_DISCOVERY_DOCUMENT_URL` | URL of your OpenID connect Provider discovery document url (*recommended*).<br>If you provide this, the following configs will be ignored:<br>- `OIDC_OP_AUTHORIZATION_URL`<br>- `OIDC_OP_TOKEN_URL`<br>- `OIDC_OP_USERINFO_URL`<br>- `OIDC_OP_JWKS_URL` | `None` |
| `OIDC_OP_AUTHORIZATION_URL` | URL of your OpenID connect Provider authorization endpoint (**not recommended**, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred). | `None` |
| `OIDC_OP_TOKEN_URL` | URL of your OpenID connect Provider token endpoint (**not recommended**, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred). | `None` |
| `OIDC_OP_USERINFO_URL` | URL of your OpenID connect Provider userinfo endpoint (**not recommended**, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred). | `None` |
| `OIDC_OP_JWKS_URL` | URL of your OpenId connect Provider endpoint to get public signing keys (in `PEM` or `DER` format).<br>This is used to verify the `id_token`.<br>This is **not recommended** to provide this url here but rather use `OIDC_OP_DISCOVERY_DOCUMENT_URL` config. | `None` |
| `OIDC_OP_END_SESSION_URL` | URL of your OpenID connect Provider end session endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred). | `None` |
| `OIDC_OP_FETCH_USER_INFO` | Fetch user info on login or not. | `True` |
| `OIDC_OP_TOTAL_LOGOUT` | Do a call to total logout will call the OP for a logout. Default true.<br>Be careful, some OP will not follow the RFC and will not allow the user to NOT logout all connected apps.<br>Azure is such a bad example. | `True` |
| `OIDC_OP_EXPECTED_EMAIL_CLAIM` | expected email key. | `'email'` |
| `OIDC_OP_EXPECTED_CLAIMS` | `OIDC_OP_EXPECTED_EMAIL_CLAIM` value is automatically included in this list. | `[]` |
| `OIDC_RP_CLIENT_ID` | OpenID Connect client ID provided for your Relaying Party/client by your OpenIdConnect Provider | |
| `OIDC_RP_CLIENT_SECRET` | OpenID Connect client secret provided for your Relaying Party/client by your OpenIdConnect Provider | |
| `OIDC_RP_USE_PKCE` | `PKCE` improve security, disable it only if your provider cannot handle it. | `True` |
| `OIDC_RP_FORCE_CONSENT_PROMPT` | Force to ask for consent on login, even if `offline_access` is not in scopes | `False` |
| `OIDC_RP_SCOPES` | The OpenID Connect scopes to request during login.<br>The scopes could be usefull later to get access to other ressources.<br>`openid` must be in the list.<br>You can also include the `email` scope to ensure that the email field will be in the claims (*recommended*).<br>You can also include the `profile` scope to get more (like names, …) info in the `id_token` (*recommended*).<br>You can also get a `refresh_token` by specifying the `offline_access` scope. | `['openid', 'email', 'profile', 'offline_access']` |
| `OIDC_RP_USERINFO_CLAIMS` | OpenID Connect authorization [request parameter `userinfo` member](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) to optionaly add to id token request (dict type). | `None` |
| `OIDC_RP_TOKEN_CLAIMS` | OpenID Connect authorization [request parameter `id_token` member](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) to optionaly add to id token request (dict type). | `None` |
| `OIDC_RP_SIGN_ALGOS_ALLOWED` | Sets the algorithms the IdP may use to sign ID tokens.<br>Typical values ar `HS256` (no key required) and `RS256` (public key required)<br>The public keys might be defined in `OIDC_RP_IDP_SIGN_KEY` or deduced using the `OIDC_OP_JWKS_URL` config. | `['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']` |
| `OIDC_RP_IDP_SIGN_KEY` | Public RSA used to verify signatures. Overrides keys from JWKS endpoint.<br>Should be in `PEM` or `DER` format. | `None` |
| `OIDC_CREATE_USER` | Enables or disables automatic user creation during authentication | `True` |
| `OIDC_RANDOM_SIZE` | Sets the length of the random string used in the OAuth2 protocol. | `32` |
| `OIDC_PROXY` | Defines a proxy for all requests to the OpenID Connect provider (fetch JWS, retrieve JWT tokens, Userinfo Endpoint).<br>The default is set to `None` which means the library will not use a proxy and connect directly.<br>For configuring a proxy check the Python requests documentation: <https://requests.readthedocs.io/en/master/user/advanced/#proxies> | `None` |
| `OIDC_TIMEOUT` | Defines a timeout for all requests to the OpenID Connect provider (fetch JWS, retrieve JWT tokens, Userinfo Endpoint).<br>The default is set to `None` which means the library will wait indefinitely.<br>The time can be defined as seconds (integer).<br>More information about possible configuration values, see Python requests: <https://requests.readthedocs.io/en/master/user/quickstart/#timeouts> | `None` |
| `OIDC_REDIRECT_OK_FIELD_NAME` | Sets the GET parameter that is being used to define the redirect URL after succesful authentication | `'next'` |
| `OIDC_REDIRECT_ERROR_FIELD_NAME` | Sets the GET parameter that is being used to define the redirect URL after failed authentication | `'fail'` |
| `OIDC_DJANGO_USERNAME_FUNC` | Function or dotted path to a function that compute the django username based on claims.<br>The username should be unique for this app.<br>The default is to use a base64 url encode of the email hash (sha1). | `get_default_django_username` |
| `OIDC_EMAIL_CLAIM` | Claim name for email<br>`None` value means use `OIDC_OP_EXPECTED_EMAIL_CLAIM` value<br>You can also provide a lambda that takes all the claims as argument and return an email | `None` |
| `OIDC_FIRSTNAME_CLAIM` | You can also provide a lambda that takes all the claims as argument and return a firstname | `'given_name'` |
| `OIDC_LASTNAME_CLAIM` | You can also provide a lambda that takes all the claims as argument and return a lastname | `'family_name'` |
| `OIDC_EXTEND_USER` | Callable that takes the `user`, the `claims` and optionaly the `request` and `access_token` as arguments and that can extend user properties.<br>You can also specify a dotted path to a callable. | `None` |
| `OIDC_UNUSABLE_PASSWORD` | Scramble the password on each SSO connection/renewal.<br>If `False`, it will only scramble it when creating an account | `True` |
| `OIDC_BLACKLIST_TOKEN_TIMEOUT_SECONDS` | 7 days by default | `7 * 86400` |
| `OIDC_AUTHORIZATION_HEADER_PREFIX` | Only used when using authorization in header:<br>`Authorization: Bearer id_token`<br>This is only possible if `oauth2_authcodeflow.middleware.BearerAuthMiddleware` has been added to `MIDDLEWARE` setting list. | `'Bearer'` |
| `OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS` | The `RefreshAccessTokenMiddleware` and `RefreshSessionMiddleware` will use this list to bypass auth checks.<br>Any url listed here will not be tried to be authenticated using Auth Code Flow.<br>You should include at least any failure/error or admin urls in it. | `[]` |
| `OIDC_MIDDLEWARE_LOGIN_REQUIRED_REDIRECT` | Redirect to login page if not authenticated when using `LoginRequiredMiddleware`. | `True` |
| `OIDC_MIDDLEWARE_API_URL_PATTERNS` | The `RefreshAccessTokenMiddleware` and `RefreshSessionMiddleware` will use this list to answer JSON response in case of refresh failure.<br>Expected list of regexp URL patterns. | `['^/api/']` |
| `OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS` | 7 days by default | `7 * 86400` |

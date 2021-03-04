Known working settings for OP
=============================

Here are presented settings known to work for a specific OIDC Provider.

`OIDC_RP_CLIENT_ID` and `OIDC_RP_CLIENT_SECRET` will not be listed.

Azure
-----

| Setting | Value |
| ------- | ----- |
| `OIDC_OP_DISCOVERY_DOCUMENT_URL` | `'https://login.microsoftonline.com/<tenant_id>/v2.0/.well-known/openid-configuration'` |
| `OIDC_DJANGO_USERNAME_FUNC` | `'myapp.utils.get_azure_django_username'` |

With the following definition in `myapp/utils.py` module:

```python
def get_azure_django_username(claims):
    return claims['oid']
```

`oid` is a special Azure Object ID that uniquely identify the user.

Azure B2C
---------
Azure B2C does not offer a termination point for user. 
The configuration is similar to that of Azure AD but requires some small
changes.


| Setting | Value |
| ------- | ----- |
| `OIDC_OP_DISCOVERY_DOCUMENT_URL` | `'https://login.microsoftonline.com/<tenant_id>/v2.0/.well-known/openid-configuration'` |
| `OIDC_DJANGO_USERNAME_FUNC` | `'myapp.utils.get_azure_django_username'` |
| `OIDC_FIRSTNAME_CLAIM` | `lambda x: x['given_name']`|
| `OIDC_LASTNAME_CLAIM` | `lambda x: x['family_name']`|
| `OIDC_EMAIL_CLAIM` | `lambda x: x['emails']`|
| `OIDC_IGNORE_USERINFO_URL` | `True`|
| `OIDC_EMAIL_CLAIM_KEY` | `'emails'`|


Gitlab
------

| Setting | Value |
| ------- | ----- |
| `OIDC_OP_DISCOVERY_DOCUMENT_URL` | `'https://gitlab.com/.well-known/openid-configuration'` |
| `OIDC_RP_SCOPES` | ` = ['openid', 'email', 'profile']` |
| `OIDC_RP_USE_PKCE` | ` = False` |
| `OIDC_RP_FORCE_CONSENT` | ` = True` |
| `OIDC_FIRSTNAME_CLAIM` | ` = lambda claims: claims['name'].split(' ', 1)[0]` |
| `OIDC_LASTNAME_CLAIM` | ` = lambda claims: claims['name'].split(' ', 1)[1]` |
| `OIDC_DJANGO_USERNAME_FUNC` | `'myapp.utils.get_gitlab_django_username'` |

With the following definition in `myapp/utils.py` module:

```python
def get_gitlab_django_username(claims):
    return claims['nickname']
```

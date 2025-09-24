# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.3.1
### Fixed
- Refresh token call should use an origin header in Azure SPA

## 1.3.0
### Changed
- Python 3.13, Django 5.2 compat
### Added
- Allow to force to not ask for consent

## 1.2.3
### Changed
- Security update for `python-jose` from version `3.3.0` to `3.4.0`

## 1.2.2
### Fixed
- 'Origin' header should NOT be present if the Azure app is not a SPA.
### Added
- Explicit compatibility with django 5.1

## 1.2.1
### Fixed
- Fix a migration error from version `1.1.0` on a non-empty database (gitlab #26).
### Added
- Explicit compatibility with django 5.1

## 1.2.0
### Security
- Security package upgrades
### Fixed
- Azure tenant PKCE public app fix (Origin header was missing)
- Final fix for mysql on InnoDB with max key of 3072 by having the constraint as a lonely migration (github #21). Thanks Jurymax99 for the suggested merge request.
- Allow to logout even when using the Django `ModelBackend` (github #25)
### Changed
- Do not send the client secret, even if defined, with `PKCE` by default (github #18)
  This can be overriden with the `OIDC_RP_FORCE_SECRET_WITH_PKCE` parameter.
- Gitlab CI upgrades

## 1.1.0
### Fixed
- redirect after total logout could happen with a GET (#10)
- allow empty client secret (QE-625, gitlab #9)
### Added
- User logged in signal doc example, thanks @pinoatrome (github #16)
- Drop python 3.7, support python 3.12 and django 5

## 1.0.1
### Fixed
- Fix timestamp-awareness inside `RefreshSession` and `RefreshAccessToken` middlewares

## 1.0.0
### Changed
- Each log (debug, warning, error) is now correctly bound to the module name.
- Mypy 1.0
### Added
- Added documentation and changelog urls for PyPI 

## 0.9.0
### Fixed
- Default value for `jwks` in `BearerAuthenticationBackend` should be dict, not a list.
- Fix blacklist expiration for token where seconds where used as hours
- Fix `_clear_cache` method in `CacheBaseView`: was not clearing the session correctly.
- Configuration cannot be updated when using unit tests. This is now fixed. No impact on lib usage.
- Respect the optional `fail` parameter of `@login_required` decorator.
- Middlewares should not inherit depraceted `MiddlewareMixin`.
- If user does not exist on request, should not crash in `Oauth2MiddlewareMixin.is_oidc_enabled`.
### Changed
- Allow to override `MIN_SECONDS` in `RefreshSessionMiddleware`.
- Use UTC time in `RefreshAccessTokenMiddleware`, `RefreshSessionMiddleware`.
### Added
- `LoginRequiredMiddleware`
- Documentation about `@login_required`
### Removed
- `pytz` removed. `datetime.timezone.utc` is the only thing required.

## 0.8.1
### Fixed
- urls listed in `OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS` will not be tried on authentication in `auth.py`

## 0.8.0
### Added
- Allow to specify `userinfo` and `id_token` individual claims to get along with the id token request if the OP supports it (Eric Plaster, mr !12).
### Changed
- `OIDC_EXTEND_USER` callable can now takes a `request` and `access_token` as additional arguments (compatibility is assured).
- Migrate can raise an `IntegrityError` (ticket #7).
- All parameters that accept a function can also accept a dotted string to import the function.
- Migrate from `pipenv` to `poetry` system.

## 0.7.0
### Added
- Missing Django migration
### Changed
- Allow Django 4.1+ (but not 5.0)
- Add Python 3.11 in classifier
- Dependencies upgrade

## 0.6.0
### Changed
- Allow usage with Django 4.0 and update classifiers
- Make the code compatible with Python 3.7

## 0.5.0
### Added
- Allow to scramble the password only when creating an account instead of each SSO connection/renewal

## 0.4.0
### Added
- Allow `user` extension with a callable using `claims`
### Fixed
- User `email` field was filled with raw `email` value instead of actual value if `OIDC_EMAIL_CLAIM` was not set.

## 0.3.2
### Fixed
- No error 500 on expired authentication because the database session might not be found

## 0.3.1
### Fixed
- Prevent infinite redirect to authenticate view when using any middleware (session was not cleared properly)

## 0.3.0
### Changed
- Use `Authorization` header for `USERINFO` instead of request param
- `token` field in `BlacklistedToken` table changed from `TextField` to `CharField(max_length=15000)` for MySql compatibility
### Fixed
- register json web keys to session only if not already registered
- fix error handling by adding required method parameter
- `email`, `first_name` and `last_name` cannot be None. Fallback to empty string.
- correctly check for status code ok when getting access token.

## 0.2.1
### Fixed
- fix doc about `SESSION_COOKIE_SECURE`
- fix typo in f-string

## 0.2.0
### Added
- OP.md with settings examples for multiple OIDC Providers
### Fixed
- Management commands were not included in the package

## 0.1.0
Initialize library

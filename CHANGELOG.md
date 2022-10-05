# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

# 0.7.0
## Added
- Missing Django migration
## Changed
- Allow Django 4.1+ (but not 5.0)
- Add Python 3.11 in classifier
- Dependencies upgrade

# 0.6.0
## Changed
- Allow usage with Django 4.0 and update classifiers
- Make the code compatible with Python 3.7

# 0.5.0
## Added
- Allow to scramble the password only when creating an account instead of each SSO connection/renewal

# 0.4.0
## Added
- Allow `user` extension with a callable using `claims`
## Fixed
- User `email` field was filled with raw `email` value instead of actual value if `OIDC_EMAIL_CLAIM` was not set.

# 0.3.2
## Fixed
- No error 500 on expired authentication because the database session might not be found

# 0.3.1
## Fixed
- Prevent infinite redirect to authenticate view when using any middleware (session was not cleared properly)

# 0.3.0
## Changed
- Use `Authorization` header for `USERINFO` instead of request param
- `token` field in `BlacklistedToken` table changed from `TextField` to `CharField(max_length=15000)` for MySql compatibility
## Fixed
- register json web keys to session only if not already registered
- fix error handling by adding required method parameter
- `email`, `first_name` and `last_name` cannot be None. Fallback to empty string.
- correctly check for status code ok when getting access token.

# 0.2.1
## Fixed
- fix doc about `SESSION_COOKIE_SECURE`
- fix typo in f-string

# 0.2.0
## Added
- OP.md with settings examples for multiple OIDC Providers
## Fixed
- Management commands were not included in the package

# 0.1.0
Initialize library

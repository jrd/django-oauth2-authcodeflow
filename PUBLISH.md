New version
===========

To automatically create a new version, you can use the following sequences:

```
make bump_version what=minor
make build
```

Don't forget to commit and push before releasing.

Upload to PyPI
==============

Upload to test repository
-------------------------

Create a account on https://test.pypi.org

Upload the packages to the test repository:

```
make test_upload
```

Upload to official repository
-----------------------------

Create a account https://pypi.org (the account is not shared with the test repository)

Upload the packages to the repository:

```
make pypi_upload
```


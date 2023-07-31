New version
===========

To automatically create a new version, you can use the following sequences:

```
make bump_version what=minor
make merge_changelogs
```

- commit
- create tag
- push

Upload to PyPI
==============

Upload to test repository
-------------------------

Create a account on https://test.pypi.org

Upload the packages to the test repository:

```
make build
poetry publish -r testPyPI -u __token__ -p your_token
```

Upload to official repository
-----------------------------

Create a account https://pypi.org (the account is not shared with the test repository)

Upload the packages to the repository:

```
make build
poetry publish -u __token__ -p your_token
```


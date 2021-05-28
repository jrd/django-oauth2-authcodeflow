.PHONY: default clean venv project bump_version build twine test_upload pypi_upload

default:
	@echo "make TARGET"
	@echo ""
	@echo "TARGETS:"
	@echo "  clean: delete all generated files"
	@echo "  project: create a fake project"
	@echo "  bump_version: use the 'what' variable to define what to bump: major, minor or patch"
	@echo "  build: create source and wheel packages"
	@echo "  test_upload: build and upload packages to testpypi (always do this first)"
	@echo "  pypi_upload: build and upload packages to pypi"

clean:
	@rm -rf build dist src/*.egg-info 2>/dev/null
	@find src -type d -name __pycache__ -prune -exec rm -rf '{}' \;

venv:
	@if [ -z "$$VIRTUAL_ENV" ]; then \
	    echo "You should activate the virtualenv: pipenv shell" >&2; \
	    exit 1; \
	fi

project: venv
	@django-admin startproject project && \
	cd project && \
	ln -s ../src/oauth2_authcodeflow ./ && \
	sed -ri "/^INSTALLED_APPS/,/^\]/s/^\]/    'oauth2_authcodeflow',\n&/" project/settings.py && \
	echo project created

bump_version: venv
	@if ! echo "$(what)" | grep -q '^major\|minor\|patch$$'; then \
	    echo "You should specify 'what' variable with one of major, minor or patch" >&2; \
	    exit 1; \
	fi; \
	VER_MODULE="$$(sed -rn '/^version =/{s/.* attr: (.*)/\1/p}' setup.cfg | rev | cut -d. -f2- | rev)"; \
	VER_VAR="$$(sed -rn '/^version =/{s/.* attr: (.*)/\1/p}' setup.cfg | rev | cut -d. -f1 | rev)"; \
	NEW_VER="$$(python -c 'from src.'$${VER_MODULE}' import '$${VER_VAR}'; from semver import parse_version_info; print(parse_version_info(__version__).bump_$(what)())')"; \
	OLD_VER="$$(sed -rn "/^$${VER_VAR} =/s/.*'(.*)'/\1/p" src/$${VER_MODULE}/__init__.py)"; \
	echo "$${OLD_VER} → $${NEW_VER}"; \
	sed -ri "/^$${VER_VAR} =/s/'.*'/'$${NEW_VER}'/" src/$${VER_MODULE}/__init__.py

build: clean venv
	python setup.py sdist bdist_wheel

twine: venv
	@pip freeze | grep -q ^twine= >/dev/null || pip install twine

test_upload: build twine
	python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

pypi_upload: build twine
	python -m twine upload dist/*

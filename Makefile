.PHONY: default clean project bump_version build test_upload pypi_upload

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
	@rm -rf build dist *.egg-info 2>/dev/null
	@find . -type d -name __pycache__ -prune -exec rm -rf '{}' \;

project:
	@poetry run python -m django startproject project && \
	cd project && \
	ln -s ../oauth2_authcodeflow ./ && \
	sed -ri "/^INSTALLED_APPS/,/^\]/s/^\]/    'oauth2_authcodeflow',\n&/" project/settings.py && \
	echo project created

bump_version:
	@if echo "$(what)" | grep -Evq '^major|minor|patch$$'; then \
		echo "You should specify 'what' variable with one of major, minor or patch" >&2; \
		exit 1; \
	fi; \
	poetry version $(what)

build: clean
	@poetry build

test_upload: build
	@poetry publish -r testpypi

pypi_upload: build
	@poetry publish

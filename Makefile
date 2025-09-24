.PHONY: help \
	clean \
	install_dev_deps \
	install_prod_deps \
	install_all_deps \
	linter \
	type \
	tests \
	version \
	bump_version \
	merge_changelogs \
	project \
	build
SHELL:=/bin/bash -eo pipefail -c
# poetry is still <2.0 on python 3.8
POETRY_INSTALL := $(shell \
  if poetry --no-ansi --version | grep -q 'version 1'; then \
    echo "poetry install --sync"; \
  else \
    echo "poetry sync"; \
  fi)
changelog_dir:=_CHANGELOGS
changelog_ext:=md

help:
	@echo "make TARGET"
	@echo ""
	@echo "TARGETS:"
	@echo "  clean: delete all generated files"
	@echo "  install_dev_deps: only install developpement and typing dependencies"
	@echo "  install_prod_deps: only install production dependencies"
	@echo "  install_all_deps: install all dependencies"
	@echo "  linter: run linter on source code"
	@echo "  type: run type checker on source code"
	@echo "  tests: run unit tests"
	@echo "  version: just show current version"
	@echo "  bump_version: use the 'what' variable to define what to bump: major, minor or patch"
	@echo "  merge_changelogs: merge $(changelog_dir)/*/*.$(changelog_ext) into CHANGELOG.md file"
	@echo "  project: create a fake project"
	@echo "  build: create source and wheel packages"

clean:
	@rm -rf build dist reports *.egg-info 2>/dev/null
	@find . -type d -name __pycache__ -prune -exec rm -rf '{}' \;

install_dev_deps:
	@$(POETRY_INSTALL) -n --no-root --only=dev,typing

install_prod_deps:
	@$(POETRY_INSTALL) -n --no-root --only=main

install_all_deps:
	@$(POETRY_INSTALL) -n --no-root

reports:
	@mkdir -p reports

linter: reports
	@poetry run flake8 --tee --output-file reports/flake8.log

type: reports
	@poetry run mypy . | tee reports/mypy.log

tests: reports
	@# pytest exit with error code 5 if there is no tests, which is fine
	@set +e; poetry run pytest --log-file reports/pytest.log; ret=$$?; [ $$ret = 5 ] && ret=0; exit $$ret

version:
	@poetry version -s

bump_version:
	@if echo "$(what)" | grep -Evq '^major|minor|patch$$'; then \
		echo "You should specify 'what' variable with one of major, minor or patch" >&2; \
		exit 1; \
	fi; \
	poetry version $(what)

merge_changelogs:
	@./.gitlab/merge_changelogs

project:
	@poetry run python -m django startproject project && \
	cd project && \
	ln -s ../oauth2_authcodeflow ./ && \
	sed -ri "/^INSTALLED_APPS/,/^\]/s/^\]/    'oauth2_authcodeflow',\n&/" project/settings.py && \
	echo project created

build: clean
	@poetry build

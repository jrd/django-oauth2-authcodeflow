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
	@rm -rf build dist *.egg-info 2>/dev/null
	@find . -type d -name __pycache__ -prune -exec rm -rf '{}' \;

venv:
	@if [ -z "$$VIRTUAL_ENV" ]; then \
	    echo "You should activate the virtualenv: pipenv shell" >&2; \
	    exit 1; \
	fi

project: venv
	@django-admin startproject project && \
	cd project && \
	ln -s ../oauth2_authcodeflow ./ && \
	sed -ri "/^INSTALLED_APPS/,/^\]/s/^\]/    'oauth2_authcodeflow',\n&/" project/settings.py && \
	echo project created

bump_version: venv
	@printf "\
	from sys import argv, stderr, exit\n\
	from configparser import ConfigParser, NoOptionError\n\
	from semver import parse_version_info\n\
	from io import StringIO\n\
	from re import sub\n\
	\n\
	what = next(iter(argv[1:]), None)\n\
	if what not in ('major', 'minor', 'patch'):\n\
		print(\"You should specify 'what' variable with one of major, minor or patch\", file=stderr)\n\
		exit(1)\n\
	config = ConfigParser()\n\
	config.read('setup.cfg')\n\
	try:\n\
		version = config.get('metadata', 'version')\n\
	except NoOptionError:\n\
		version = ''\n\
	new_version = getattr(parse_version_info(version), f'bump_{what}')()\n\
	print(f\"{version} -> {new_version}\")\n\
	config.set('metadata', 'version', str(new_version))\n\
	sio = StringIO()\n\
	config.write(sio)\n\
	with open('setup.cfg', 'w') as f:\n\
		f.write(sub(r'\s+\\\\n', '\\\\n', sio.getvalue()))\n\
	" | python - $(what)

build: clean venv
	python setup.py sdist bdist_wheel

twine: venv
	@pip freeze | grep -q ^twine= >/dev/null || pip install twine

test_upload: build twine
	python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

pypi_upload: build twine
	python -m twine upload dist/*

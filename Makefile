# Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
# SPDX-License-Identifier: LGPL-2.1+

VENV=./env
PYTHON=$(VENV)/bin/python
PYTEST=$(VENV)/bin/pytest
PYLINT=$(VENV)/bin/pylint
MYPY=$(VENV)/bin/mypy
CODESPELL=$(VENV)/bin/codespell
PIP=$(VENV)/bin/pip
BLACK=$(VENV)/bin/black
STUBGEN=$(VENV)/bin/stubgen

setup: requirements.txt
	virtualenv ./env
	$(VENV)/bin/pip install -r requirements.txt
	$(VENV)/bin/pip install pre-commit
	$(VENV)/bin/pre-commit install

clean:
	rm -rf ./build
	rm -rf ./htmlcov

$(PYTEST):
	$(PIP) install pytest-cov pylint

$(MYPY):
	$(PIP) install mypy

$(STUBGEN):
	$(PIP) install stubgen

$(BLACK):
	$(PIP) install black

check: $(PYTEST) $(MYPY)
	$(MYPY) uswid
	$(PYTEST) uswid
	$(PYLINT) --rcfile pylintrc uswid/*.py *.py

blacken: $(BLACK)
	find uswid -name '*.py' -exec $(BLACK) {} \;

pkg: $(STUBGEN)
	$(STUBGEN) --output . --package uswid
	$(PYTHON) setup.py sdist bdist_wheel

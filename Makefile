# Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
# SPDX-License-Identifier: BSD-2-Clause-Patent

VENV=./env
PYTHON=$(VENV)/bin/python
PYTEST=$(VENV)/bin/pytest
PYLINT=$(VENV)/bin/pylint
MYPY=$(VENV)/bin/mypy
CODESPELL=$(VENV)/bin/codespell
PIP=$(VENV)/bin/pip
BLACK=$(VENV)/bin/black
STUBGEN=$(VENV)/bin/stubgen
SPHINX_BUILD=$(VENV)/bin/sphinx-build
RUFF=$(VENV)/bin/ruff

setup: requirements.txt
	virtualenv ./env
	$(VENV)/bin/pip install -r requirements.txt
	$(VENV)/bin/pip install pre-commit
	$(VENV)/bin/pre-commit install

clean:
	rm -rf ./build
	rm -rf ./htmlcov
	rm -rf ./docs/build

$(PYTEST):
	$(PIP) install pytest-cov pylint

$(MYPY):
	$(PIP) install mypy

$(STUBGEN):
	$(PIP) install stubgen

$(BLACK):
	$(PIP) install black

$(RUFF):
	$(PIP) install ruff

$(SPHINX_BUILD):
	$(PIP) install sphinx sphinx_autodoc_typehints sphinx_rtd_theme

check: $(PYTEST) $(MYPY)
	$(MYPY) --check-untyped-defs uswid
	$(PYTEST) uswid
	$(PYLINT) --rcfile pylintrc uswid/*.py *.py

install:
	$(VENV)/bin/pip install .

blacken: $(BLACK)
	find uswid -name '*.py' -exec $(BLACK) {} \;

codespell: $(CODESPELL)
	$(CODESPELL) --write-changes --builtin en-GB_to_en-US --skip \
	.git,\
	.mypy_cache,\
	.coverage,\
	*.pyc,\
	env

ruff: $(RUFF)
	$(RUFF) check uswid examples

pkg: $(STUBGEN)
	$(STUBGEN) --output . --package uswid
	$(PYTHON) setup.py sdist bdist_wheel

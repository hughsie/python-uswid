# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
import subprocess

sys.path.insert(0, os.path.abspath("../.."))


project = "python-uswid"
copyright = "2021, Richard Hughes"
author = "Richard Hughes"

# full version, including alpha/beta/rc tags
try:
    release = subprocess.check_output(
        ["git", "describe"], stderr=subprocess.DEVNULL
    ).decode("utf-8")
except (subprocess.CalledProcessError, PermissionError, FileNotFoundError):
    release = ""
master_doc = "index"
html_copy_source = False
html_show_sphinx = False
extensions = ["sphinx.ext.autodoc"]
templates_path = ["_templates"]
exclude_patterns = []
html_theme = "alabaster"
html_static_path = ["_static"]

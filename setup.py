#!/usr/bin/env python

from setuptools import setup

# note: this is a repeat of the README, to evolve, good enough for now.
long_desc = """
Contributors welcome, either adding new functionality or fixing bugs.
"""

setup(
    name="uswid",
    version="0.5.1",
    license="BSD-2-Clause-Patent",
    license_files=[
        "LICENSE",
    ],
    description="A pure-python library for embedding CoSWID data",
    long_description=long_desc,
    author="Richard Hughes",
    author_email="richard@hughsie.com",
    url="https://github.com/hughsie/python-uswid",
    packages=[
        "uswid",
    ],
    include_package_data=True,
    install_requires=[
        "cbor2",
        "lxml",
        "pefile",
        "importlib-metadata >= 1.0 ; python_version < '3.8'",
    ],
    entry_points={
        "console_scripts": [
            "uswid = uswid.cli:main",
        ]
    },
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Topic :: Utilities",
        "Topic :: System :: Archiving",
    ],
    keywords=["swid", "sbom", "coswid"],
    package_data={
        "uswid": [
            "py.typed",
            "entity.pyi",
            "enums.pyi",
            "errors.pyi",
            "format_coswid.pyi",
            "format_cyclonedx.pyi",
            "format_goswid.pyi",
            "format_ini.pyi",
            "format.pyi",
            "format_spdx.pyi",
            "format_swid.pyi",
            "format_uswid.pyi",
            "format_pe.pyi",
            "hash.pyi",
            "payload.pyi",
            "purl.pyi",
            "evidence.pyi",
            "component.pyi",
            "container.pyi",
            "container_utils.pyi",
            "link.pyi",
            "problem.pyi",
            "vcs.pyi",
            "vex_document.pyi",
            "vex_product.pyi",
            "vex_statement.pyi",
            "__init__.pyi",
        ]
    },
    setup_requires=["wheel"],
)

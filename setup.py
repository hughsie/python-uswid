#!/usr/bin/env python

from setuptools import setup

# note: this is a repeat of the README, to evolve, good enough for now.
long_desc = """
Contributors welcome, either adding new functionality or fixing bugs.
"""

setup(
    name="uswid",
    version="0.2.0",
    license="LGPL-2.1-or-later",
    description="A pure-python library for embedding CoSWID data",
    long_description=long_desc,
    author="Richard Hughes",
    author_email="richard@hughsie.com",
    url="https://github.com/hughsie/python-uswid",
    packages=[
        "uswid",
    ],
    include_package_data=True,
    install_requires=["cbor", "lxml", "pefile"],
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
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
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
            "identity.pyi",
            "link.pyi",
            "__init__.pyi",
        ]
    },
)

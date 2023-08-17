#!/usr/bin/env python
# import pytest
import re
import sys
import os
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

rootdir = os.path.abspath(os.path.dirname(__file__))
name = open(os.path.join(rootdir, 'NAME')).read().strip()
version = open(os.path.join(rootdir, 'VERSION')).read().strip()
#long_description = open(os.path.join(rootdir, 'README.md')).read()
long_description = "food Integrations"

setup(
    name=name,
    packages=find_packages(),
    version=version,
    description=long_description,
    long_description=long_description,
    author='Jitendra Chauhan',
    author_email='jitendra.chauhan@xxxxx.com',
    url="",
    include_package_data=True,
    #    python_requires='>=2.7,>=3.5,<4.0',
    install_requires=[
        "google-cloud-storage",
        "google-cloud-pubsub>=2.0",
        "knowledge-graph==3.12.0",
        "statistics"
    ],
    setup_requires=[],
    tests_require=["mock"],
    # cmdclass={'test': PyTest},
)

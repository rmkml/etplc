#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

__title__ = "etplc"
__summary__ = "E.T. Proxy Logs Checker"
__uri__ = "https://github.com/rmkml/etplc"

__version__ = "0.6"

__author__ = "rmkml"
__email__ = "rmkml@yahoo.fr"

__license__ = "GNU General Public License"
__copyright__ = "Copyright 2014 %s" % __author__


with open('README.md') as f:
    long_description = f.read()

setup(
    name=__title__,
    version=__version__,
    description=__summary__,
    long_description=long_description,
    url=__uri__,
    author=__author__,
    author_email=__email__,
    license=__license__,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='log analysis',
    packages=["etplc"],
    package_data={
        'etplc': ['rules/*.rules']
    },
    install_requires=['regex'],
    entry_points={
        'console_scripts': [
            'etplc=etplc.etplc:main',
        ],
    },
)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Code based on https://github.com/robotattackorg/robot-detect/blob/master/setup.py:
# > Detection and proof of concept for the ROBOT attack
# > https://robotattack.org/
# > 
# > This code is licensed as CC0.

from setuptools import setup, find_packages

package_name = 'legacy_attack'

readme = """
legacy_attack
============

Tool to detect and run the Reverse-Bleichenbacher attack.
"""

VERSION = 0.1

setup(
    name=package_name,
    version=VERSION,
    description="",
    long_description=readme,
    author="Youheng Lü",
    author_email='mail@ylue.de',
    package_dir={'legacy_attack': '.'},
    packages=['legacy_attack'],
    scripts=[],
    python_requires='>=3',
    install_requires=[],
    license="CC0",
    zip_safe=True,
    keywords=['tls', 'bleichenbacher', 'security', 'vulnerability'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: ',
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
        'Natural Language :: English',
        'Programming Language :: Python :: 3'
    ],
)

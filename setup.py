#!/usr/bin/env python3

from distutils.core import setup

setup(
    name='encx_vault',
    version='0.2.0',
    description='Extension to Encx that adds a client for the encx vault server',
    author='KJ',
    author_email='<redacted>',
    url='https://github.com/jdotpy/encx_vault',
    packages=[
        'encx_vault',
    ],
    install_requires=[
        'requests',
    ],
)

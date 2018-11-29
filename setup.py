#
# Copyright (c) 2017, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

from setuptools import setup
from setuptools import find_packages

setup(
    name='flask_saml_sso',
    version='0.2.0',
    description='',
    author='Magenta ApS',
    author_email='info@magenta.dk',
    license="MPL 2.0",
    packages=find_packages(exclude=['tests']),
    package_data={
        '': ["*.txt", "*.xml"]
    },
    zip_safe=False,
    install_requires=[
        "python3-saml~=1.4.1",
        "flask~=1.0.2",
        "Flask-Session~=0.3.1",
        "requests~=2.20.0",
        "Flask-SQLAlchemy~=2.3.2",
        "itsdangerous<1.0.0"

    ],
    tests_require=[
        'Flask-Testing',
        'freezegun',
    ]
)

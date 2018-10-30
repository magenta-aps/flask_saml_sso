#!/bin/bash -e

cd $(dirname $0)

# Virtualenv / Python
TEST_ENV=python-testenv
PYTHON=${TEST_ENV}/bin/python

# Create virtualenv
python3 -m venv $TEST_ENV

$PYTHON -m pip install .
$PYTHON -m pip install -r requirements-test.txt
$PYTHON -m pytest


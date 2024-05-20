#!/usr/bin/env python3
import os
import sys

from setuptools import setup, find_packages
__version__      = '0.6.5'
__package_name__ = 'pymrtd'
__summery__ = 'Python implementation of ICAO 9303 MRTD standard aka Biometric Passport'

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

setup(
    name=__package_name__,
    description=__summery__,
    version=__version__,
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    python_requires=">=3.9.11",
    install_requires=[
        'asn1crypto>=1.5.1',
        'cryptography==42.0.4'
    ],
    extras_require={
        'tests': [
            'pytest>=7.1.0',
            'pytest-depends>=1.0.1',
            'pytest-datafiles>=2.0.0'
        ],
    },
    setup_requires=['pytest-runner'],
    tests_require=['pytest>=7.1.0'],
    test_suite='tests',
)

#!/usr/bin/env python3
import os
import platform
import sys

from setuptools import setup, find_packages

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
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
          'asn1crypto>=1.4.0',
          'cryptography>=3.4.7'
      ],
    extras_require={
        "test": [
            "pytest>=6.2.4",
        ],
    }
)
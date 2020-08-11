# -*- coding: utf-8 -*-
"""Setup configuration."""
from setuptools import find_packages
from setuptools import setup


setup(
    name="change_this_to_name_of_package",
    version="0.1",
    description="CREATE A DESCRIPTION",
    url="https://github.com/CuriBio/CHANGE_THIS_TO_NAME_OF_REPO",
    author="Curi Bio",
    author_email="contact@curibio.com",
    license="MIT",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=[],
)

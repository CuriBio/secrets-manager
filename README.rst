After creating a copy of this template, change the name of the package in `setup.py`, `pytest.ini`, `MANIFEST.in`, `codebuild_formation.yaml` and the subfolder within the `src` directory.
Before CodeBuild can automatically publish to PyPI, the package must be registered using command `twine register`: https://twine.readthedocs.io/en/latest/#twine-register

.. image:: https://github.com/CuriBio/python-github-template/workflows/Dev/badge.svg?branch=development
   :alt: Development Branch Build

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. image:: https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white
   :target: https://github.com/pre-commit/pre-commit
   :alt: pre-commit

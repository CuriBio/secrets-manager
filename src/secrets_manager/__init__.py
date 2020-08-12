# -*- coding: utf-8 -*-
"""Manages access to secrets through various sources."""
from .constants import AWS_PARAM_STORE_PATH_KEY_NAME
from .exceptions import NoAwsParameterStorePathError
from .exceptions import NoConnectedBotoSessionError
from .exceptions import SecretNotFoundInAwsParameterStoreError
from .exceptions import SecretNotFoundInVaultError
from .exceptions import UnrecognizedVaultDeploymentTierError
from .secrets_manager import generate_resource_prefix_from_deployment_tier
from .secrets_manager import remove_invalid_resource_name_charaters
from .secrets_manager import Vault
from .warnings import KebabCaseSecretNameWarning

__all__ = [
    "Vault",
    "remove_invalid_resource_name_charaters",
    "generate_resource_prefix_from_deployment_tier",
    "UnrecognizedVaultDeploymentTierError",
    "SecretNotFoundInVaultError",
    "NoConnectedBotoSessionError",
    "NoAwsParameterStorePathError",
    "SecretNotFoundInAwsParameterStoreError",
    "AWS_PARAM_STORE_PATH_KEY_NAME",
    "KebabCaseSecretNameWarning",
]

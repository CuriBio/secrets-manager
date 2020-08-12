# -*- coding: utf-8 -*-
"""Manage access to secrets in an application."""
from .constants import AWS_PARAM_STORE_PATH_KEY_NAME


class UnrecognizedVaultDeploymentTierError(Exception):
    def __init__(self, deployment_tier: str):
        super().__init__(
            f"The vault deployment_tier '{deployment_tier}' is not recognized."
        )


class SecretNotFoundInVaultError(Exception):
    def __init__(self, secret_name: str):
        super().__init__(
            f"The secret '{secret_name}' was not found in any vault source."
        )


class SecretNotFoundInLocalSourcesError(Exception):
    def __init__(self, secret_name: str):
        super().__init__(
            f"The secret '{secret_name}' was not found in any local vault source."
        )


class SecretNotFoundInAwsParameterStoreError(Exception):
    def __init__(self, secret_name: str):
        super().__init__(
            f"The secret '{secret_name}' was not found in the AWS Parameter Store."
        )


class NoConnectedBotoSessionError(Exception):
    def __init__(self, secret_name: str):
        super().__init__(
            f"There is no boto3 session connected to the vault to allow searching the AWS Parameter Store for the secret '{secret_name}'. Use the set_boto_session method to supply it."
        )


class NoAwsParameterStorePathError(Exception):
    def __init__(self, secret_name: str):
        super().__init__(
            f"There is no path provided in a local secret to use to search the AWS parameter store. It must be available as a secret called '{AWS_PARAM_STORE_PATH_KEY_NAME}' (prefixed for appropriate deployment tier). Because it was missing, the AWS Parameter store was not able to be searched for the secret '{secret_name}'."
        )

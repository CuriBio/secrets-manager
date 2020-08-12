# -*- coding: utf-8 -*-
"""Manage access to secrets in an application."""
import datetime
import json
import os
import socket
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union
import warnings

from .constants import AWS_PARAM_STORE_PATH_KEY_NAME
from .exceptions import NoAwsParameterStorePathError
from .exceptions import NoConnectedBotoSessionError
from .exceptions import SecretNotFoundInAwsParameterStoreError
from .exceptions import SecretNotFoundInLocalSourcesError
from .exceptions import SecretNotFoundInVaultError
from .exceptions import UnrecognizedVaultDeploymentTierError
from .warnings import KebabCaseSecretNameWarning


def _check_for_kebab_case(secret_name: str) -> None:
    if "-" in secret_name:
        warnings.warn(
            f"The secret '{secret_name}' should not be kebab case as environmental variables can only be snake case. Use {str(secret_name).replace('-', '_')} instead",
            KebabCaseSecretNameWarning,
        )


def _convert_special_annotations(value: str) -> str:
    for this_annotation, this_replacement in (
        ("CONVERTTOSINGLEQUOTE", "'"),
        ("CONVERTTOSPACE", " "),
        ("CONVERTTODOUBLEQUOTE", '"'),
        ("CONVERTTOHYPHEN", "-"),
        ("CONVERTTOLESSTHAN", "<"),
        ("CONVERTTOGREATERTHAN", ">"),
        ("CONVERTTOFORWARDSLASH", "/"),
        ("CONVERTTOBACKSLASH", "\\"),
        ("CONVERTTOPERIOD", "."),
        ("CONVERTTOSEMICOLON", ";"),
        ("CONVERTTOCOLON", ":"),
    ):
        value = value.replace(this_annotation, this_replacement)
    return value


def load_json_file(file_name: str) -> Dict[str, Any]:
    with open(file_name) as json_file:
        data: Dict[str, Any] = json.load(json_file)
    return data


def remove_invalid_resource_name_charaters(  # pylint: disable=invalid-name
    str_to_process: str,
) -> str:
    """Remove characters that would be invalid in certain cases (e.g. DNS)."""
    remove_these_chars = ["'", '"', "%", "$", "`"]
    out_str = ""

    for this_char in str_to_process:
        if this_char in remove_these_chars:
            continue
        if this_char in [" ", "-"]:
            out_str += "_"
            continue
        out_str += this_char

    return out_str


def generate_resource_prefix_from_deployment_tier(  # pylint: disable=invalid-name
    deployment_tier: str,
) -> str:
    """Append the appropriate prefix to a resource name."""
    if deployment_tier in ("prod", "production"):
        return ""
    now = datetime.datetime.utcnow()
    hostname = remove_invalid_resource_name_charaters(socket.gethostname()).lower()
    max_hostname_length = 5
    if len(hostname) > max_hostname_length:
        hostname = hostname[:max_hostname_length]
    resource_prefix = f"zztest_{hostname}_{now.strftime('%y%m%d%H%M%S')}_"
    return resource_prefix


def get_deployment_tier_prefix(deployment_tier: str) -> str:

    if deployment_tier in ("test", "testing"):
        return "test_"
    if deployment_tier in ("prod", "production"):
        return "prod_"
    raise UnrecognizedVaultDeploymentTierError(deployment_tier)


def _prepend_specific_deployment_tier(stub: str, deployment_tier: str) -> str:
    return "%s%s" % (get_deployment_tier_prefix(deployment_tier), stub)


class Vault:
    """Manages access to secrets through various sources.

    First searches any internal secrets specifically set in the vault
    after instantiation. Then searches the environmental variables, then
    specified JSON-formatted files (if supplied during init).

    If a boto3 AWS session has been supplied, and there is a secret configured called 'aws_parameter_store_prefix', then that prefix will be checked (after other checks) to see if the desired secret exists there.
    """

    def __init__(
        self,
        deployment_tier: str = "test",
        search_environment_first: bool = True,
        files_to_search: Optional[List[str]] = None,
    ):
        if files_to_search is None:
            files_to_search = list()
        self._files_to_search = files_to_search
        self._search_environment_first = search_environment_first
        self._validate_and_assign_deployment_tier(deployment_tier)
        self._internal_secrets: Dict[str, Union[str, float, int]] = dict()

        self._boto_session: Optional[str] = None  # an AWS boto3 session

    def set_boto_session(self, session: str) -> None:
        """Set a boto3 AWS session.

        This boto3 connection will be used to obtain values from the AWS parameter store.

        There is no type hint because this package does not actually import boto3 (to lighten dependencies).  The session can just be injected by code using this package that has imported boto3.
        """
        self._boto_session = session

    def get_boto_session(self) -> object:
        return self._boto_session

    def get_deployment_tier(self) -> str:
        return self._deployment_tier

    def _validate_and_assign_deployment_tier(self, deployment_tier: str) -> None:
        if deployment_tier == "testing":
            deployment_tier = "test"
        elif deployment_tier == "production":
            deployment_tier = "prod"
        self._deployment_tier = deployment_tier
        if deployment_tier in ["test", "prod"]:
            return
        raise UnrecognizedVaultDeploymentTierError(deployment_tier)

    def set_internal_secret_for_specific_deployment_tier(
        self,
        secret_name: str,
        secret_value: Union[str, int, float],
        deployment_tier: str,
    ) -> None:
        secret_name = _prepend_specific_deployment_tier(secret_name, deployment_tier)
        self.set_internal_secret(
            secret_name, secret_value, prepend_deployment_tier=False
        )

    def set_internal_secret(
        self,
        secret_name: str,
        secret_value: Union[str, int, float],
        prepend_deployment_tier: bool = True,
    ) -> None:
        _check_for_kebab_case(secret_name)
        if prepend_deployment_tier:
            secret_name = self._prepend_deployment_tier(secret_name)
        self._internal_secrets[secret_name] = secret_value

    def _prepend_deployment_tier(self, stub: str) -> str:
        return _prepend_specific_deployment_tier(stub, self.get_deployment_tier())

    def _search_through_local_sources_and_find_secret(
        self, complete_secret_name: str
    ) -> Union[str, int, float]:
        """Search through sources and find a secret.

        Args:
            complete_secret_name: should already be prefixed with the deployment tier
        """
        name = complete_secret_name
        secret = None  # initialize
        if name in self._internal_secrets:
            return self._internal_secrets[name]

        if self._search_environment_first:
            secret = os.environ.get(name)
            if secret is not None:
                return secret
        for this_file_name in self._files_to_search:
            if os.path.exists(this_file_name):
                json_data = load_json_file(this_file_name)
                if name in json_data:
                    secret = json_data[name]
                    assert (  # nosec  needed for mypy  -- apparently json can optionally have None as a value
                        secret is not None
                    )
                    return secret
        secret = os.environ.get(name)
        if secret is not None:
            return secret

        raise SecretNotFoundInLocalSourcesError(name)

    def search_aws_param_store_for_secret(
        self, complete_secret_name: str
    ) -> Union[str, int, float]:
        """Search for the secret in the AWS Parameter Store.

        Uses a boto3 session to search a specific path in the AWS
        Parameter Store for the supplied secret.
        """
        boto_session = self.get_boto_session()
        if boto_session is None:
            raise NoConnectedBotoSessionError(complete_secret_name)
        param_store_prefix_secret_name = _prepend_specific_deployment_tier(
            AWS_PARAM_STORE_PATH_KEY_NAME, self.get_deployment_tier()
        )
        try:
            param_store_prefix = self._search_through_local_sources_and_find_secret(
                param_store_prefix_secret_name
            )
        except SecretNotFoundInLocalSourcesError:
            raise NoAwsParameterStorePathError(complete_secret_name)

        full_aws_path = f"{param_store_prefix}{complete_secret_name}"

        ssm_client = boto_session.client("ssm")  # type: ignore # the boto3 session is being injected, so we lose the ability to do type checking
        try:
            response = ssm_client.get_parameter(Name=full_aws_path, WithDecryption=True)
        except Exception as e:
            if str(type(e)) == "<class 'botocore.errorfactory.ParameterNotFound'>":
                raise SecretNotFoundInAwsParameterStoreError(complete_secret_name)
            raise e
        response_param_val: Union[str, int, float] = response["Parameter"]["Value"]
        return response_param_val

    def _search_through_sources_and_find_secret(
        self, complete_secret_name: str
    ) -> Union[str, int, float]:

        try:
            return self._search_through_local_sources_and_find_secret(
                complete_secret_name
            )
        except SecretNotFoundInLocalSourcesError:
            pass

        # check AWS param store
        try:
            return self.search_aws_param_store_for_secret(complete_secret_name)
        except (SecretNotFoundInAwsParameterStoreError, NoConnectedBotoSessionError):
            pass

        raise SecretNotFoundInVaultError(complete_secret_name)

    def get_secret_for_specific_deployment_tier(
        self, name: str, deployment_tier: str
    ) -> Union[str, int, float]:
        """Obtain the secret for a specific deployment tier."""
        _check_for_kebab_case(name)
        full_secret_name = _prepend_specific_deployment_tier(name, deployment_tier)

        value = self._search_through_sources_and_find_secret(full_secret_name)
        if isinstance(value, str):
            value = _convert_special_annotations(value)
        return value

    def get_secret(self, name: str) -> Union[str, int, float]:
        return self.get_secret_for_specific_deployment_tier(
            name, self.get_deployment_tier()
        )

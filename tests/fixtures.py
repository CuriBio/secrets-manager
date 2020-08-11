# -*- coding: utf-8 -*-
import inspect
import os

from boto3.session import Session
import pytest
from secrets_manager import AWS_PARAM_STORE_PATH_KEY_NAME
from secrets_manager import generate_resource_prefix_from_deployment_tier
from secrets_manager import Vault

PATH_OF_CURRENT_FILE = os.path.dirname((inspect.stack()[0][1]))


@pytest.fixture(scope="function", name="vault_for_param_store")
def fixture_vault_for_param_store():
    param_store_prefix = "/CodeBuild/secrets_manager/"
    vault = Vault(files_to_search=[os.path.join(PATH_OF_CURRENT_FILE, "secrets.json")])
    vault.set_internal_secret(AWS_PARAM_STORE_PATH_KEY_NAME, param_store_prefix)
    session = Session(
        aws_access_key_id=vault.get_secret("aws_root_access_key"),
        aws_secret_access_key=vault.get_secret("aws_root_secret_key"),
        region_name=vault.get_secret("aws_root_region"),
    )
    vault.set_boto_session(session)
    yield vault, param_store_prefix


@pytest.fixture(scope="function", name="ssm_param")
def fixture_ssm_param(vault_for_param_store):
    """Create this as a fixture so it is deleted even if test fails."""
    expected_secret_value = "my-encrypted-parameter"
    prefix = generate_resource_prefix_from_deployment_tier("testing")
    secret_name = f"{prefix}ssm_param"
    vault, param_store_prefix = vault_for_param_store
    # param_store_prefix = "/CodeBuild/secrets_manager/"
    param_name = f"{param_store_prefix}testing_{secret_name}"

    session = vault.get_boto_session()
    ssm_client = session.client("ssm")
    ssm_client.put_parameter(
        Name=param_name,
        Value=expected_secret_value,
        Type="SecureString",
        Overwrite=False,
        Tier="Standard",
    )
    yield vault, secret_name, expected_secret_value

    # clean up
    ssm_client.delete_parameter(Name=param_name)

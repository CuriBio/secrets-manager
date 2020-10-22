# -*- coding: utf-8 -*-
import datetime
import os

from boto3.session import Session
import pytest
from secrets_manager import AWS_PARAM_STORE_PATH_KEY_NAME
from secrets_manager import generate_resource_prefix_from_deployment_tier
from secrets_manager import Vault
from stdlib_utils import get_current_file_abs_directory


PATH_OF_CURRENT_FILE = get_current_file_abs_directory()


@pytest.fixture(scope="function", name="vault_for_param_store")
def fixture_vault_for_param_store():
    param_store_prefix = "/CodeBuild/secrets-manager/"
    vault = Vault(files_to_search=[os.path.join(PATH_OF_CURRENT_FILE, "secrets.json")])
    vault.set_internal_secret(AWS_PARAM_STORE_PATH_KEY_NAME, param_store_prefix)
    vault.set_internal_secret("int_secret", 1)
    vault.set_internal_secret("float_secret", 1.0)
    session = Session(
        aws_access_key_id=vault.get_secret("aws_ssm_access_key"),
        aws_secret_access_key=vault.get_secret("aws_ssm_secret_key"),
        region_name=vault.get_secret("aws_ssm_region"),
    )
    vault.set_boto_session(session)
    yield vault, param_store_prefix


@pytest.fixture(scope="function", name="ssm_param")
def fixture_ssm_param(vault_for_param_store):
    """Create this as a fixture so it is deleted even if test fails."""
    expected_secret_value = "my-encrypted-parameter"
    prefix = generate_resource_prefix_from_deployment_tier("test")
    secret_name = f"{prefix}ssm_param_{datetime.datetime.utcnow().strftime('%y%m%d%H%M%S%f')}"  # add a timestamp to avoid name conflicts when running parallel builds in CI
    vault, param_store_prefix = vault_for_param_store
    # param_store_prefix = "/CodeBuild/secrets_manager/"
    param_name = f"{param_store_prefix}test_{secret_name}"

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

# -*- coding: utf-8 -*-
import inspect
import os
import socket
from unittest.mock import call
import warnings

from freezegun import freeze_time
import pytest
from secrets_manager import generate_resource_prefix_from_deployment_tier
from secrets_manager import KebabCaseSecretNameWarning
from secrets_manager import NoAwsParameterStorePathError
from secrets_manager import NoConnectedBotoSessionError
from secrets_manager import remove_invalid_resource_name_charaters
from secrets_manager import SecretNotFoundInAwsParameterStoreError
from secrets_manager import SecretNotFoundInVaultError
from secrets_manager import secrets_manager
from secrets_manager import UnrecognizedVaultDeploymentTierError
from secrets_manager import Vault

from .fixtures import fixture_ssm_param
from .fixtures import fixture_vault_for_param_store

__fixtures__ = [fixture_ssm_param, fixture_vault_for_param_store]

PATH_OF_CURRENT_FILE = os.path.dirname((inspect.stack()[0][1]))


def test_vault__unrecognized_deployment_tier_raises_error():
    with pytest.raises(UnrecognizedVaultDeploymentTierError):
        Vault(deployment_tier="crazy")


def test_vault__returns_environmental_variable_for_test_mode(mocker):
    v = Vault()

    expected = "AOOEETHO"
    secret_name = "aws_s3_access_key"

    mocker.patch.dict(os.environ, {"test_%s" % secret_name: expected}, clear=True)
    actual = v.get_secret(secret_name)

    assert actual == expected


def test_vault__returns_environmental_variable_for_production_mode(mocker):
    v = Vault(deployment_tier="prod")

    expected = "hoet33293"
    secret_name = "mysql_db_name"
    mocker.patch("os.path.exists", autospec=True, return_value=True)
    mocker.patch.dict(os.environ, {"prod_%s" % secret_name: expected}, clear=True)
    actual = v.get_secret(secret_name)

    assert actual == expected


def test_vault__raises_error_if_secret_not_found(mocker):
    v = Vault()
    mocker.patch("builtins.open", mocker.mock_open(read_data="{}"))
    with pytest.raises(SecretNotFoundInVaultError):
        v.get_secret("crazy_thing")


def test_vault__returns_value_from_json_when_not_in_environ(mocker):
    v = Vault(files_to_search=["blah.json"])

    expected = "blah218"
    secret_name = "sql_user"
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data='{"test_%s":"%s"}' % (secret_name, expected)),
    )
    mocker.patch("os.path.exists", autospec=True, return_value=True)
    actual = v.get_secret(secret_name)
    assert actual == expected


def test_vault__returns_value_from_json_when_value_also_in_environment_if_json_specified_first(
    mocker,
):
    v = Vault(search_environment_first=False, files_to_search=["blad.json"])

    expected = "bestpasswordever"
    secret_name = "sql_password"
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data='{"test_%s":"%s"}' % (secret_name, expected)),
    )
    mocker.patch("os.path.exists", autospec=True, return_value=True)
    mocker.patch.dict(os.environ, {"test_%s" % secret_name: "not expected"}, clear=True)
    actual = v.get_secret(secret_name)
    assert actual == expected


def test_vault__returns_value_from_environment_if_json_specified_first(mocker):
    v = Vault(search_environment_first=False, files_to_search=["blad.json"])

    expected = "3306"
    secret_name = "sql_port"
    m = mocker.patch.object(secrets_manager, "load_json_file", return_value={})
    mocker.patch("os.path.exists", autospec=True, return_value=True)
    mocker.patch.dict(os.environ, {"test_%s" % secret_name: expected}, clear=True)
    actual = v.get_secret(secret_name)
    assert actual == expected
    m.assert_called_once_with("blad.json")


def test_vault__opens_all_json_files_specified(mocker):
    v = Vault(files_to_search=["file1.json", "file2.json"])
    mocker.patch("os.path.exists", autospec=True, return_value=True)
    m = mocker.patch.object(secrets_manager, "load_json_file", return_value={})
    with pytest.raises(SecretNotFoundInVaultError):
        v.get_secret("blah")
    m.assert_has_calls([call("file1.json"), call("file2.json")])


def test_vault__retrieves_value_from_internal_store__even_when_present_in_environment(
    mocker,
):
    v = Vault()
    secret_name = "very_secret"
    expected = "correct secret"
    mocker.patch.dict(os.environ, {"test_%s" % secret_name: "not correct"}, clear=True)

    v.set_internal_secret("%s" % secret_name, expected)

    actual = v.get_secret(secret_name)
    assert actual == expected


def test_Vault__set_internal_secret__prepends_deployment_tier_by_default():
    v = Vault()
    expected = "eli"
    v.set_internal_secret("username", expected)
    actual = v.get_secret("username")
    assert actual == expected


def test_Vault__does_not_raise_file_error_when_asked_to_search_file_that_does_not_exist():
    v = Vault(files_to_search=["blah.json"])
    with pytest.raises(SecretNotFoundInVaultError):
        v.get_secret("blah")


@pytest.mark.parametrize(
    "test_str,expected,test_description",
    [
        ("Eli's Work", "Elis_Work", "remove apostrophe and replace space"),
        ('Eli%`$"good', "Eligood", "remove misc chars"),
        ("Eli-work", "Eli_work", "replaces hyphen with space"),
    ],
)
def test_remove_invalid_resource_name_charaters__removes_apostrophes_and_replaces_spaces(
    test_str, expected, test_description
):
    actual = remove_invalid_resource_name_charaters(test_str)
    assert actual == expected


@freeze_time("2019-05-24 11:09:22", tz_offset=0)
@pytest.mark.parametrize(
    "hostname,environment,expected,test_description",
    [
        (
            "eli's work",
            "test",
            "zztest_elis__190524110922_",
            "remove apostrophe and replace space and truncate",
        ),
        (
            "Eli",
            "test",
            "zztest_eli_190524110922_",
            "converts to lower case and handles name shorter than truncation limit",
        ),
        ("Eli", "production", "", "production environment"),
    ],
)
def test_generate_resource_prefix_from_deployment_tier(
    hostname, environment, expected, test_description, mocker
):
    mocker.patch.object(socket, "gethostname", return_value=hostname)

    actual = generate_resource_prefix_from_deployment_tier(environment)
    assert actual == expected


def test_set_and_get_secret_for_specific_deployment_tier():
    v = Vault(deployment_tier="test")
    v.set_internal_secret("mykey", "test_value")
    v.set_internal_secret_for_specific_deployment_tier(
        "mykey", "prod_value", "production"
    )

    actual = v.get_secret_for_specific_deployment_tier("mykey", "production")
    assert actual == "prod_value"


def test_get_deployment_tier_prefix__raises_error_for_unknown_tier():
    with pytest.raises(UnrecognizedVaultDeploymentTierError):
        secrets_manager.get_deployment_tier_prefix("fake tier")


@pytest.mark.parametrize(
    "test_value,expected_value,test_description",
    [
        ("blahCONVERTTOSPACEblah", "blah blah", "convert to space"),
        ("blahCONVERTTOSINGLEQUOTEblah", "blah'blah", "convert to single quote"),
        (
            "blahCONVERTTOSPACEblahCONVERTTOSPACEsplat",
            "blah blah splat",
            "multiple spaces",
        ),
        ("blahCONVERTTODOUBLEQUOTEblah", 'blah"blah', "convert to double quote"),
        ("blahCONVERTTOHYPHENblah", "blah-blah", "convert to hyphen"),
        ("blahCONVERTTOLESSTHANblah", "blah<blah", "convert to less than"),
        ("blahCONVERTTOGREATERTHANblah", "blah>blah", "convert to greater than"),
        ("blahCONVERTTOFORWARDSLASHblah", "blah/blah", "convert to forward slash"),
        ("blahCONVERTTOBACKSLASHblah", "blah\\blah", "back slash"),
        ("blahCONVERTTOPERIODblah", "blah.blah", "period"),
        ("blahCONVERTTOSEMICOLONblah", "blah;blah", "semi-colon"),
        ("blahCONVERTTOCOLONblah", "blah:blah", "colon"),
    ],
)
def test__get_secret_converts_special_annotations(
    test_value, expected_value, test_description
):
    v = Vault()
    v.set_internal_secret("mykey", test_value)
    actual = v.get_secret("mykey")
    assert actual == expected_value


def test_set_boto_session():
    v = Vault()
    expected_session = "blah"
    v.set_boto_session(expected_session)
    actual_session = v.get_boto_session()
    assert actual_session == expected_session


def test_search_aws_param_store_for_secret__raises_error_if_no_boto_session():
    vault = Vault()
    with pytest.raises(NoConnectedBotoSessionError, match="'blah'"):
        vault.search_aws_param_store_for_secret("blah")


def test_search_aws_param_store_for_secret__raises_error_if_no_param_store_path_supplied():
    vault = Vault()
    vault.set_boto_session("blah session")
    with pytest.raises(NoAwsParameterStorePathError, match="'blah3'"):
        vault.search_aws_param_store_for_secret("blah3")


def test_get_secret__retrieves_value_from_parameter_store(ssm_param):
    vault, secret_name, expected_secret_value = ssm_param

    actual_secret_value = vault.get_secret(secret_name)
    assert actual_secret_value == expected_secret_value


def test_search_aws_param_store_for_secret__raises_error_if_secret_not_in_parameter_store(
    vault_for_param_store,
):
    vault, _ = vault_for_param_store
    with pytest.raises(SecretNotFoundInAwsParameterStoreError, match="blah8"):
        vault.search_aws_param_store_for_secret("test_blah8")


def test_search_aws_param_store_for_secret__reraises_permission_error_that_could_occur_during_boto_call(
    vault_for_param_store,
):
    vault, _ = vault_for_param_store
    with pytest.raises(
        Exception,
        match=r"An error occurred \(AccessDeniedException\) when calling the GetParameter operation",
    ):
        vault.search_aws_param_store_for_secret("blah22091")


def test_get_secret__raises_error_if_secret_not_in_parameter_store(
    vault_for_param_store,
):
    vault, _ = vault_for_param_store
    with pytest.raises(SecretNotFoundInVaultError, match="test_blah891"):
        vault.get_secret("blah891")


def test_get_secret__works_with_int_secret(vault_for_param_store):
    vault, _ = vault_for_param_store
    int_secret = vault.get_secret("int_secret")
    assert isinstance(int_secret, int) is True


def test_get_secret__works_with_float_secret(vault_for_param_store):
    vault, _ = vault_for_param_store
    int_secret = vault.get_secret("float_secret")
    assert isinstance(int_secret, float) is True


def test_Vault__raises_warning_when_setting_with_kebab_case_name():
    v = Vault()
    with pytest.warns(KebabCaseSecretNameWarning, match="kebab_name"):
        v.set_internal_secret("kebab-name", "dummy_val")


def test_Vault__raises_warning_when_getting_with_kebab_case_name():
    v = Vault()
    warnings.simplefilter("ignore", category=KebabCaseSecretNameWarning)
    v.set_internal_secret("kebab-name", "dummy_val")
    warnings.simplefilter("default", category=KebabCaseSecretNameWarning)
    with pytest.warns(KebabCaseSecretNameWarning, match="kebab_name"):
        v.get_secret("kebab-name")


def test_Vault__raises_warning_when_getting_secret_for_specific_deployment_tier_with_kebab_case_name():
    v = Vault()
    deployment_tier = "test"
    with pytest.warns(KebabCaseSecretNameWarning, match="longer_kebab_name"):
        v.set_internal_secret_for_specific_deployment_tier(
            "longer-kebab-name", "dummy_val", deployment_tier
        )


def test_Vault__raises_warning_when_setting_secret_for_specific_deployment_tier_with_kebab_case_name():
    v = Vault()
    deployment_tier = "test"
    warnings.simplefilter("ignore", category=KebabCaseSecretNameWarning)
    v.set_internal_secret_for_specific_deployment_tier(
        "longer-kebab-name", "dummy_val", deployment_tier
    )
    warnings.simplefilter("default", category=KebabCaseSecretNameWarning)
    with pytest.warns(KebabCaseSecretNameWarning, match="longer_kebab_name"):
        v.get_secret_for_specific_deployment_tier("longer-kebab-name", deployment_tier)

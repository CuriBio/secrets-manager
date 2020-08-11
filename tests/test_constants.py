# -*- coding: utf-8 -*-
from secrets_manager import AWS_PARAM_STORE_PATH_KEY_NAME


def test_param_store_path():
    assert AWS_PARAM_STORE_PATH_KEY_NAME == "aws_parameter_store_prefix"

from unittest.mock import MagicMock

import pytest

from aws_reflex.ec2.handlers.base_c2_handler import (SSM_CACHE,
                                                     get_ssm_parameter)


# Pytest fixture that runs before each test function.
# It ensures the cache is empty, so tests don't interfere with each other.
@pytest.fixture(autouse=True)
def clear_ssm_cache():
    """Clears the SSM_CACHE before each test run."""
    SSM_CACHE.clear()


def test_get_ssm_parameter_success(mocker):
    """
    Tests that the function successfully fetches a parameter from SSM
    when it's not in the cache.
    """

    mock_ssm_client = MagicMock()
    mocker.patch("boto3.client", return_value=mock_ssm_client)

    parameter_name = "/test/param"
    parameter_value = "secret_value"
    mock_ssm_client.get_parameter.return_value = {
        "Parameter": {"Value": parameter_value}
    }

    result = get_ssm_parameter(parameter_name)

    assert result == parameter_value
    mock_ssm_client.get_parameter.assert_called_once_with(Name=parameter_name)
    assert SSM_CACHE[parameter_name] == parameter_value


def test_get_ssm_parameter_caching(mocker):
    """
    Tests that the function returns a cached value on the second call
    without calling the SSM API again.
    """
    mock_ssm_client = MagicMock()
    mocker.patch("boto3.client", return_value=mock_ssm_client)

    parameter_name = "/test/cached_param"
    parameter_value = "cached_value"
    mock_ssm_client.get_parameter.return_value = {
        "Parameter": {"Value": parameter_value}
    }

    result1 = get_ssm_parameter(parameter_name)
    result2 = get_ssm_parameter(parameter_name)

    assert result1 == parameter_value
    assert result2 == parameter_value

    mock_ssm_client.get_parameter.assert_called_once_with(Name=parameter_name)


def test_get_ssm_parameter_not_found(mocker):
    """
    Tests that the function raises a KeyError when the SSM parameter is not found.
    """
    mock_ssm_client = MagicMock()
    mocker.patch("boto3.client", return_value=mock_ssm_client)

    parameter_name = "/test/not_found"
    mock_ssm_client.exceptions.ParameterNotFound = Exception
    mock_ssm_client.get_parameter.side_effect = (
        mock_ssm_client.exceptions.ParameterNotFound
    )

    with pytest.raises(KeyError) as excinfo:
        get_ssm_parameter(parameter_name)

    expected_err_msg = f"SSM Parameter {parameter_name} is not found"
    assert expected_err_msg in str(excinfo.value)
    assert parameter_name not in SSM_CACHE

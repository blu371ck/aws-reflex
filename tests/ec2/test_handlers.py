from unittest.mock import MagicMock

import pytest

from aws_reflex.ec2.factory import get_ec2_handler
from aws_reflex.ec2.handlers.base_c2_handler import C2ContainmentHandler


# An example GuardDuty finding for mock
@pytest.fixture
def sample_ec2_finding():
    """
    Provides a sample GuardDuty C2 Finding.
    """
    return {
        "Type": "Backdoor:EC2/C&CActivity.B",
        "Id": "12345finding6789",
        "Resource": {"InstanceDetails": {"InstanceId": "i-012345abcdef12345"}},
        "Service": {
            "Action": {
                "NetworkConnectionAction": {
                    "RemoteIpDetails": {"IpAddressV4": "198.51.100.10"}
                }
            }
        },
    }


def test_c2_handler_execution(mocker, sample_ec2_finding):
    """
    Test the full execution of the C2ContainmentHandler
    """
    mock_ec2_client = MagicMock()
    mock_sns_client = MagicMock()

    def client_side_effect(service_name):
        if service_name == "ec2":
            return mock_ec2_client
        if service_name == "sns":
            return mock_sns_client
        return MagicMock()

    mocker.patch("boto3.client", side_effect=client_side_effect)

    mock_ec2_client.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "BlockDeviceMappings": [
                            {"Ebs": {"VolumeId": "vol-09876fedcba54321"}}
                        ]
                    }
                ]
            }
        ]
    }

    mock_ec2_client.create_snapshot.return_value = {"SnapshotId": "snap-55555"}

    handler = get_ec2_handler(sample_ec2_finding)
    assert isinstance(handler, C2ContainmentHandler)

    handler.execute()

    mock_ec2_client.modify_instance_attribute.assert_called_once_with(
        InstanceId="i-012345abcdef12345", Groups=[handler.QUARANTINE_SG_ID]
    )

    expected_description = (
        f"Forensic snapshot for instance {sample_ec2_finding['Resource']['InstanceDetails']['InstanceId']} "
        f"from GuardDuty finding {sample_ec2_finding['Id']}"
    )

    mock_ec2_client.create_snapshot.assert_called_once_with(
        VolumeId="vol-09876fedcba54321",
        Description=expected_description,
    )

    mock_ec2_client.terminate_instances.assert_called_once_with(
        InstanceIds=["i-012345abcdef12345"]
    )

    mock_sns_client.publish.assert_called_once()

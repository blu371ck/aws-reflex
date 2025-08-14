import logging
from typing import TYPE_CHECKING, Optional

import boto3

if TYPE_CHECKING:
    from mypy_boto3_ec2 import EC2Client
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_ssm import SSMClient

from .base import BaseEC2FindingHandler

logger = logging.getLogger(__name__)

SSM_CACHE: dict = {}


def get_ssm_parameter(name: str) -> str:
    """
    Fetches a parameter from AWS SSM parameter store, with caching.

    Args:
        name: The name of the parameter to fetch.

    Returns:
        The value of the parameter

    Raises:
        KeyError: if the parameter is not found
    """
    if name in SSM_CACHE:
        return SSM_CACHE[name]

    logger.info(f"Fetching parameter {name} from SSM.")
    ssm: SSMClient = boto3.client("ssm")
    try:
        response = ssm.get_parameter(Name=name)
        value = response["Parameter"]["Value"]
        SSM_CACHE[name] = value
        return value
    except ssm.exceptions.ParameterNotFound as e:
        logger.error(f"SSM Parameter {name} is not found.")
        raise KeyError(f"SSM Parameter {name} is not found.") from e


class C2ContainmentHandler(BaseEC2FindingHandler):
    """A handler for critical C2 findings that require a full containment workflow.

    This class orchestrates a multi-step incident response plan:
    1. Contain: Isolates the instance by changing its security group.
    2. Preserve: Creates an EBS snapshot of the root volume for forensics.
    3. Eradicate: Terminates the compromised instance.
    4. Report: Notifies the security team via an SNS topic.

    Attributes:
        QUARANTINE_SG_ID (str): The ID of the security group to apply for isolation.
        FORENSICS_TEAM_TOPIC_ARN (str): The ARN of the SNS topic for notifications.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.QUARANTINE_SG_ID: str = get_ssm_parameter("/cloud-warden/quarantine_sg_id")
        self.FORENSICS_TEAM_TOPIC_ARN: str = get_ssm_parameter(
            "/cloud-warden/forensics_topic_arn"
        )
        self.ec2: EC2Client = boto3.client("ec2")
        self.sns: SNSClient = boto3.client("sns")

    def _is_remediation_in_progress(self) -> bool:
        """
        Checks if the instance is already tagged for remediation.
        """
        logger.info(
            f"Checking for existing remediation tag on instance {self.instance_id}."
        )
        try:
            response = self.ec2.describe_tags(
                Filters=[
                    {"Name": "resource-id", "Values": [self.instance_id]},
                    {"Name": "key", "Values": ["RemediationInProgress"]},
                ]
            )
            return len(response.get("Tags", [])) > 0
        except Exception as e:
            logger.error(
                f"Failed to describe tags for instance {self.instance_id}: {e}"
            )
            return True

    def _apply_remediation_tag(self) -> None:
        """
        Applies a tag to the instance to mark remediation has started.
        """
        logger.info(
            f"Applying 'RemediationInProgress' tag to instance {self.instance_id}."
        )
        self.ec2.create_tags(
            Resources=[self.instance_id],
            Tags=[{"Key": "RemediationInProgress", "Value": "true"}],
        )

    def execute(self) -> None:
        """
        Executes the full incident response workflow.
        """
        logger.warning(
            f"Executing C2 containment plan for instance {self.instance_id} due to finding {self.finding.get('Type')}."
        )

        if self._is_remediation_in_progress():
            logger.warning(
                f"Remediation for instance {self.instance_id} is already in progress. Skipping."
            )
            return

        self._apply_remediation_tag()

        try:
            self._isolate_instance()
            snapshot_id = self._create_snapshot()

            if snapshot_id:
                self._terminate_instance()

                self._notify_team(snapshot_id)

                logger.warning(
                    f"Successfully completed C2 containment plan for instance {self.instance_id}."
                )
            else:
                logger.critical("...MANUAL INTERVENTION REQUIRED")

        except Exception as e:
            logger.error(
                f"Failed to execute C2 containment plan for {self.instance_id}: {e}",
                exc_info=True,
            )

    def _isolate_instance(self) -> None:
        """Changes the instance's security group to a quarantine SG."""
        logger.info(
            f"Applying quarantine security group '{self.QUARANTINE_SG_ID}' to instance {self.instance_id}."
        )
        self.ec2.modify_instance_attribute(
            InstanceId=self.instance_id, Groups=[self.QUARANTINE_SG_ID]
        )
        logger.info(f"Instance {self.instance_id} has been isolated.")

    def _create_snapshot(self) -> Optional[str]:
        """Creates a snapshot of the instance's root EBS volume for forensics.

        Returns:
            The snapshot ID on success, or None on failure.
        """
        logger.info(
            f"Creating snapshot for root volume of instance {self.instance_id}."
        )

        try:

            response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
            root_volume_id: str = response["Reservations"][0]["Instances"][0][
                "BlockDeviceMappings"
            ][0]["Ebs"]["VolumeId"]

            snapshot_response = self.ec2.create_snapshot(
                VolumeId=root_volume_id,
                Description=f"Forensic snapshot for instance {self.instance_id} from GuardDuty finding {self.finding.get('id')}",
            )

            snapshot_id: str = snapshot_response["SnapshotId"]

            logger.info(
                f"Snapshot '{snapshot_id}' created for volume of instance {self.instance_id}."
            )
            return snapshot_id
        except (KeyError, IndexError) as e:
            logger.error(
                f"Error parsing instance details for {self.instance_id}: {e}",
                exc_info=True,
            )
            return None

    def _terminate_instance(self) -> None:
        """Terminates the EC2 instance."""
        logger.warning(f"Terminating compromised instance {self.instance_id}.")
        self.ec2.terminate_instances(InstanceIds=[self.instance_id])
        logger.warning(f"Instance {self.instance_id} has been terminated.")

    def _notify_team(self, snapshot_id: str) -> None:
        """Sends a detailed report to the forensics team SNS topic.

        Args:
            snapshot_id: The ID of the forensic snapshot that was created.
        """
        logger.info(f"Sending report to SNS topic {self.FORENSICS_TEAM_TOPIC_ARN}.")
        message = (
            f"Automated SOAR Response for GuardDuty Finding\n\n"
            f"Finding Type: {self.finding.get('Type')}\n"
            f"Instance ID: {self.instance_id}\n"
            f"Description: An active C2 threat was detected and remediated.\n\n"
            f"Actions Taken:\n"
            f"1. Instance isolated with SG: {self.QUARANTINE_SG_ID}\n"
            f"2. Forensic snapshot created: {snapshot_id}\n"
            f"3. Instance terminated.\n\n"
            f"Please begin forensic analysis on the snapshot."
        )

        self.sns.publish(
            TopicArn=self.FORENSICS_TEAM_TOPIC_ARN,
            Subject=f"Automated C2 Response for Instance {self.instance_id}",
            Message=message,
        )
        logger.info("Report sent successfully.")

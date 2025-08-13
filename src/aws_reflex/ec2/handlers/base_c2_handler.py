import logging
from typing import Optional

import boto3
from mypy_boto3_ec2 import EC2Client
from mypy_boto3_guardduty import GuardDutyClient
from mypy_boto3_sns import SNSClient

from .base import BaseEC2FindingHandler

logger = logging.getLogger(__name__)


class C2ContainmentHandler(BaseEC2FindingHandler):
    """
    An abstract handler for critical C2 findings that require a full
    contain, preserve, and eradicate response.
    """

    # In a real application, this would be fetched from a config file or SSM Parameter Store
    QUARANTINE_SG_ID: str = "sg-0123456789abcdef0"  # Example Quarantine Security Group
    FORENSICS_TEAM_TOPIC_ARN: str = (
        "arn:aws:sns:us-east-1:111122223333:ForensicsTeamTopic"
    )

    def execute(self) -> None:
        """
        Executes the full incident response workflow:
        1. Contain: Isolate the instance.
        2. Preserve: Snapshot the root volume.
        3. Eradicate: Terminate the instance.
        4. Report: Log and notify.
        """
        logger.warning(
            f"Executing C2 containment plan for instance {self.instance_id} due to finding {self.finding.get('Type')}."
        )

        try:
            # Step 1: Containment - Isolate the instance immediately
            self._isolate_instance()

            # Step 2: Preservation - Create a snapshot for forensics
            snapshot_id = self._create_snapshot()

            if snapshot_id:
                self._terminate_instance()

                # Step 4: Reporting - Notify the team with all details
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
            # You might add logic here to alert an operator that the automation failed.

    def _isolate_instance(self) -> None:
        """Changes the instance's security group to a quarantine SG."""
        logger.info(
            f"Applying quarantine security group '{self.QUARANTINE_SG_ID}' to instance {self.instance_id}."
        )
        ec2: EC2Client = boto3.client("ec2")
        ec2.modify_instance_attribute(
            InstanceId=self.instance_id, Groups=[self.QUARANTINE_SG_ID]
        )
        logger.info(f"Instance {self.instance_id} has been isolated.")

    def _create_snapshot(self) -> Optional[str]:
        """Creates a snapshot of the instance's root EBS volume."""
        logger.info(
            f"Creating snapshot for root volume of instance {self.instance_id}."
        )

        ec2: EC2Client = boto3.client("ec2")
        try:

            response = ec2.describe_instances(InstanceIds=[self.instance_id])
            root_volume_id: str = response["Reservations"][0]["Instances"][0][
                "BlockDeviceMappings"
            ][0]["Ebs"]["VolumeId"]

            snapshot_response = ec2.create_snapshot(
                VolumeId=root_volume_id,
                Description=f"Forensic snapshot for instance {self.instance_id} from GuardDuty finding {self.finding.get('Id')}",
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
        ec2: EC2Client = boto3.client("ec2")
        ec2.terminate_instances(InstanceIds=[self.instance_id])
        logger.warning(f"Instance {self.instance_id} has been terminated.")

    def _notify_team(self, snapshot_id: str) -> None:
        """Sends a report to the forensics team SNS topic."""
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

        sns: SNSClient = boto3.client("sns")
        sns.publish(
            TopicArn=self.FORENSICS_TEAM_TOPIC_ARN,
            Subject=f"Automated C2 Response for Instance {self.instance_id}",
            Message=message,
        )
        logger.info("Report sent successfully.")

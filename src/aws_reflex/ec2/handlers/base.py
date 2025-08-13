import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class BaseEC2FindingHandler(ABC):
    """Abstract base class for handling GuardDuty EC2 findings.

    This class provides a common interface and helper methods for all specific
    finding handlers. It is responsible for parsing common details from the
    finding, such as the instance ID.

    Attributes:
        finding (Dict[str, Any]): The raw GuardDuty finding data.
        instance_id (str): The ID of the EC2 instance associated with the finding.
        remote_ip (Optional[str]): The remote IP address involved, if available.
    """

    def __init__(self, finding_details: Dict[str, Any]) -> None:
        """Initializes the BaseEC2FindingHandler.

        Args:
            finding_details: The full GuardDuty finding JSON object.
        """
        self.finding: Dict[str, Any] = finding_details
        self.instance_id: str = self._get_instance_id()
        self.remote_ip: Optional[str] = self._get_remote_ip()
        logger.info(f"Initialized handler for instance {self.instance_id}")

    def _get_instance_id(self) -> str:
        """Extracts the instance ID from the finding details.

        Returns:
            The EC2 instance ID as a string.

        Raises:
            KeyError: If the instance ID cannot be found in the finding structure.
        """
        return self.finding["Resource"]["InstanceDetails"]["InstanceId"]

    def _get_remote_ip(self) -> Optional[str]:
        """Extracts the remote IP address from the finding's service action.

        Returns:
            The remote IPv4 address as a string, or None if not found.
        """
        try:
            return self.finding["Service"]["Action"]["NetworkConnectionAction"][
                "RemoteIpDetails"
            ]["IpAddressV4"]
        except KeyError:
            return None

    @abstractmethod
    def execute(self) -> None:
        """The core method to execute the response action.

        This method must be implemented by all concrete subclasses.
        """
        pass

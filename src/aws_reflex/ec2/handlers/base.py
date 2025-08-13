import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class BaseEC2FindingHandler(ABC):
    """
    Abstract base class for handling GuardDuty EC2 findings.
    """

    def __init__(self, finding_details: Dict[str, Any]) -> None:
        self.finding: Dict[str, Any] = finding_details
        self.instance_id: str = self._get_instance_id()
        self.remote_ip: Optional[str] = self._get_remote_ip()
        logger.info(f"Initialized handler for instance {self.instance_id}")

    def _get_instance_id(self) -> str:
        """
        Helper method to extract instance ID from the finding.
        """
        return self.finding["Resource"]["InstanceDetails"]["InstanceId"]

    def _get_remote_ip(self) -> Optional[str]:
        """
        Helper method to extract the remote IP address from the finding's
        service action.
        """
        try:
            return self.finding["Service"]["Action"]["NetworkConnectionAction"][
                "RemoteIpDetails"
            ]["IpAddressV4"]
        except KeyError:
            return None

    @abstractmethod
    def execute(self) -> None:
        """
        The core method to execute the response. Must be implemented by subclasses.
        """
        pass

import logging
from typing import Any, Dict, Optional, Type

from .handlers import C2ActivityHandler, C2DnsActivityHandler
from .handlers.base import BaseEC2FindingHandler

logger = logging.getLogger(__name__)

HANDLER_MAPPING: Dict[str, Type[BaseEC2FindingHandler]] = {
    "Backdoor:EC2/C&CActivity.B": C2ActivityHandler,
    "Backdoor:EC2/C&CActivity.B!DNS": C2DnsActivityHandler,
}


def get_ec2_handler(finding: Dict[str, Any]) -> Optional[BaseEC2FindingHandler]:
    """
    Factory function that returns the appropriate handler instance for a given finding.

    Args:
        finding: Full GuardDuty finding JSON object.
    Returns:
        A handler object if the finding exists, else none.
    """
    finding_type: Optional[str] = finding.get("Type")
    logger.debug(f"Attempting to find handler for finding type: {finding_type}")

    HandlerClass: Optional[Type[BaseEC2FindingHandler]] = HANDLER_MAPPING.get(
        str(finding_type)
    )

    if HandlerClass:
        logger.info(
            f"Found handler {HandlerClass.__name__} for finding type {finding_type}."
        )
        return HandlerClass(finding)

    logger.warning(f"No handler configured for finding {finding_type}.")
    return None

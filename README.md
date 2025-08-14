# AWS Reflex 🛡️

[![Python Version](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/managed%20with-uv-blue.svg)](https://github.com/astral-sh/uv)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An extensible Python library for building automated, event-driven security responses to AWS GuardDuty findings.

`aws-reflex` provides a clean, object-oriented framework to automatically contain threats detected in your AWS environment. It is designed to be deployed as an AWS Lambda Layer and triggered by GuardDuty events via Amazon EventBridge, enabling rapid, serverless Security Orchestration, Automation, and Response (SOAR).

---

## Key Features

* **Event-Driven & Serverless**: Built to run within AWS Lambda for a cost-effective, scalable, and low-maintenance SOAR solution.
* **Object-Oriented Design**: Uses a factory pattern with dedicated handler classes for different GuardDuty findings, making the logic clean, scalable, and easy to maintain.
* **Secure Configuration**: Securely manages configuration (like ARNs and IDs) using AWS Systems Manager (SSM) Parameter Store, avoiding hardcoded secrets.
* **Extensible**: Easily add new handlers for different GuardDuty findings without modifying the core logic.
* **Type-Safe**: Fully type-annotated for improved code quality and developer experience with tools like Pylance and `mypy`.
* **Testable**: Designed for comprehensive unit testing with `pytest` and mocking.

---

## How It Works



1.  **Detect**: Amazon GuardDuty detects a threat (e.g., an EC2 instance communicating with a C2 server) and generates a finding.
2.  **Trigger**: An Amazon EventBridge rule filters for high-severity findings and invokes a Lambda function.
3.  **Orchestrate**: The Lambda function uses the `aws-reflex` library to identify the correct handler for the finding type.
4.  **Remediate**: The handler class executes a series of automated response steps using Boto3, such as:
    * Isolating the EC2 instance by changing its security group.
    * Preserving evidence by creating an EBS snapshot.
    * Terminating the compromised instance.
    * Notifying a security team via an SNS topic.

---

## Installation

This library is intended to be packaged as an **AWS Lambda Layer**.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/aws-reflex.git](https://github.com/your-username/aws-reflex.git)
    cd aws-reflex
    ```

2.  **Install Requirements:**
    Use `uv` or `pip` to install requirements from `requirements.txt`

```
uv pip install -r requirements.txt

pip install -r requirements.txt
```

3.  **Create the Layer Package:**
    Use `pip` to install the package into a directory structure that Lambda understands.

    ```bash
    # Create the required directory structure
    mkdir -p build/python

    # Install the library from your source into that directory
    pip install . -t build/python

    # Create the zip file from the contents of the build directory
    cd build
    zip -r ../layer.zip .
    ```
    You can now upload `layer.zip` as a new Lambda Layer in your AWS account.

---

## Configuration

The library securely fetches configuration from **AWS Systems Manager (SSM) Parameter Store**. You must create the following parameters:

| Parameter Name                  | Description                                      | Example Value                                                 |
| ------------------------------- | ------------------------------------------------ | ------------------------------------------------------------- |
| `/reflex/quarantine_sg_id`  | The ID of the Security Group used for isolation. | `sg-0123456789abcdef0`                                        |
| `/reflex/forensics_topic_arn` | The ARN of the SNS topic for notifications.      | `arn:aws:sns:us-east-1:111122223333:ForensicsTeamTopic` |

Your Lambda function's IAM role will need `ssm:GetParameter` permissions for these specific resources.

---

## Usage

The library is designed to be used within an AWS Lambda function handler.

**`lambda_function.py` Example:**

```python
import json
import logging
from typing import Any, Dict

# This import works because the 'aws_reflex' library is provided
# by the Lambda Layer and is available in the /opt/python path.
from aws_reflex.ec2 import get_ec2_handler

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """
    Lambda handler triggered by a GuardDuty finding from Amazon EventBridge.

    This function receives the GuardDuty finding, passes it to the aws-reflex
    library's factory to get the correct handler, and then executes the
    automated response.

    Args:
        event: The EventBridge event containing the GuardDuty finding.
        context: The Lambda runtime context object.

    Returns:
        A dictionary with a status code and a message.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # The actual GuardDuty finding is nested inside the EventBridge event's 'detail' key.
        finding = event.get("detail")
        if not finding:
            logger.warning("Event did not contain a 'detail' key with finding information.")
            return {"statusCode": 200, "body": json.dumps("No finding found in event.")}

        # Use the factory from our layer to get the correct handler for this finding type.
        handler_instance = get_ec2_handler(finding)

        if handler_instance:
            # If a handler was found, execute its automated response logic.
            logger.info(f"Executing handler '{type(handler_instance).__name__}' for finding type '{finding.get('type')}'.")
            handler_instance.execute()
        else:
            # If no handler is configured for this finding type, log it and exit gracefully.
            logger.info(f"No handler configured for finding type '{finding.get('type')}'. Ignoring.")

        return {"statusCode": 200, "body": json.dumps("Processing complete.")}

    except Exception as e:
        logger.error(f"An unhandled error occurred during handler execution: {e}", exc_info=True)
        # Re-raise the exception to allow Lambda to handle retries if they are configured
        # and to mark the invocation as failed.
        raise
```

## Testing

The library is tested using pytest. Tests are located in the `tests/` directory and use pytest-mock to simulate Boto3 API calls.

Install development dependencies:
```
uv pip install -r requirements.txt
# or
pip install pytest pytest-mock boto3-stubs
```
Run tests:
Navigate to the project root and run pytest.
```
pytest
# or
uv run pytest .\tests
```
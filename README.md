# AWS Reflex

[![Python Version](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/managed%20with-uv-blue.svg)](https://github.com/astral-sh/uv)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is an example of a Python library that is utilized by a Terraform pipeline to perform automated security finding remediation. This library is not complete and only contains a few example scenarios.

The library itself defines classes for GuardDuty findings that initiate and utilize appropriate response measures. This library is intended to be ingested within an AWS environment, on any form of compute. An example of the full SOAR pipeline can be found [here](https://github.com/blu371ck/AWS-GUARDDUTY-AND-LAMBDA-SOAR).

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

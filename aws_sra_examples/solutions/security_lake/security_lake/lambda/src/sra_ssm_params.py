"""Custom Resource to gather data and create SSM paramters in the management account.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Literal, Optional, Sequence, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_ssm.type_defs import TagTypeDef
    from mypy_boto3_ssm.client import SSMClient


class sra_ssm_params:
    def __init__(self, logger):
        self.LOGGER = logger

    # Global Variables
        self.UNEXPECTED = "Unexpected!"
        self.BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

        try:
            MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
            self.SSM_CLIENT: SSMClient = MANAGEMENT_ACCOUNT_SESSION.client("ssm")
        except Exception:
            self.LOGGER.exception(self.UNEXPECTED)
            raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None

    def get_log_archive_acct(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify log archive account id.

        Returns:
            Log archive account id
        """
        log_archive_acct = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/log-archive-account-id")
        log_archive_acct = ssm_response["Parameter"]["Value"]
        return log_archive_acct

    def get_security_acct(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify security tooling account id.

        Returns:
            Security tooling account id
        """
        sra_security_acct = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/audit-account-id")
        sra_security_acct = ssm_response["Parameter"]["Value"]
        return sra_security_acct

    def get_home_region(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify home region.

        Returns:
            Home region
        """
        home_region = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/home-region",)
        home_region = ssm_response["Parameter"]["Value"]
        return home_region

    def get_root_organizational_unit_id(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify root organizational unit id.

        Returns:
            Root organizational unit id
        """
        root_organizational_unit_id = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/root-organizational-unit-id",)
        root_organizational_unit_id = ssm_response["Parameter"]["Value"]
        return root_organizational_unit_id

    def get_organization_id(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify organization id.

        Returns:
            Organization id
        """
        organization_id = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/organization-id",)
        organization_id = ssm_response["Parameter"]["Value"]
        return organization_id

    def get_management_acct_id(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify management account id.

        Returns:
            Managemet account id
        """
        management_acct_id = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/control-tower/management-account-id",)
        management_acct_id = ssm_response["Parameter"]["Value"]
        return management_acct_id

    def get_enabled_regions(self) -> list:  # noqa: CCR001
        """Query SSM Parameter Store to identify enabled regions.

        Returns:
            Enabled regions
        """
        enabled_regions = []
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/regions/enabled-regions",)
        enabled_regions = ssm_response["Parameter"]["Value"].split(",")
        return list(enabled_regions)

    def get_staging_bucket_name(self) -> str:  # noqa: CCR001
        """Query SSM Parameter Store to identify staging s3 bucket name.

        Returns:
            Staging s3 bucket name
        """
        staging_bucket_name = ''
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/staging-s3-bucket-name",)
        staging_bucket_name = ssm_response["Parameter"]["Value"]
        return staging_bucket_name

    def get_enabled_regions_without_home_region(self) -> list:  # noqa: CCR001
        """Query SSM Parameter Store to identify enabled regions without home region.

        Returns:
            Enabled regions without home region
        """
        enabled_regions_without_home_region = []
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/regions/enabled-regions-without-home-region",)
        enabled_regions_without_home_region = ssm_response["Parameter"]["Value"].split(",")
        return list(enabled_regions_without_home_region)

    def get_customer_regions(self) -> list:  # noqa: CCR001
        """Query SSM Parameter Store to identify customer regions.

        Returns:
            Customer regions
        """
        customer_regions = []
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/regions/customer-control-tower-regions",)
        customer_regions = ssm_response["Parameter"]["Value"].split(",")
        return list(customer_regions)

    def get_customer_regions_without_home_region(self) -> list:  # noqa: CCR001
        """Query SSM Parameter Store to identify customer Control Tower regions without home region.

        Returns:
            Customer regions without home region
        """
        customer_regions_without_home_region = []
        ssm_response = self.SSM_CLIENT.get_parameter(Name="/sra/regions/customer-control-tower-regions-without-home-region",)
        customer_control_tower_regions_without_home_region = ssm_response["Parameter"]["Value"].split(",")
        return list(customer_control_tower_regions_without_home_region)
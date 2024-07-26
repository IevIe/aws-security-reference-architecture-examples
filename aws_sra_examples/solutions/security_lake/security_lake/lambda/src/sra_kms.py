"""Custom Resource to setup SRA IAM resources in the management account.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
import json
from time import sleep
import random

from botocore.exceptions import ClientError


class sra_kms:
    """KMS resources class."""

    def __init__(
        self,
        logger,
    ) -> None:
        """Initialize KMS resources class.

        Args:
            logger: Logger
            management_acct_id: Management Account Id
            delegated_admin_id: Delegated Admin Account Id
            log_archive_acct_id: Log Archive Account Id
            partition: AWS partition
            home_region: Home region
        """
        self.logger = logger
        self.KEY = "sra-solution"
        self.VALUE = "sra-security-lake"

    def define_key_policy(self, delegated_admin_acct, partition, region):
        """Define Config Delivery Key Policy.

        Returns:
            policy_template: Policy template
        """
        policy_template = {  # noqa ECE001
            "Version": "2012-10-17",
            "Id": "sra-security-lake-key",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            f"arn:{partition}:iam::{delegated_admin_acct}:root",
                            f"arn:{partition}:iam::{delegated_admin_acct}:role/sra-security-lake-configuration"
                        ],
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "Allow alias creation during setup",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:{partition}:iam::{delegated_admin_acct}:root"
                        },
                    "Action": "kms:CreateAlias",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": f"lambda.{region}.amazonaws.com",
                            "kms:CallerAccount": delegated_admin_acct,
                        }
                    },
                },
                {
                    "Sid": "Allow use of the key",
                    "Effect": "Allow",
                    "Principal": {
                            "AWS": f"arn:{partition}:iam::{delegated_admin_acct}:role/aws-service-role/lakeformation.amazonaws.com/AWSServiceRoleForLakeFormationDataAccess"
                        },
                    "Action": [
                        "kms:CreateGrant",
                        "kms:DescribeKey",
                        "kms:GenerateDataKey",
                        "kms:Decrypt"
                    ],
                    "Resource": "*"
                }
            ]
        }

        return json.dumps(policy_template)


    def create_kms_key(self, kms_client, key_policy, key_description):
        """Create KMS key.

        Args:
            kms_client: boto3 kms client
            key_policy: key policy
            key_description: key description

        Returns:
            key_id: key id
        """
        number_retries = 10
        base_delay = 0.5
        max_delay = 20
        key_created = False
        for attempt in range(number_retries):
            try:
                key_response = kms_client.create_key(
                    Policy=key_policy,
                    Description=key_description,
                    KeyUsage="ENCRYPT_DECRYPT",
                    CustomerMasterKeySpec="SYMMETRIC_DEFAULT",
                    Tags=[
                        {
                            'TagKey': self.KEY,
                            'TagValue': self.VALUE
                        },
                    ]
                )
                key_created = True
                return key_response["KeyMetadata"]
            except ClientError as error:
                if error.response["Error"]["Code"] == "MalformedPolicyDocumentException":
                    self.logger.error(f"'MalformedPolicyDocumentException' occurred: {error}. Retrying ({attempt+1}/{number_retries})...")
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    delay += random.uniform(0, 1)
                    print("!!! KMS KEY DELAY", delay)
                    sleep(delay)
                else:
                    self.logger.error(f"Create KMS key error: {error.response['Error']['Message']}")
                    raise
        if not key_created:
            self.logger.error("Error creating KMS key")

    def create_alias(self, kms_client, alias_name, target_key_id):
        """Create KMS key alias.

        Args:
            kms_client: boto3 kms client
            alias_name: alias name
            target_key_id: target key id
        """
        try:
            kms_client.create_alias(AliasName=alias_name, TargetKeyId=target_key_id)
            return True
        except kms_client.exceptions.AlreadyExistsException:
            self.logger.info(f"Alias {alias_name} already exists")
            return False

    def enable_key_rotation(self, kms_client, key_id):
        """Enable key rotation.

        Args:
            kms_client: boto3 kms client
            key_id: key id
        """
        try:
            kms_client.enable_key_rotation(KeyId=key_id)
        except kms_client.exceptions.NotFoundException:
            self.logger.info(f"Key {key_id} does not exist")

    def delete_alias(self, kms_client, alias_name):
        """Delete KMS key alias.

        Args:
            kms_client: boto3 kms client
            alias_name: alias name
        """
        try:
            kms_client.delete_alias(AliasName=alias_name)
        except kms_client.exceptions.NotFoundException:
            self.logger.info(f"Alias {alias_name} does not exist")

    def schedule_key_deletion(self, kms_client, key_id, pending_window_in_days=30):
        """Schedule KMS key deletion.

        Args:
            kms_client: boto3 kms client
            key_id: key id
            pending_window_in_days: number of days before key deletion

        Returns:
            True if key deletion scheduled, False if key is already pending deletion
        """
        try:
            kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=pending_window_in_days)
            return True
        except kms_client.exceptions.KMSInvalidStateException:
            self.logger.info(f"kms key {key_id} is already pending deletion")
            return False

    def check_key_exists(self, kms_client, key_id):
        """Check if KMS key exists.

        Args:
            kms_client: boto3 kms client
            key_id: key id

        Returns:
            True and key_arn if key exists, False and None if key does not exist
        """
        try:
            response = kms_client.describe_key(KeyId=key_id)
            key_arn = response["KeyMetadata"]["Arn"]
            return True, key_arn
        except kms_client.exceptions.NotFoundException:
            return False, None

    def check_alias_exists(self, kms_client, alias_name):
        """Check if KMS key alias exists.

        Args:
            kms_client: boto3 kms client
            alias_name: alias name

        Returns:
            True and alias info if alias exists, False and None if alias does not exist
        """
        try:
            response = kms_client.list_aliases()
            for alias in response["Aliases"]:
                if alias["AliasName"] == alias_name:
                    return True, alias
            return False, None
        except ClientError as e:
            self.logger.info(f"Unexpected error: {e}")
            return False, None

    def get_key_id(self, kms_client, key_alias):
        """Get KMS key id from alias.

        Args:
            kms_client: boto3 kms client
            key_alias: key alias

        Returns:
            Key id
        """
        try:
            response = kms_client.describe_key(KeyId=key_alias)
            return response["KeyMetadata"]["KeyId"]
        except kms_client.exceptions.NotFoundException:
            self.logger.info(f"KMS key with alias {key_alias} does not exist")
            return None
        
    def get_policy_name(self, kms_client, key_id):
        """Get KMS key policy name.

        Args:
            key_id: key id

        Returns:
            Policy name
        """
        try:
            response = kms_client.list_key_policies(KeyId=key_id)
            policy_name = response["PolicyNames"][0]
            return policy_name
        except ClientError as e:
            self.logger.info(f"Unexpected error: {e}")
            return None

    def update_key_policy(self, kms_client, key_id, key_policy):
        """Put KMS key policy.

        Args:
            kms_client: boto3 kms client
            key_id: key id
            key_policy: key policy
        """
        try:
            kms_client.put_key_policy(
                KeyId=key_id,
                Policy=key_policy,
                PolicyName="default",
            )
        except ClientError as e:
            self.logger.info(f"Unexpected error: {e}")
"""Custom Resource to setup SRA IAM resources in the management account.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
import json

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
        self.KEY_DESCRIPTION: str = ("Config Delivery KMS Key")  # todo(liamschn): parameterize this description

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
                        "AWS": f"arn:{partition}:iam::{delegated_admin_acct}:root"
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
                            "AWS": f"arn:aws:iam::{delegated_admin_acct}:role/AmazonSecurityLakeMetaStoreManagerV2"
                        },
                    "Action": [
                        "kms:CreateGrant",
                        "kms:DescribeKey",
                        "kms:GenerateDataKey"
                    ],
                    "Resource": "*"
                },
            ],
        }

        self.logger.info(f"Key Policy:\n{json.dumps(policy_template)}")
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
        key_response = kms_client.create_key(
            Policy=key_policy,
            Description=key_description,
            KeyUsage="ENCRYPT_DECRYPT",
            CustomerMasterKeySpec="SYMMETRIC_DEFAULT",
        )
        # return key_response["KeyMetadata"]["KeyId"]
        return key_response["KeyMetadata"]

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

"""This script performs operations to create roles and policies for SRA solutions.

Version: 1.0

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError
from time import sleep

if TYPE_CHECKING:
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import CreatePolicyResponseTypeDef, CreateRoleResponseTypeDef, EmptyResponseMetadataTypeDef


class sra_iam:
    def __init__(self, logger):
        self.LOGGER = logger

    def check_iam_role_exists(self, iam_client, role_name):
        """
        Checks if an IAM role exists.

        Parameters:
        - role_name (str): The name of the IAM role to check.

        Returns:
        bool: True if the role exists, False otherwise.
        """
        try:
            role_info = iam_client.get_role(RoleName=role_name)
            self.LOGGER.info(f"The role '{role_name}' exists.")
            # return True, role_info
            return True
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                self.LOGGER.info(f"The role '{role_name}' does not exist.")
                # return False, None
                return False
            else:
                # Handle other possible exceptions (e.g., permission issues)
                raise

    def create_role(self, iam_client, role_name: str, trust_policy: str):   # TODO: add waiter
        """Create IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role to be created
            trust_policy: Trust policy relationship for the role

        Returns:
            Dictionary output of a successful CreateRole request
        """
        try:
            self.LOGGER.info(f"Creating role {role_name}")
            return iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        except ClientError as err:
            self.LOGGER.exception(err)
            raise ValueError(f"Error: {err}") from None

    def create_policy(self, iam_client, policy_name: str, policy_document: str) -> CreatePolicyResponseTypeDef:
        """Create IAM policy.

        Args:
            session: boto3 session used by boto3 API calls
            policy_name: Name of the policy to be created
            policy_document: IAM policy document for the role

        Returns:
            Dictionary output of a successful CreatePolicy request
        """
        self.LOGGER.info(f"Creating policy {policy_name}")
        return iam_client.create_policy(PolicyName=policy_name, PolicyDocument=policy_document)

    def attach_policy(self, iam_client, role_name: str, policy_name: str, policy_document: str) -> EmptyResponseMetadataTypeDef:
        """Attach policy to IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role for policy to be attached to
            policy_name: Name of the policy to be attached
            policy_document: IAM policy document to be attached

        Returns:
            Empty response metadata
        """
        self.LOGGER.info(f"Attaching policy to {role_name}")
        return iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)

    def attach_managed_policy(self, iam_client, role_name: str, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Attach managed policy to IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role for policy to be attached to
            policy_name: Name of the policy to be attached
            policy_document: IAM policy document to be attached

        Returns:
            Empty response metadata
        """
        self.LOGGER.info(f"Attaching managed policy to {role_name}")
        return iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def update_policy(self, iam_client, policy_arn, policy):
        self.LOGGER.info(f"Updating policy {policy_arn}")
        
        response = iam_client.list_policy_versions(PolicyArn=policy_arn)
        print(response)
        # delete version if more than 4 versions already exist
        if len(response["Versions"]) > 4:
            iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=response["Versions"][1]["VersionId"])
        
        iam_client.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=policy,
            SetAsDefault=True
        )

    def list_policy_versions(self, iam_client, policy_arn):
        response = iam_client.list_policy_versions(PolicyArn=policy_arn)
        return response

    def delete_policy_versions(self, iam_client, policy_arn):
                
        response = self.list_policy_versions(iam_client, policy_arn)
        print(response)
        # delete version if more than 4 versions already exist
        if len(response["Versions"]) > 1:
            for version in response["Versions"]:
                if not version["IsDefaultVersion"]:
                    print(version)
                    iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=version["VersionId"])
    
    def detach_policy(self, iam_client, role_name: str, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Detach IAM policy.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role for which the policy is removed from
            policy_name: Name of the policy to be removed (detached)

        Returns:
            Empty response metadata
        """
        self.LOGGER.info(f"Detaching policy from {role_name}")
        return iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def delete_policy(self, iam_client, policy_arn: str) -> EmptyResponseMetadataTypeDef:
        """Delete IAM Policy.

        Args:
            session: boto3 session used by boto3 API calls
            policy_arn: The Amazon Resource Name (ARN) of the policy to be deleted

        Returns:
            Empty response metadata
        """
        self.LOGGER.info(f"Deleting policy {policy_arn}")
        return iam_client.delete_policy(PolicyArn=policy_arn)

    def delete_role(self, iam_client, role_name: str) -> EmptyResponseMetadataTypeDef:
        """Delete IAM role.

        Args:
            session: boto3 session used by boto3 API calls
            role_name: Name of the role to be deleted

        Returns:
            Empty response metadata
        """
        self.LOGGER.info(f"Deleting role {role_name}")
        return iam_client.delete_role(RoleName=role_name)
    
    def delete_service_linked_role(self, iam_client, role_name):
        self.LOGGER.info(f"Deleting service linked role {role_name}")
        response = iam_client.delete_service_linked_role(RoleName=role_name)
        print(response['DeletionTaskId'])
        
        return response['DeletionTaskId']
        
    def get_deletion_status(self, iam_client, task_id):   
        sleep(5)
        try:
            status = iam_client.get_service_linked_role_deletion_status(DeletionTaskId=task_id)
            self.LOGGER.info(f"Deletion status: {status['Status']}")
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchEntity":
                sleep(1)
                status = iam_client.get_service_linked_role_deletion_status(DeletionTaskId=task_id)

        while status['Status'] == "IN_PROGRESS":
            sleep(1)
            status = iam_client.get_service_linked_role_deletion_status(DeletionTaskId=task_id)
            self.LOGGER.info(f"Deletion status: {status['Status']}")
        
        self.LOGGER.info(f"Deletion status: {status}")
        return status


"""This script performs operations to enable, configure, and disable security lake.

Version: 1.0
'security_lake_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import math
import os
from time import sleep
from typing import TYPE_CHECKING

import boto3
import botocore
import common

if TYPE_CHECKING:
    from mypy_boto3_securitylake import SecurityLakeClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_organizations import OrganizationsClient

LOGGER = logging.getLogger("sra")


log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)


UNEXPECTED = "Unexpected!"
EMPTY_STRING = ""
SECURITY_LAKE_THROTTLE_PERIOD = 0.2
ENABLE_RETRY_ATTEMPTS = 10
ENABLE_RETRY_SLEEP_INTERVAL = 10
MAX_RETRY = 5
SLEEP_SECONDS = 10
# TODO: (ieviero) make security_lake.py a class

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


# check if delegated admin is registered for securitylake.amazonwas.com
def check_organization_admin_enabled(delegated_admin_account_id: str, service_principal: str, region: str) -> bool:
    """Check if the delegated administrator account for the provided service principal exists.

    Args:
        delegated_admin_account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal
        region: AWS Region

    Returns:
        bool: True if the delegated administrator account exists, False otherwise
    """
    LOGGER.info(f"Checking if delegated administrator already registered for: {service_principal}.")
    delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

    if not delegated_administrators["DelegatedAdministrators"]:
        LOGGER.info(f"Delegated administrator for {service_principal} is not registered.")
        return False
    elif delegated_administrators["DelegatedAdministrators"][0]["Id"] == delegated_admin_account_id:
        LOGGER.info(f"Account {delegated_admin_account_id} already registered as delegated administrator for {service_principal} service principal.")
        return True
    elif delegated_administrators["DelegatedAdministrators"][0]["Id"] != delegated_admin_account_id:
        LOGGER.info(f"Account: {delegated_administrators['DelegatedAdministrators'][0]['Id']} already registered for {service_principal} service principal. Deregistering account {delegated_administrators['DelegatedAdministrators'][0]['Id']} to register Log Archive account {delegated_admin_account_id}")
        deregister_security_lake_admin(delegated_administrators['DelegatedAdministrators'][0]['Id'], region)
        return False
    else:
        print("Delegated admin check error")
        return False


#  register delegated admin for securitylake.amazonwas.com
def register_delegated_admin(admin_account_id: str, region: str) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region

    Raises:
        Exception: Generic Exception
    """
    sl_client = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    try:
        if not check_organization_admin_enabled(admin_account_id, "securitylake.amazonaws.com", region):
            LOGGER.info(f"Enabling security lake admin account {admin_account_id} in region {region}")
            delegated_admin_response = sl_client.register_data_lake_delegated_administrator(accountId=admin_account_id)
            api_call_details = {"API_Call": "securitylake:RegisterDataLakeDelegatedAdministrator", "API_Response": delegated_admin_response}
            LOGGER.info(api_call_details)
    except Exception as e:
        LOGGER.error(f"Error calling RegisterDataLakeDelegatedAdministrator {e}. For account {admin_account_id}) in {region}")
        raise ValueError("Error registering the delegated administrator account")


def deregister_security_lake_admin(admin_account_id, region):
    sl_client = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    try:
        LOGGER.info(f"Deregistering delegated admin account {admin_account_id}")
        delegated_admin_response = sl_client.deregister_data_lake_delegated_administrator()
        api_call_details = {"API_Call": "securitylake:DeregisterDataLakeDelegatedAdministrator", "API_Response": delegated_admin_response}
        LOGGER.info(api_call_details)
    except Exception as e:
        LOGGER.error(f"Error calling DeregisterDataLakeDelegatedAdministrator {e}. For account {admin_account_id}) in {region}")
        raise ValueError("Error deregistering the delegated administrator account")


def set_configurations(delegated_admin_acct, region, expiration_days, transition_days, storage_class, regions = []):
    configurations=[
        {
            'encryptionConfiguration': {
                'kmsKeyId': 'S3_MANAGED_KEY'
            },
            'lifecycleConfiguration': {
                'expiration': {
                    'days': expiration_days
                },
                'transitions': [
                    {
                        'days': transition_days,
                        'storageClass': storage_class
                    },
                ]
            },
            'region': region,
            'replicationConfiguration': {
                'regions': regions,
                'roleArn': 'arn:aws:iam::' + delegated_admin_acct + ':role/service-role/AmazonSecurityLakeS3ReplicationRole'  # TODO: (ieviero) pass role arn
            }
        },
    ]
    return configurations


def create_sec_lake_in_rollup_regions(region, delegated_admin_acct, configuration_role_name, sl_configurations):
    
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-security-lake", delegated_admin_acct)  # TODO: (ieviero) use assume_role from sts class
    sl_client = delegated_admin_session.client("securitylake", region)
    
    security_lake = sl_client.create_data_lake(
        configurations= sl_configurations,
        metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/AmazonSecurityLakeMetaStoreManagerV2', # TODO: (ieviero) pass role arn
    )
    LOGGER.info(f"create_sec_lake_in_rollup_regions: {security_lake}")


def create_security_lake(region, delegated_admin_acct, configuration_role_name, sl_configurations):
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-security-lake", delegated_admin_acct)
    sl_client = delegated_admin_session.client("securitylake", region)

    security_lake = sl_client.create_data_lake(
        configurations= sl_configurations,
        metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/AmazonSecurityLakeMetaStoreManagerV2',
        # tags=[
        #     {
        #         'key': 'string',
        #         'value': 'string'
        #     },
        # ]
    )
    LOGGER.info(f"create_security_lake: {security_lake}")


def set_aws_log_source(configuration_role_name, delegated_admin_acct, regions, sources):
    # TODO: (ieviero) add check if source already exists
    for region in regions:
        for source in sources:
            delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-security-lake", delegated_admin_acct)
            sl_client = delegated_admin_session.client("securitylake", region)
            log_sources = sl_client.create_aws_log_source(
                sources=[
                    {
                        'regions': regions,
                        'sourceName': source,
                        'sourceVersion': '2.0'
                    },
                ]
            )

# def disable_organization_admin_account(regions: list) -> None:
#     """Disable the organization admin account.

#     Args:
#         regions: AWS Region List
#     """
#     for region in regions:
#         sl_client: SecurityLakeClient = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
#         response = sl_client.disable_organization_admin_account()
#         api_call_details = {"API_Call": "securitylake:DeregisterDataLakeDelegatedAdministrator", "API_Response": response}
#         LOGGER.info(api_call_details)
#         LOGGER.info(f"Admin Account Disabled in {region}")
#         sleep(20)


# def set_auto_enable_security_lake_in_org(
#     region: str,
#     sl_client: SecurityLakeClient,
#     sources: list,
# ) -> None:
#     """Set auto enable for security lake in organizations.

#     Args:
#         region: AWS Region
#         sl_client: boto3 SecurityLakeClient client

#     Raises:
#         Exception: Generic Exception
#     """
#     try:
#         LOGGER.info(f"configuring auto-enable security lake CreateDataLakeOrganizationConfiguration in region {region} for {sources}")
#         create_organization_configuration_response = sl_client.create_data_lake_organization_configuration()
#         api_call_details = {
#             "API_Call": "SecurityLakeClient:CreateDataLakeOrganizationConfiguration",
#             "API_Response": update_organization_configuration_response,
#         }
#         LOGGER.info(api_call_details)
#         LOGGER.info(f"security lake organization auto-enable configuration updated in {region}")
#     except Exception as e:
#         LOGGER.error(f"Error calling UpdateOrganizationConfiguration {e}.\n Graph arn: {graph_arn}, region {region}")
#         raise


def get_unprocessed_account_details(create_members_response: CreateMembersResponseTypeDef, accounts: list) -> list:
    """Get unprocessed account details.

    Args:
        create_members_response: CreateMembersResponseTypeDef
        accounts: list

    Raises:
        ValueError: Internal Error creating member accounts

    Returns:
        remaining account list
    """
    remaining_accounts = []

    for unprocessed_account in create_members_response["UnprocessedAccounts"]:
        if "error" in unprocessed_account["Reason"]:
            LOGGER.error(f"{unprocessed_account}")
            raise ValueError(f"Internal Error creating member accounts: {unprocessed_account['Reason']}") from None
        for account_record in accounts:
            LOGGER.info(f"Unprocessed Account {unprocessed_account}")
            if account_record["AccountId"] == unprocessed_account["AccountId"] and unprocessed_account["Reason"] != "Account is already a member":
                remaining_accounts.append(account_record)
    return remaining_accounts


def create_service_linked_role(account_id: str, configuration_role_name: str) -> None:
    """Create service linked role in the given account.

    Args:
        account_id (str): Account ID
        configuration_role_name (str): IAM configuration role name
    """
    LOGGER.info(f"creating service linked role for account {account_id}")
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-security-lake-create-srl", account_id)
    iam_client: IAMClient = account_session.client("iam")
    common.create_service_linked_role(  #  TODO: (ieviero) move to iam class
        "AWSServiceRoleForSecurityLake",
        "securitylake.amazonaws.com",
        "A service-linked role required for Amazon Security Lake to access your resources.",
        iam_client,
    )


def delete_security_lake(configuration_role_name, delegated_admin_acct, region, regions):
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-disable-security-lake", delegated_admin_acct)
    sl_client = delegated_admin_session.client("securitylake", region)
    response = sl_client.delete_data_lake(
        regions=regions
    )
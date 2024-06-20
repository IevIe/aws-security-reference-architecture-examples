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
import random
from typing import TYPE_CHECKING

import boto3
import botocore
import common
from botocore.exceptions import ClientError

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


def create_service_linked_role(account_id: str, configuration_role_name: str) -> None:
    """Create service linked role in the given account.

    Args:
        account_id (str): Account ID
        configuration_role_name (str): IAM configuration role name
    """
    LOGGER.info(f"Creating service linked role in account {account_id}...")
    account_session: boto3.Session = common.assume_role(configuration_role_name, "sra-security-lake-create-slr", account_id)
    iam_client: IAMClient = account_session.client("iam")
    common.create_service_linked_role(  #  TODO: (ieviero) move to iam class
        "AWSServiceRoleForSecurityLake",
        "securitylake.amazonaws.com",
        "A service-linked role required for Amazon Security Lake to access your resources.",
        iam_client,
    )


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
    LOGGER.info(f"Checking if delegated administrator already registered for '{service_principal}' service principal.")
    delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

    if not delegated_administrators["DelegatedAdministrators"]:
        LOGGER.info(f"Delegated administrator for '{service_principal}' service principal not registered.")
        return False
    elif delegated_administrators["DelegatedAdministrators"][0]["Id"] == delegated_admin_account_id:
        LOGGER.info(f"Account {delegated_admin_account_id} already registered as delegated administrator for '{service_principal}' service principal.")
        return True
    elif delegated_administrators["DelegatedAdministrators"][0]["Id"] != delegated_admin_account_id:
        LOGGER.info(f"Account: {delegated_administrators['DelegatedAdministrators'][0]['Id']} already registered for '{service_principal}' service principal. Deregistering account {delegated_administrators['DelegatedAdministrators'][0]['Id']} to register Log Archive account {delegated_admin_account_id}")
        deregister_security_lake_admin(delegated_administrators['DelegatedAdministrators'][0]['Id'], region)
        return False
    else:
        LOGGER.info("Delegated administrator check error occured...")
        return False


def check_data_lake_exists(sl_client, region):
    try:
        response = sl_client.list_data_lakes(regions=[region])
        if not response["dataLakes"]:
            return False
        else:
            return True
    except ClientError as error:
        LOGGER.error(f"Error calling list_data_lakes: {error}")
        raise
    

#  register delegated admin for securitylake.amazonwas.com
def register_delegated_admin(admin_account_id: str, region: str, service_principal) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region

    Raises:
        Exception: Generic Exception

    Returns:
        bool: True if the delegated administrator registered, False otherwise
    """
    sl_client = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    register_admin_retries = 5
    base_delay = 0.5
    max_delay = 30
    admin_registered = False
    for attempt in range(register_admin_retries):
        try:
            if not check_organization_admin_enabled(admin_account_id, service_principal, region):
                LOGGER.info(f"Registering security lake delegated administrator account {admin_account_id}...")
                sleep(base_delay)
                delegated_admin_response = sl_client.register_data_lake_delegated_administrator(accountId=admin_account_id)
                api_call_details = {"API_Call": "securitylake:RegisterDataLakeDelegatedAdministrator", "API_Response": delegated_admin_response}
                LOGGER.info(api_call_details)
                admin_registered = True
                break
            else:
                break
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == "ThrottlingException":
                LOGGER.info(f"'ThrottlingException' occurred. Retrying ({attempt+1}/{register_admin_retries})...")
                delay = min(base_delay * (2 ** attempt), max_delay)
                delay += random.uniform(0, 1)
                sleep(delay)
            elif error_code == 'ConflictException':
                LOGGER.info(f"'ConflictException' occurred: {e}. Delegated administrator already registered ...")
                admin_registered = True
                break
            else:
                LOGGER.error(f"Error calling RegisterDataLakeDelegatedAdministrator for account {admin_account_id}) in {region}: {e}.")
                raise
    if not admin_registered:
        LOGGER.error(f"Error registering delegated administrator account for '{service_principal}' service principal.")


def deregister_security_lake_admin(admin_account_id, region):  # TODO: (ieviero) used only to change delegated administrator to log arcive account if admin was already registered
    sl_client = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    try:
        LOGGER.info(f"Deregistering delegated admin account {admin_account_id}")
        delegated_admin_response = sl_client.deregister_data_lake_delegated_administrator()
        api_call_details = {"API_Call": "securitylake:DeregisterDataLakeDelegatedAdministrator", "API_Response": delegated_admin_response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error(f"Error calling DeregisterDataLakeDelegatedAdministrator {e}. For account {admin_account_id}) in {region}")
        raise


def set_configurations(region):  # TODO: (ieviero) create kms key
    configurations=[
        {
            'encryptionConfiguration': {
                'kmsKeyId': 'S3_MANAGED_KEY'
            },
            'region': region,
        },
    ]
    return configurations


def create_security_lake(sl_client, delegated_admin_acct, sl_configurations):
    retries = 5
    base_delay = 0.5
    max_delay = 30
    data_lake_created = False
    for attempt in range(retries):
        try:
            security_lake_response = sl_client.create_data_lake(
                configurations= sl_configurations,
                metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/AmazonSecurityLakeMetaStoreManagerV2',  # TODO: (ieviero) pass role arn
                # tags=[{'key': 'string','value': 'string'},]
            )
            api_call_details = {"API_Call": "securitylake:CreateDataLake", "API_Response": security_lake_response}   # TODO: ieviero get the status of SL from response
            LOGGER.info(api_call_details)
            data_lake_created = True
            break
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['BadRequestException','ConflictException']:
                LOGGER.info(f"'{error_code}' occurred: {e}. Retrying ({attempt+1}/{retries})...")
                delay = min(base_delay * (2 ** attempt), max_delay)
                delay += random.uniform(0, 1)
                sleep(delay)
            else:
                LOGGER.error(f"Error calling CreateDataLake: {e}")
                raise

    if not data_lake_created:
        LOGGER.error(f"Error creating security lake")


def check_log_source_exists(client, accounts, region, source, source_version):
    new_accounts = []
    existing_accounts = []

    response = client.list_log_sources(
        accounts=accounts,
        regions=[region],
        sources=[
            {
                'awsLogSource': {
                    'sourceName': source,
                    'sourceVersion': source_version
                },
            },
        ]
    )
    if not response['sources']:
        LOGGER.info(f"Log and event source {source} not found in {region}")
        return False, accounts
    else:
        for i in response["sources"]:
            if [i][0]['account'] in accounts:
                if [i][0]['account'] not in existing_accounts:
                    existing_accounts.append([i][0]['account'])
        LOGGER.info(f"Log source {source} exists in account(s) {', '.join(existing_accounts)} in {region} region.")
        for account in accounts:
            if account in existing_accounts:
                pass
            else:
                new_accounts.append(account)

        return True, new_accounts


def set_aws_log_source(sl_client, regions, source, accounts, source_version):
    for region in regions:
        create_log_source_retries = 5
        base_delay = 0.5
        max_delay = 30
        log_source_created = False
        configurations = {'accounts': accounts, 'regions': [region], 'sourceName': source, 'sourceVersion': source_version}
        source_exists, new_accounts = check_log_source_exists(sl_client, accounts, region, source, source_version)

        if source_exists and new_accounts:
            configurations.update({'accounts': new_accounts})

        for attempt in range(create_log_source_retries):
            if source_exists and not new_accounts:
                log_source_created = True
                break
            else:
                try:
                    LOGGER.info(f"Creating log and events source {source} in account(s) {', '.join(configurations['accounts'])} in {region} region...")
                    sl_client.create_aws_log_source(sources=[configurations])
                    log_source_created = True
                    LOGGER.info(f"Log and events source {source} created in account(s) {', '.join(configurations['accounts'])} in {region} region...")
                    break
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'ConflictException':
                        LOGGER.info(f"'ConflictException' occurred. Retrying ({attempt+1}/{create_log_source_retries})...")
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        delay += random.uniform(0, 1)
                        sleep(delay)
                    else:
                        LOGGER.error(f"Error calling CreateAwsLogSource {e}.")
                        raise
    if not log_source_created:
        LOGGER.error(f"Failed to create log and events source {source} after {create_log_source_retries} attempts.")


def update_security_lake(sl_client, delegated_admin_acct, sl_configurations):  # TODO: parametarize iam role
    try:
        update_sl_response = sl_client.update_data_lake(
            configurations= sl_configurations,
            metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/AmazonSecurityLakeMetaStoreManagerV2',
            # tags=[{'key': 'string','value': 'string'},]
        )
        api_call_details = {"API_Call": "securitylake:UpdateSecurityLake", "API_Response": update_sl_response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error(f"Error calling UpdateSecurityLake {e}")
        raise


# subscribers
def list_subscribers(sl_client, subscriber_name, next_token: str = EMPTY_STRING):
    subscriber_exists = False
    subscriber_id = ""
    external_id = ""
    try:
        if next_token != EMPTY_STRING:
            response = sl_client.list_subscribers(maxResults=1, nextToken=next_token)
        else:
            response = sl_client.list_subscribers(maxResults=1)
        
        if response['subscribers']:
            for subscriber in response['subscribers']:
                if subscriber_name in subscriber['subscriberName']:
                    subscriber_id = subscriber['subscriberId']
                    external_id = subscriber['subscriberIdentity']['externalId']
                    subscriber_exists = True
                    LOGGER.info(f"Subscriber {subscriber_name} found with {subscriber_id} id and {external_id}")
                    return subscriber_exists, subscriber_id, external_id

                elif "nextToken" in response:
                    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name, response["nextToken"])  

                else:
                    return subscriber_exists, subscriber_id, external_id
            return subscriber_exists, subscriber_id, external_id
        
        else:
            LOGGER.info(f"No subscribers found")
            return subscriber_exists, subscriber_id, external_id

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info(f"Error calling ListSubscribers: {e}. Skipping...")  # todo: stop process if error
        else:
            LOGGER.error(f"Error calling ListSubscribers {e}.")
            raise


#  creating subscribers for security lake
def create_subscribers(sl_client, data_access, source_types, external_id, principal, subscriber_name, region, source_version):
    subscriber_sources = []
    for source in source_types:
        aws_log_source={'awsLogSource': {'sourceName': source, 'sourceVersion': source_version},}
        subscriber_sources.append(aws_log_source)
    LOGGER.info(f"Subscriber '{subscriber_name}' log and events sources: {subscriber_sources}")

    resource_share_arn = ""
    # resource_share_name = ""
    try:
        response = sl_client.create_subscriber(
            accessTypes=[data_access],
            sources=subscriber_sources,
            subscriberIdentity={
                'externalId': external_id,
                'principal': principal
            },
            subscriberName=subscriber_name,
            # tags=[{'key': 'string','value': 'string'},]
        )
        api_call_details = {"API_Call": "securitylake:CreateSubscriber", "API_Response": response}
        LOGGER.info(api_call_details)
        subscriber_id = response['subscriber']['subscriberId']
        if data_access == 'LAKEFORMATION':
            resource_share_arn = response['subscriber']['resourceShareArn']
            # resource_share_name = response['subscriber']['resourceShareName']
            return subscriber_id, resource_share_arn
        return subscriber_id, "s3_data_access"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ConflictException':
            LOGGER.info("'ConflictException' occurred. Subscriber with specified configurations already exists")
            return "error occured", error_code
        else:
            LOGGER.error(f"Error calling CreateSubscriber: {e}.")
            raise


#  subscriber notification
def create_subscriber_notification(sl_client, subscriber_id):  # TODO: (ieviero) add https endopoint subscriber?
    try:
        response = sl_client.create_subscriber_notification(
            configuration={'sqsNotificationConfiguration': {}},
            subscriberId=subscriber_id
        )
        api_call_details = {"API_Call": "securitylake:CreateSubscriberNotification", "API_Response": response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error(f"Error calling CreateSubscriberNotification {e}.")
        raise


def update_subscriber(sl_client, subscriber_id, source_types, external_id, principal, subscriber_name, source_verison):
    subscriber_sources = []
    for source in source_types:
        aws_log_source={'awsLogSource': {'sourceName': source, 'sourceVersion': source_verison},}
        subscriber_sources.append(aws_log_source)
    LOGGER.info(f"Subscriber '{subscriber_name}' log and events sources: {subscriber_sources}")

    try:
        response = sl_client.update_subscriber(
            sources=subscriber_sources,
            subscriberId=subscriber_id,
            subscriberIdentity={
                'externalId': external_id,
                'principal': principal
            },
            subscriberName=subscriber_name
        )
        api_call_details = {"API_Call": "securitylake:UpdateSubscriber", "API_Response": response}
        LOGGER.info(api_call_details)
        if response['subscriber']['accessTypes'] == ['LAKEFORMATION']:
            resource_share_arn = response['subscriber']['resourceShareArn']
            # resource_share_name = response['subscriber']['resourceShareName']
            return resource_share_arn
        return "s3_data_access"
    except ClientError as e:
        LOGGER.error(f"Error calling CreateSubscriber {e}.")
        raise


def update_subscriber_notification(sl_client, subscriber_id):
    try:
        response = sl_client.update_subscriber_notification(
            configuration={'sqsNotificationConfiguration': {}},
            subscriberId=subscriber_id
        )
        api_call_details = {"API_Call": "securitylake:UpdateSubscriberNotification", "API_Response": response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error(f"Error calling UpdateSubscriberNotification {e}.")
        raise


#  Configure resources in subscriber account
def configure_resource_share_in_subscriber_acct(ram_client, resource_share_arn):
    try:
        paginator = ram_client.get_paginator("get_resource_share_invitations")
        for page in paginator.paginate(PaginationConfig={"PageSize": 20}):
            if page['resourceShareInvitations']:
                for invitation in page['resourceShareInvitations']:
                    if resource_share_arn in invitation['resourceShareArn']:
                        if invitation['status'] == 'PENDING':
                            ram_client.accept_resource_share_invitation(
                                resourceShareInvitationArn=invitation['resourceShareInvitationArn'],
                            )
                            LOGGER.info(f"Accepted resource share invitation {invitation['resourceShareInvitationArn']} for {resource_share_arn}")
                            sleep(10)
                            break
                        else:
                            pass
                    else:
                        LOGGER.info(f"Resource share invitation for {resource_share_arn} not found.")
            else:
                LOGGER.info(f"No resource share invitations found")
    except ClientError as e:
        LOGGER.info(f"Error calling GetResourceShareInvitations: {e}.")
        raise


def get_shared_resource_names(ram_client, resource_share_arn):  # TODO: add paginator
    database_name = ""
    tables = []
    sleep(5)
    response = ram_client.list_resources(
        resourceOwner='OTHER-ACCOUNTS',
        resourceShareArns=[resource_share_arn]
    )
    if response['resources']:
        for resource in response['resources']:
            if resource['type'] == "glue:Database":
                database_name = resource['arn'].split('/')[-1]
            elif resource['type'] == "glue:Table":
                tables.append(resource['arn'].split('/')[-1])
        return database_name, tables
    else:
        LOGGER.info(f"No resources found for {resource_share_arn}")

    return database_name, tables


def create_db_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name):  # TODO: get best practices/permissions for glue database
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    glue_client = subscriber_session.client("glue", region)
    
    try:
        response = glue_client.create_database(
            CatalogId=subscriber_acct,
            DatabaseInput={
                'Name': shared_db_name})
                # 'CreateTableDefaultPermissions': [
                #     {
                #         'Principal': {
                #             'DataLakePrincipalIdentifier': subscriber_acct
                #         },
                #         'Permissions': ['ALL']},],},)   # TODO: (ieviero) work on permissions
        api_call_details = {"API_Call": "glue:CreateDatabase", "API_Response": response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AlreadyExistsException':
            LOGGER.info(f"Database '{shared_db_name}' exists in {region} region.")
        else:
            LOGGER.error(f"Error calling CreateDatabase {e}.")
            raise


def create_table_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name, shared_table_names, security_lake_acct):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    glue_client = subscriber_session.client("glue", region)
    for table in shared_table_names:
        try:
            response = glue_client.create_table(
                DatabaseName=shared_db_name,
                TableInput={
                    'Name': table,
                    'TargetTable': {
                        'CatalogId': security_lake_acct,
                        'DatabaseName': shared_db_name,
                        'Name': table
                    },
                })
            api_call_details = {"API_Call": "glue:CreateTable", "API_Response": response}
            LOGGER.info(api_call_details)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AlreadyExistsException':
                LOGGER.info(f"Table '{table}' already exists in {region} region.")
            else:
                LOGGER.error(f"Error calling glue:CreateTable {e}")
                raise


def set_audit_subscriber_log_sources(client, region, source_version):  # TODO: use to get all enabled sources
    log_sources = ["ROUTE53", "VPC_FLOW", "SH_FINDINGS", "CLOUD_TRAIL_MGMT", "LAMBDA_EXECUTION", "S3_DATA", "EKS_AUDIT", "WAF"]
    existing_log_sources = []

    for source in log_sources:
        try:
            response = client.list_log_sources(
                regions=[region],
                sources=[
                    {
                        'awsLogSource': {
                            'sourceName': source,
                            'sourceVersion': source_version
                        },
                    },
                ]
            )
            if not response['sources']:
                pass
            else:
                existing_log_sources.append(source)
            return  existing_log_sources
        except ClientError as e:
            LOGGER.error(f"Error calling ListLogSources {e}.")
            raise
    
    return existing_log_sources


def delete_subscriber_notification(sl_client, subscriber_name, region):
    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name)
    if subscriber_exists:
        LOGGER.info(f"Subscriber '{subscriber_name}' found in {region} region. Deleting subscriber notification...")
        try:
            response = sl_client.delete_subscriber_notification(
                subscriberId=subscriber_id
            )
            api_call_details = {"API_Call": "securitylake:DeleteSubscriberNotification", "API_Response": response}
            LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error(f"Error calling DeleteSubscriberNotification: {e}.")
            raise
    else:
        LOGGER.info(f"Subscriber '{subscriber_name}' not found in {region} region. Skipping delete subscriber notification...")


def delete_subscriber(sl_client, subscriber_name, region):
    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name)
    if subscriber_exists:
        LOGGER.info(f"Subscriber '{subscriber_name}' found in {region} region. Deleting subscriber...")
        try:
            response = sl_client.delete_subscriber(
                subscriberId=subscriber_id
            )
            api_call_details = {"API_Call": "securitylake:DeleteSubscriber", "API_Response": response}
            LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error(f"Error calling DeleteSubscriber {e}.")
            raise
    else:
        LOGGER.info(f"Subscriber not found in {region} region. Skipping delete subscriber...")


def delete_security_lake(configuration_role_name, delegated_admin_acct, region, regions):
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-disable-security-lake", delegated_admin_acct)
    sl_client = delegated_admin_session.client("securitylake", region)
    try:
        response = sl_client.delete_data_lake(
            regions=regions
        )
        api_call_details = {"API_Call": "securitylake:DeleteDataLake", "API_Response": response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info(f"'ResourceNotFoundException' occured: {e}. Skipping delete...")
        else:
            LOGGER.error(f"Error calling DeleteDataLake {e}.")
            raise


def deregister_administrator_security_lake(region: str) -> None:  # home region only needed
    """Disable the organization admin account.

    Args:
        regions: AWS Region List
    """
    sl_client: SecurityLakeClient = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    try:
        response = sl_client.deregister_data_lake_delegated_administrator()
        sleep(SECURITY_LAKE_THROTTLE_PERIOD)
        api_call_details = {"API_Call": "securitylake:DeregisterDataLakeDelegatedAdministrator", "API_Response": response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"Admin Account Disabled in {region}")
    except ClientError as e:
        LOGGER.error(f"Error calling DeregisterDataLakeDelegatedAdministrator {e}.")
        raise


def deregister_administrator_organizations(delegated_admin_account_id: str, service_principal: str) -> None:
    """Deregister the delegated administrator account for the provided service principal.

    Args:
        delegated_admin_account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal format: service_name.amazonaws.com

    """
    LOGGER.info(f"Deregistering delegated administrator account {delegated_admin_account_id} for {service_principal} service principal")

    try:
        delegated_admin_response = ORG_CLIENT.deregister_delegated_administrator(AccountId=delegated_admin_account_id, ServicePrincipal=service_principal, )
        api_call_details = {"API_Call": "organizations:DeregisterOrganizationDelegatedAdmin", "API_Response": delegated_admin_response}
        LOGGER.info(api_call_details)
        LOGGER.info(f"Delegated admin ({delegated_admin_account_id}) deregistered")
        delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

        LOGGER.debug(str(delegated_administrators))

        if not delegated_administrators:
            LOGGER.info(f"The deregister was successful for the {service_principal} delegated administrator")
    except ORG_CLIENT.exceptions.AccountNotRegisteredException:
        LOGGER.info(f"Account: {delegated_admin_account_id} not registered for {service_principal}")

# def create_sec_lake_in_rollup_regions(region, delegated_admin_acct, configuration_role_name, sl_configurations):
    
#     delegated_admin_session = common.assume_role(configuration_role_name, "sra-enable-security-lake", delegated_admin_acct)  # TODO: (ieviero) use assume_role from sts class
#     sl_client = delegated_admin_session.client("securitylake", region)
    
#     security_lake = sl_client.create_data_lake(
#         configurations= sl_configurations,
#         metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/AmazonSecurityLakeMetaStoreManagerV2', # TODO: (ieviero) pass role arn
#     )
#     LOGGER.info(f"create_sec_lake_in_rollup_regions: {security_lake}")


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

# def get_unprocessed_account_details(create_members_response: CreateMembersResponseTypeDef, accounts: list) -> list:
#     """Get unprocessed account details.

#     Args:
#         create_members_response: CreateMembersResponseTypeDef
#         accounts: list

#     Raises:
#         ValueError: Internal Error creating member accounts

#     Returns:
#         remaining account list
#     """
#     remaining_accounts = []

#     for unprocessed_account in create_members_response["UnprocessedAccounts"]:
#         if "error" in unprocessed_account["Reason"]:
#             LOGGER.error(f"{unprocessed_account}")
#             raise ValueError(f"Internal Error creating member accounts: {unprocessed_account['Reason']}") from None
#         for account_record in accounts:
#             LOGGER.info(f"Unprocessed Account {unprocessed_account}")
#             if account_record["AccountId"] == unprocessed_account["AccountId"] and unprocessed_account["Reason"] != "Account is already a member":
#                 remaining_accounts.append(account_record)
#     return remaining_accounts0000000000000000000000000000000000000000000000000000000000000000000000000000000
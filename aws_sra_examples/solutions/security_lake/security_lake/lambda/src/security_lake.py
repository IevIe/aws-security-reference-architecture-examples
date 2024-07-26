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
from typing import TYPE_CHECKING, List, Set
from collections import namedtuple

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
KEY = "sra-solution"
VALUE = "sra-security-lake"
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
    LOGGER.info("Checking if delegated administrator registered for '%s' service principal.", service_principal)
    try:
        delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)
        if not delegated_administrators["DelegatedAdministrators"]:
            LOGGER.info("Delegated administrator not registered for '%s' service principal.", service_principal)
            return False
        elif delegated_administrators["DelegatedAdministrators"][0]["Id"] == delegated_admin_account_id:
            LOGGER.info("Account %s already registered as delegated administrator for '%s' service principal.", delegated_admin_account_id, service_principal)
            return True
        else:
            LOGGER.info("Account %s already registered as delegated administrator for '%s' service principal.", delegated_admin_account_id, service_principal)
            # LOGGER.info("Deregistering account %s to delegate administration to Log Archive account %s", delegated_administrators['DelegatedAdministrators'][0]['Id'], delegated_admin_account_id)
            LOGGER.info("Important: removing the delegated Security Lake administrator deletes your data lake and disables Security Lake for the accounts in your organization.")
            raise ValueError("Deregister account %s to delegate administration to Log Archive account %s", delegated_administrators['DelegatedAdministrators'][0]['Id'], delegated_admin_account_id)
            # deregister_security_lake_admin(delegated_administrators['DelegatedAdministrators'][0]['Id'], region)
    except ClientError as e:
        LOGGER.error("Delegated administrator check error occurred: %s", e)
        return False


#  register delegated admin for securitylake.amazonwas.com
def register_delegated_admin(admin_account_id: str, region: str, service_principal) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region

    Raises:
        Error

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
                LOGGER.info("Registering delegated administrator (%s)...", admin_account_id)
                sl_client.register_data_lake_delegated_administrator(accountId=admin_account_id)
                LOGGER.info("Account %s registered as delegated administrator for '%s' service principal.", admin_account_id, service_principal)
                admin_registered = True
                break
            else:
                admin_registered = True
                break
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == "ThrottlingException":
                LOGGER.info("'ThrottlingException' occurred. Retrying (%d/%d)...", attempt+1, register_admin_retries)
                delay = min(base_delay * (2 ** attempt), max_delay)
                delay += random.uniform(0, 1)
                sleep(delay)
            elif error_code == 'ConflictException':
                LOGGER.info("'ConflictException' occurred: %s. Delegated administrator already registered ...", e)
                admin_registered = True
                break
            else:
                LOGGER.error("Error calling RegisterDataLakeAdministrator for account %s in %s: %s.", admin_account_id, region, e)
                raise
        attempt += 1
        if attempt >= register_admin_retries:
            LOGGER.error("Error calling 'RegisterDataLakeDelegatedAdministrator'")
            break
    if not admin_registered:
        LOGGER.error("Error registering delegated administrator account for '%s' service principal.", service_principal)
        raise

def check_data_lake_exists(sl_client, region, max_retries=MAX_RETRY, initial_delay=1):
    status = False
    retry_count = 0
    delay = initial_delay
    max_delay = 30

    while not status:
        try:
            response = sl_client.list_data_lakes(regions=[region])
            if not response["dataLakes"]:
                return status
            elif response["dataLakes"][0]["createStatus"] == "INITIALIZED":
                if retry_count < max_retries:
                    delay = min(delay * (2 ** retry_count), max_delay)
                    delay += random.uniform(0, 1)
                    LOGGER.info("Security Lake create status (%s): 'INITIALIZED'. Retrying (%d/%d) in %d seconds...", region, retry_count+1, max_retries, delay)
                    sleep(delay)
                    retry_count += 1
            elif response["dataLakes"][0]["createStatus"] == "COMPLETED":
                status = True
                return status
        except ClientError as e:
            LOGGER.info("Error checking data lake status for region: %s: %s...", region, e)
            raise

    if not status:
        LOGGER.info("Maximum retries reached. Data lake creation status for region %s is not 'COMPLETED'.", region)
        return status


def deregister_security_lake_admin(admin_account_id, region):  # TODO: (ieviero) used only to change delegated administrator to log arcive account if admin was already registered
    sl_client = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    try:
        LOGGER.info("Deregistering delegated admin account %s", admin_account_id)
        delegated_admin_response = sl_client.deregister_data_lake_delegated_administrator()
        api_call_details = {"API_Call": "securitylake:DeregisterDataLakeDelegatedAdministrator", "API_Response": delegated_admin_response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error("Error calling DeregisterDataLakeAdministrator %s. For account %s in %s", e, admin_account_id, region)
        raise


def set_configurations(region, kms_key_arn='S3_MANAGED_KEY'):  # TODO: (ieviero) create kms key
    configurations=[
        {
            'encryptionConfiguration': {
                'kmsKeyId': kms_key_arn
            },
            'region': region,
        },
    ]
    return configurations


def create_security_lake(sl_client, delegated_admin_acct, sl_configurations, region):  # todo: why region
    retries = 5
    base_delay = 10
    max_delay = 20
    data_lake_created = False
    
    for attempt in range(retries):
        try:
            security_lake_response = sl_client.create_data_lake(
                configurations= sl_configurations,
                metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/sra-AmazonSecurityLakeMetaStoreManager',  # TODO: (ieviero) pass role arn, edit partition
                tags=[{'key': KEY,'value': VALUE},]
            )
            api_call_details = {"API_Call": "securitylake:CreateDataLake", "API_Response": security_lake_response}   # TODO: ieviero get the status of SL from response
            # LOGGER.info(api_call_details)
            sleep(20)
            data_lake_created = True
            break

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['BadRequestException', 'ConflictException']:
                error_message = str(e)
                if "The CreateDataLake operation can't be used to update the settings for an existing data lake" in error_message:
                    raise ValueError("Security lake already exists.")
                else:
                    delay = min(base_delay * (1. ** attempt), max_delay)
                    delay += round(random.uniform(0, 1), 2)  # Add a small random delay
                    LOGGER.info("'%s' occurred: %s. Retrying (%d/%d) in %d seconds...", error_code, e, attempt+1, retries, delay)
                    sleep(delay)

            else:
                LOGGER.error("Error calling CreateDataLake: %s", e)
                raise
        attempt += 1
        if attempt >= retries:
            LOGGER.error("Error calling CreateDataLake: %s", e)
            break
    if not data_lake_created:
        LOGGER.error("Error creating security lake")
        raise

# def check_log_source(sl_client, org_accounts, regions, log_source_name, log_source_version):
#     accounts_to_disable_log_source = []
#     CheckLogSourceResult = namedtuple('CheckLogSourceResult', ['source_exists', 'accounts_to_disable'])

#     response = sl_client.list_log_sources(
#         accounts=org_accounts,
#         regions=regions,
#         sources=[{'awsLogSource': {'sourceName': log_source_name, 'sourceVersion': log_source_version}}]
#     )
#     LOGGER.info("!!!! running check_log_source line 244")
#     if not response['sources']:
#         # LOGGER.info("Log and event source %s not enabled", log_source_name)
#         return CheckLogSourceResult(False, accounts_to_disable_log_source)
#     else:
#         enabled_accounts = set(s['account'] for s in response["sources"] if s['account'] in org_accounts)
#         accounts_to_disable_log_source = enabled_accounts

#         LOGGER.info("Accounts to disable %s: %s", log_source_name, accounts_to_disable_log_source)  # TODO: remove
#         LOGGER.info("Regions to disable %s: %s", log_source_name, regions)

#         return CheckLogSourceResult(True, accounts_to_disable_log_source)


def check_log_source_enabled(sl_client, requested_accounts, org_accounts, requested_regions, log_source_name, log_source_version):
    accounts_to_enable = []
    accounts_to_disable_log_source = []
    regions_with_source_enabled = []
    CheckLogSourceResult = namedtuple('CheckLogSourceResult', ['source_exists', 'accounts_to_enable', 'accounts_to_disable', 'regions_to_enable'])

    response = sl_client.list_log_sources(
        accounts=org_accounts,
        regions=requested_regions,
        sources=[{'awsLogSource': {'sourceName': log_source_name, 'sourceVersion': log_source_version}}]
    )

    if not response['sources']:
        # LOGGER.info("Log and event source %s not enabled", log_source_name)
        return CheckLogSourceResult(False, requested_accounts, accounts_to_disable_log_source, requested_regions)
    else:
        enabled_accounts = set(s['account'] for s in response["sources"] if s['account'] in org_accounts)
        regions_with_source_enabled = list(set(s['region'] for s in response["sources"]))
        LOGGER.info("Log source %s exists in account(s) %s in %s region(s).", log_source_name, ', '.join(enabled_accounts), ', '.join(regions_with_source_enabled))

        accounts_to_enable = [account for account in requested_accounts if account not in enabled_accounts]
        accounts_to_disable_log_source = [account for account in enabled_accounts if account not in requested_accounts]
        regions_to_enable = [region for region in requested_regions if region not in regions_with_source_enabled]

        if accounts_to_enable:
            LOGGER.info("AWS log and event source %s  will be enabled in %s account(s)", log_source_name, ', '.join(accounts_to_enable))
        if accounts_to_disable_log_source:
            LOGGER.info("AWS log and event source %s will be deleted in %s account(s)", log_source_name, ', '.join(accounts_to_disable_log_source))
        if regions_to_enable:
            LOGGER.info("AWS log and event source %s will be enabled in %s region(s)", log_source_name, ', '.join(regions_to_enable))

        return CheckLogSourceResult(True, accounts_to_enable, accounts_to_disable_log_source, regions_to_enable)


def set_aws_log_source(sl_client, requested_regions, source, requested_accounts, org_accounts, source_version): # HERE
    result = check_log_source_enabled(sl_client, requested_accounts, org_accounts, requested_regions, source, source_version)
    accounts = list(result.accounts_to_enable)
    accounts_to_delete = list(result.accounts_to_disable)
    regions_to_enable = list(result.regions_to_enable)

    configurations = {'accounts': requested_accounts, 'regions': requested_regions, 'sourceName': source, 'sourceVersion': source_version}
    if result.source_exists and accounts:
        configurations.update({'accounts': accounts})
    
    if result.source_exists and not accounts and not regions_to_enable:
        pass
    
    else:
        create_log_source_retries = 10
        base_delay = 1
        max_delay = 30
        log_source_created = False

        for attempt in range(create_log_source_retries):
            try:
                LOGGER.info("Creating/updating log and events source %s in account(s) %s in %s region(s)", source, ', '.join(configurations['accounts']), ', '.join(requested_regions))
                sl_client.create_aws_log_source(sources=[configurations])
                log_source_created = True
                LOGGER.info("Created/updated log and events source %s in account(s) %s in %s region(s)", source, ', '.join(configurations['accounts']), ', '.join(configurations['regions']))
                break
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ConflictException':
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    delay += random.uniform(0, 1)
                    LOGGER.info("'ConflictException' occurred. Retrying (%d/%d) in %d seconds...", attempt+1, create_log_source_retries, delay)
                    sleep(delay)
                else:
                    LOGGER.error("Error calling CreateAwsLogSource: %s.", e)
                    raise
            attempt += 1
            if log_source_created or attempt >= create_log_source_retries:
                break
    
        if not log_source_created:
            LOGGER.error("Failed to create log events source %s after %d attempts.", source, create_log_source_retries)
            raise
      
    if accounts_to_delete:
        delete_aws_log_source(sl_client, requested_regions, source, accounts_to_delete, source_version)


def set_org_configuration_log_sources(org_sources, source_version):
    org_configuration_sources = []
    for source in org_sources:
        aws_log_source={'sourceName': source, 'sourceVersion': source_version}
        org_configuration_sources.append(aws_log_source)
    return org_configuration_sources


def get_org_configuration(sl_client):
    try:
        org_configruations = sl_client.get_data_lake_organization_configuration()
        if org_configruations['autoEnableNewAccount']:
            return True, org_configruations['autoEnableNewAccount']
        else:
            return False, org_configruations
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            return False, "ResourceNotFoundException"
        else:
            LOGGER.error("Error calling GetDataLakeConfiguration: %s.", e)
            raise


def create_organization_configuration(sl_client, region, org_sources, source_version):
    sources = set_org_configuration_log_sources(org_sources, source_version)
    try:
        sl_client.create_data_lake_organization_configuration(
            autoEnableNewAccount=[{'region': region, 'sources': sources},])
    except ClientError as e:
        LOGGER.error("Error calling CreateDataLakeConfiguration: %s.", e)
        raise
   

def update_security_lake(sl_client, delegated_admin_acct, sl_configurations):  # TODO: parametarize iam role
    try:
        sl_client.update_data_lake(
            configurations= sl_configurations,
            metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/sra-AmazonSecurityLakeMetaStoreManager',
            tags=[{'key': KEY,'value': VALUE},]
        )
    except ClientError as e:
        LOGGER.error("Error calling UpdateSecurityLake %s", e)
        raise


def set_sources_to_disable(org_configruations, region):
    sources_to_disable = []
    for configuration in org_configruations:
        if configuration['region'] == region:
            for source in configuration['sources']:
                sources_to_disable.append(source)

    return sources_to_disable


#  Update org configurations TODO: ieviero refactor
def update_organization_configuration(sl_client, region, org_sources, source_version, exisiting_org_configuration):
    delete_organization_configuration(sl_client, region, exisiting_org_configuration)
    sources = set_org_configuration_log_sources(org_sources, source_version)
    try:
        response = sl_client.create_data_lake_organization_configuration(
            autoEnableNewAccount=[{'region': region, 'sources': sources},])
        api_call_details = {"API_Call": "securitylake:CreateDataLakeOrganizationConfiguration", "API_Response": response}
        # LOGGER.info(api_call_details)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info("'ResourceNotFoundException' occurred: %s. Skipping delete...", e)
        else:
            LOGGER.error("Error calling securitylake:CreateDataLakeConfiguration: %s.", e)
            raise


#  Delete org configurations
def delete_organization_configuration(sl_client, region, exisiting_org_configuration):
    sources_to_disable = set_sources_to_disable(exisiting_org_configuration, region)
    if sources_to_disable:
        try:
            delete_response = sl_client.delete_data_lake_organization_configuration(
                autoEnableNewAccount=[{'region': region, 'sources': sources_to_disable},])
            api_call_details = {"API_Call": "securitylake:DeleteDataLakeOrganizationConfiguration", "API_Response": delete_response}
            # LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error("Error calling securitylake:DeleteDataLakeOrganizationConfiguration: %s.", e)
            raise


#  List subscribers
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
                    return subscriber_exists, subscriber_id, external_id

                elif "nextToken" in response:
                    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name, response["nextToken"])  

                else:
                    return subscriber_exists, subscriber_id, external_id
            return subscriber_exists, subscriber_id, external_id
        
        else:
            return subscriber_exists, subscriber_id, external_id

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info("Error calling ListSubscribers: %s. Skipping...", e)  # todo: stop process if error
            return subscriber_exists, subscriber_id, external_id
        else:
            LOGGER.error("Error calling ListSubscribers %s.", e)
            raise


#  creating subscribers for security lake
def create_subscribers(sl_client, data_access, source_types, external_id, principal, subscriber_name, region, source_version):
    subscriber_sources = []
    for source in source_types:
        aws_log_source={'awsLogSource': {'sourceName': source, 'sourceVersion': source_version},}
        subscriber_sources.append(aws_log_source)

    resource_share_arn = ""
    # resource_share_name = ""
    retries = 10
    base_delay = 1
    max_delay = 3
    done = False
    for attempt in range(retries):
        try:
            response = sl_client.create_subscriber(
                accessTypes=[data_access],
                sources=subscriber_sources,
                subscriberIdentity={
                    'externalId': external_id,
                    'principal': principal
                },
                subscriberName=subscriber_name,
                tags=[{'key': KEY,'value': VALUE},]
            )
            api_call_details = {"API_Call": "securitylake:CreateSubscriber", "API_Response": response}
            # LOGGER.info(api_call_details)
            subscriber_id = response['subscriber']['subscriberId']
            if data_access == 'LAKEFORMATION':
                resource_share_arn = response['subscriber']['resourceShareArn']
                # resource_share_name = response['subscriber']['resourceShareName']
                done = True
                return subscriber_id, resource_share_arn
            return subscriber_id, "s3_data_access"
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ConflictException':
                LOGGER.info("'ConflictException' occurred. Subscriber with specified configurations already exists")
                return "error occured", error_code
            elif error_code == 'BadRequestException':
                delay = min(base_delay * (2 ** attempt), max_delay)
                delay += random.uniform(0, 1)
                LOGGER.info("'BadRequestException' occurred calling securitylake:CreateSubscriber: %s. Retrying (%d/%d) in %d seconds...", e, attempt+1, retries, delay)
                sleep(delay)
            elif error_code == 'AccessDeniedException':
                delay = min(base_delay * (2 ** attempt), max_delay)
                delay += random.uniform(0, 1)
                LOGGER.info("'AccessDeniedException' occurred calling securitylake:CreateSubscriber: %s. Retrying (%d/%d) in %d seconds...", e, attempt+1, retries, delay)
                sleep(delay)
            else:
                LOGGER.error("Error calling CreateSubscriber: %s.", e)
                raise
        attempt += 1
        if done or attempt >= retries:
            break
    if not done:
        LOGGER.error("Subscriber not created. ")
        raise


#  create subscriber notification
def create_subscriber_notification(sl_client, subscriber_id):  # TODO: (ieviero) add https endopoint subscriber?
    try:
        response = sl_client.create_subscriber_notification(
            configuration={'sqsNotificationConfiguration': {}},
            subscriberId=subscriber_id
        )
        api_call_details = {"API_Call": "securitylake:CreateSubscriberNotification", "API_Response": response}
        # LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error("Error calling CreateSubscriberNotification %s.", e)
        raise


#  update subscriber
def update_subscriber(sl_client, subscriber_id, source_types, external_id, principal, subscriber_name, source_verison):
    subscriber_sources = []
    for source in source_types:
        aws_log_source={'awsLogSource': {'sourceName': source, 'sourceVersion': source_verison},}
        subscriber_sources.append(aws_log_source)

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
        # LOGGER.info(api_call_details)
        LOGGER.info("Subscriber '%s' updated", subscriber_name)
        if response['subscriber']['accessTypes'] == ['LAKEFORMATION']:
            resource_share_arn = response['subscriber']['resourceShareArn']
            # resource_share_name = response['subscriber']['resourceShareName']
            return resource_share_arn
        return "s3_data_access"
    except ClientError as e:
        LOGGER.error("Error calling CreateSubscriber %s.", e)
        raise


#  update subscriber notification
def update_subscriber_notification(sl_client, subscriber_id):
    try:
        response = sl_client.update_subscriber_notification(
            configuration={'sqsNotificationConfiguration': {}},
            subscriberId=subscriber_id
        )
        api_call_details = {"API_Call": "securitylake:UpdateSubscriberNotification", "API_Response": response}
        # LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error("Error calling UpdateSubscriberNotification %s.", e)
        raise


#  Configure resources in subscriber account
def configure_resource_share_in_subscriber_acct(ram_client, resource_share_arn):
    retries = 5
    base_delay = 0.5
    max_delay = 5
    invitation_accepted = False
    for attempt in range(retries):
        try:
            paginator = ram_client.get_paginator("get_resource_share_invitations")
            for page in paginator.paginate(PaginationConfig={"PageSize": 20}):
                if page['resourceShareInvitations']:
                    for invitation in page['resourceShareInvitations']:
                        if resource_share_arn == invitation['resourceShareArn']:
                            if invitation['status'] == 'ACCEPTED':
                                invitation_accepted = True
                                break
                            elif invitation['status'] == 'PENDING':
                                ram_client.accept_resource_share_invitation(
                                    resourceShareInvitationArn=invitation['resourceShareInvitationArn'],
                                )
                                delay = min(base_delay * (2 ** attempt), max_delay)
                                delay += random.uniform(0, 1)
                                LOGGER.info("Accepting resource share invitation for %s. Retrying (%d/%d) in %d seconds...", resource_share_arn, attempt+1, retries, delay)
                                sleep(delay)
                                break
                            else:
                                pass
                        else:
                            LOGGER.info("Resource share invitation for %s not found.", resource_share_arn)
                else:
                    LOGGER.info("No resource share invitations found")
        except ClientError as e:
            LOGGER.info("Error calling GetResourceShareInvitations: %s.", e)
            raise
        attempt += 1
        if invitation_accepted or attempt >= retries:
            break
    if not invitation_accepted:
        LOGGER.error("Error accepting resource share invitation ")
        raise

# get names of shared security lake tables
def get_shared_resource_names(ram_client, resource_share_arn):  # TODO: add paginator
    database_name = ""
    tables = []
    sleep(6)
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
        LOGGER.info("No resources found for %s", resource_share_arn)

    return database_name, tables


def create_db_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    glue_client = subscriber_session.client("glue", region)
    
    try:
        response = glue_client.create_database(
            CatalogId=subscriber_acct,
            DatabaseInput={
                'Name': shared_db_name + "_subscriber",
                'CreateTableDefaultPermissions': []
            }
                    
        )
        api_call_details = {"API_Call": "glue:CreateDatabase", "API_Response": response}
        # LOGGER.info(api_call_details)
        # sleep(30)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AlreadyExistsException':
            LOGGER.info("Database '%s' exists in %s region.", shared_db_name, region)
        else:
            LOGGER.error("Error calling CreateDatabase %s.", e)
            raise


def create_table_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name, shared_table_names, security_lake_acct):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    glue_client = subscriber_session.client("glue", region)
    for table in shared_table_names:
        try:
            response = glue_client.create_table(
                DatabaseName=shared_db_name + "_subscriber",
                TableInput={
                    'Name': "rl_" + table,
                    'TargetTable': {
                        'CatalogId': security_lake_acct,
                        'DatabaseName': shared_db_name,
                        'Name': table
                    },
                })
            api_call_details = {"API_Call": "glue:CreateTable", "API_Response": response}
            # LOGGER.info(api_call_details)
            set_lake_formation_permissions_sub(configuration_role_name, subscriber_acct, region, shared_db_name, table)
            set_lake_formation_permissions(configuration_role_name, subscriber_acct, region, shared_db_name, table)
            # set_lake_formation_permissions_taget(configuration_role_name, subscriber_acct, region, shared_db_name, table, security_lake_acct)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AlreadyExistsException':
                LOGGER.info("Table '%s' already exists in %s region.", table, region)
                set_lake_formation_permissions_sub(configuration_role_name, subscriber_acct, region, shared_db_name, table)
                set_lake_formation_permissions(configuration_role_name, subscriber_acct, region, shared_db_name, table)
                # set_lake_formation_permissions_taget(configuration_role_name, subscriber_acct, region, shared_db_name, table, security_lake_acct)
            else:
                LOGGER.error("Error calling glue:CreateTable %s", e)
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
            LOGGER.error("Error calling ListLogSources %s.", e)
            raise
    
    return existing_log_sources


def set_lake_formation_permissions(configuration_role_name, account, region, db_name, table_name):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", account)
    lf_client = subscriber_session.client("lakeformation", region)
    LOGGER.info("Setting lakeformation permissions for table %s", table_name)

    try:
        response = lf_client.grant_permissions(
            CatalogId=account,
            Principal={
                'DataLakePrincipalIdentifier': f'arn:aws:iam::{account}:role/sra-security-lake-query-subscriber'
            },
            Resource={
                'Database': {
                    'CatalogId': account,
                    'Name': db_name + '_subscriber'
                },
                'Table': {
                    'CatalogId': account,
                    'DatabaseName': db_name + '_subscriber',
                    'Name': "rl" + table_name
                },
                },
            Permissions=["ALL"],
            PermissionsWithGrantOption=["ALL"])
    except ClientError as e:
        LOGGER.error("Error calling GrantPermissions %s.", e)
        raise


def set_lake_formation_permissions_sub(configuration_role_name, account, region, db_name, table_name):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", account)
    lf_client = subscriber_session.client("lakeformation", region)
    LOGGER.info("Setting lakeformation permissions on resource link table 'rl_%s'", table_name)

    try:
        response = lf_client.grant_permissions(
            CatalogId=account,
            Principal={
                'DataLakePrincipalIdentifier': f'arn:aws:iam::{account}:role/sra-security-lake-query-subscriber'
            },
            Resource={
                'Table': {
                    'CatalogId': account,
                    'DatabaseName': db_name + '_subscriber',
                    'Name': "rl_" + table_name
                },
            },
            Permissions=["ALL"],
            PermissionsWithGrantOption=["ALL"])
    except ClientError as e:
        LOGGER.error("Error calling GrantPermissions %s.", e)
        raise


def set_lake_formation_permissions_taget(configuration_role_name, account, region, db_name, table_name, security_lake_acct):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", account)
    lf_client = subscriber_session.client("lakeformation", region)
    LOGGER.info("Setting lakeformation permissions on resource link target table %s", table_name)

    try:
        response = lf_client.grant_permissions(
            Principal={
                'DataLakePrincipalIdentifier': f'arn:aws:iam::{account}:role/sra-security-lake-query-subscriber'
            },
            Resource={
                'Table': {
                    'CatalogId': security_lake_acct,
                    'DatabaseName': db_name,
                    'Name': table_name,
                },
            },
            Permissions=["SELECT"],
            PermissionsWithGrantOption=["SELECT"])
    except ClientError as e:
        LOGGER.error("Error calling GrantPermissions %s.", e)
        raise    


def delete_subscriber_notification(sl_client, subscriber_name, region):
    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name)
    if subscriber_exists:
        LOGGER.info("Subscriber '%s' found in %s region. Deleting subscriber notification...", subscriber_name, region)
        try:
            response = sl_client.delete_subscriber_notification(
                subscriberId=subscriber_id
            )
            # api_call_details = {"API_Call": "securitylake:DeleteSubscriberNotification", "API_Response": response}
            # LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error("Error calling DeleteSubscriberNotification: %s.", e)
            raise
    else:
        LOGGER.info("Subscriber '%s' not found in %s region. Skipping delete subscriber notification...", subscriber_name, region)


def delete_subscriber(sl_client, subscriber_name, region):
    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name)
    if subscriber_exists:
        LOGGER.info("Subscriber '%s' found in %s region. Deleting subscriber...", subscriber_name, region)
        try:
            response = sl_client.delete_subscriber(
                subscriberId=subscriber_id
            )
            api_call_details = {"API_Call": "securitylake:DeleteSubscriber", "API_Response": response}
            # LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error("Error calling DeleteSubscriber %s.", e)
            raise
    else:
        LOGGER.info("Subscriber not found in %s region. Skipping delete subscriber...", region)


def delete_aws_log_source(sl_client, regions, source, accounts, source_version):
    configurations = {'accounts': accounts, 'regions': regions, 'sourceName': source, 'sourceVersion': source_version}
    try:
        LOGGER.info("Deleting AWS log source %s in %s accounts %s region(s)...", source, ', '.join(accounts), ', '.join(regions))
        sl_client.delete_aws_log_source(sources=[configurations])
        LOGGER.info("Deleting AWS log source %s in %s accounts %s region(s)...", source, ', '.join(accounts), ', '.join(regions))
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedException':
            LOGGER.info("'UnauthorizedException' occurred....")
        else:
            LOGGER.error("Error calling CreateAwsLogSource %s.", e)
            raise


def delete_security_lake(configuration_role_name, delegated_admin_acct, region, regions):
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-disable-security-lake", delegated_admin_acct)
    sl_client = delegated_admin_session.client("securitylake", region)
    try:
        response = sl_client.delete_data_lake(
            regions=regions
        )
        api_call_details = {"API_Call": "securitylake:DeleteDataLake", "API_Response": response}
        # LOGGER.info(api_call_details)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info("'ResourceNotFoundException' occurred: %s. Skipping delete...", e)
        elif error_code == 'UnauthorizedException':
            LOGGER.info("'UnauthorizedException' occurred: %s. Skipping delete...", e)
        else:
            LOGGER.error("Error calling DeleteDataLake %s.", e)
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
        # LOGGER.info(api_call_details)
        LOGGER.info("Admin Account Disabled")
    except ClientError as e:
        LOGGER.error("Error calling DeregisterDataLakeAdministrator %s.", e)
        raise


def deregister_administrator_organizations(delegated_admin_account_id: str, service_principal: str) -> None:
    """Deregister the delegated administrator account for the provided service principal.

    Args:
        delegated_admin_account_id: Delegated Administrator Account ID
        service_principal: AWS Service Principal format: service_name.amazonaws.com

    """
    LOGGER.info("Deregistering delegated administrator account %s for %s service principal", delegated_admin_account_id, service_principal)

    try:
        delegated_admin_response = ORG_CLIENT.deregister_delegated_administrator(AccountId=delegated_admin_account_id, ServicePrincipal=service_principal, )
        api_call_details = {"API_Call": "organizations:DeregisterOrganizationDelegatedAdmin", "API_Response": delegated_admin_response}
        # LOGGER.info(api_call_details)
        LOGGER.info("Delegated admin (%s) deregistered", delegated_admin_account_id)
        delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

        LOGGER.debug(str(delegated_administrators))

        if not delegated_administrators:
            LOGGER.info("The deregister was successful for the %s delegated administrator", service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException:
        LOGGER.info("Account: %s not registered for %s", delegated_admin_account_id, service_principal)
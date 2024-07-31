"""This script performs operations to enable, configure, and disable security lake.

Version: 1.0
'security_lake_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import concurrent.futures
import math
import os
from time import sleep
import random
from typing import TYPE_CHECKING, List, Set, Sequence, NamedTuple, Union, Literal
from collections import namedtuple

import boto3
import botocore
from botocore.config import Config
import common
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_securitylake import SecurityLakeClient
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_ram import RAMClient
    from mypy_boto3_glue import GlueClient
    from mypy_boto3_lakeformation import LakeFormationClient
    from mypy_boto3_securitylake.paginator import (
        GetDataLakeSourcesPaginator,
        ListDataLakeExceptionsPaginator,
        ListLogSourcesPaginator,
        ListSubscribersPaginator,
    )
    from mypy_boto3_securitylake.type_defs import (
        ListDataLakesResponseTypeDef,
        CreateDataLakeResponseTypeDef,
        AwsLogSourceConfigurationTypeDef,
        CreateSubscriberResponseTypeDef,
        LogSourceResourceTypeDef,
        DataLakeAutoEnableNewAccountConfigurationTypeDef,
        DataLakeAutoEnableNewAccountConfigurationOutputTypeDef,
    )
    from mypy_boto3_securitylake.literals import AwsLogSourceNameType
    
LOGGER = logging.getLogger("sra")


log_level = os.environ.get("LOG_LEVEL", logging.INFO)
LOGGER.setLevel(log_level)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
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
            LOGGER.info("Delegated administrator not registered for '%s'", service_principal)
            return False
        elif delegated_administrators["DelegatedAdministrators"][0]["Id"] == delegated_admin_account_id:
            LOGGER.info("Requested account %s already registered as delegated administrator for '%s'", delegated_admin_account_id, service_principal)
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
def register_delegated_admin(admin_account_id: str, region: str, service_principal: str) -> None:
    """Set the delegated admin account for the given region.

    Args:
        admin_account_id: Admin account ID
        region: AWS Region
        service_principal: AWS Service Principal

    Raises:
        Error

    Returns:
        bool: True if the delegated administrator registered, False otherwise
    """
    sl_client: SecurityLakeClient = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region, config=BOTO3_CONFIG)
    try:
        if not check_organization_admin_enabled(admin_account_id, service_principal, region):
            LOGGER.info("Registering delegated administrator (%s)...", admin_account_id)
            sl_client.register_data_lake_delegated_administrator(accountId=admin_account_id)
            LOGGER.info("Account %s registered as delegated administrator for '%s'", admin_account_id, service_principal)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ConflictException':
            LOGGER.info("'ConflictException' occurred: %s. Delegated administrator already registered ...", e)
        else:
            LOGGER.error("Error calling RegisterDataLakeAdministrator for account %s in %s: %s.", admin_account_id, region, e)
            raise



def check_data_lake_exists(sl_client: SecurityLakeClient, region: str, max_retries: int = MAX_RETRY, initial_delay: int =1) -> bool:
    """Check if Security Lake enabled for the given region.

    Args:
        sl_client: SecurityLakeClient
        region: AWS region
        max_retries: maximum number of retries
        initial_delay: initial delay in seconds

    Returns:
        status: True or False
    """
    status: bool = False
    retry_count: int = 0
    delay: float = initial_delay
    max_delay: int = 30
    while not status:
        try:
            response: ListDataLakesResponseTypeDef = sl_client.list_data_lakes(regions=[region])
            if not response["dataLakes"]:
                break
                # return status
            elif response["dataLakes"][0]["createStatus"] == "INITIALIZED":
                if retry_count < max_retries:
                    delay = min(delay * (2 ** retry_count), max_delay)
                    delay += random.uniform(0, 1)
                    LOGGER.info("Security Lake create status (%s): 'INITIALIZED'. Retrying (%d/%d) in %d seconds...", region, retry_count+1, max_retries, delay)
                    sleep(delay)
                    retry_count += 1
            elif response["dataLakes"][0]["createStatus"] == "COMPLETED":
                status = True
                # return status
                break
        except ClientError as e:
            LOGGER.info("Error checking data lake status for region: %s: %s...", region, e)
            raise

    if not status:
        LOGGER.info("Maximum retries reached. Data lake creation status for region %s is not 'COMPLETED'.", region)
    return status


def check_data_lake_status(sl_client: SecurityLakeClient, regions: list, retries: int = 0) -> bool:
    """Check Security Lake creation status for given regions.

    Args:
        sl_client (SecurityLakeClient): boto3 client
        regions (list): list of AWS regions
        retries (int, optional): Number of retries. Defaults to 0.

    Returns:
        bool: True if creation completed, False otherwise
    """
    all_completed: bool = False
    max_retries: int = 20
    regions_status_list: list = []
    while retries < max_retries:
        try:
            response: ListDataLakesResponseTypeDef = sl_client.list_data_lakes(regions=regions)
            for data_lake in response["dataLakes"]:
                create_status = data_lake["createStatus"]
                regions_status_list.append(create_status)
            if "INITIALIZED" not in regions_status_list:
                all_completed = True
                break
            if "INITIALIZED" in regions_status_list:
                LOGGER.info(f"Security Lake creation status: 'INITIALIZED'. Retrying ({retries+1}/{max_retries}) in 3 seconds...")
                sleep(3)
                retries += 1
                status = check_data_lake_status(sl_client, regions, retries)
                if status:
                    all_completed = True
                    break
        except ClientError as e:
            LOGGER.info(f"Error checking data lake status: {e}")

        if retries >= max_retries:
            LOGGER.error("Security Lake status not 'COMPLETED'")
            break

    return all_completed


def deregister_security_lake_admin(admin_account_id: str, region: str) -> None:  # TODO: (ieviero) used only to change delegated administrator to log arcive account if admin was already registered
    """Deregister Security LAke delegated administrator account.

    Args:
        admin_account_id (str): delegated administrator AWS account id
        region (str): AWS region
    """
    sl_client: SecurityLakeClient = MANAGEMENT_ACCOUNT_SESSION.client("securitylake", region)
    try:
        LOGGER.info("Deregistering delegated admin account %s", admin_account_id)
        sl_client.deregister_data_lake_delegated_administrator()
    except ClientError as e:
        LOGGER.error("Error calling DeregisterDataLakeAdministrator %s. For account %s in %s", e, admin_account_id, region)
        raise


def create_security_lake(sl_client: SecurityLakeClient, delegated_admin_acct: str, sl_configurations: list) -> None:  # todo: why region
    retries = 5
    base_delay = 10
    max_delay = 20
    data_lake_created = False
    
    for attempt in range(retries):
        try:
            security_lake_response: CreateDataLakeResponseTypeDef = sl_client.create_data_lake(
                configurations= sl_configurations,
                metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/sra-AmazonSecurityLakeMetaStoreManager',  # TODO: (ieviero) pass role arn, edit partition
                tags=[{'key': KEY,'value': VALUE},]
            )
            api_call_details = {"API_Call": "securitylake:CreateDataLake", "API_Response": security_lake_response}
            LOGGER.info(api_call_details)
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
            LOGGER.error("Error calling CreateDataLake")
            break
    if not data_lake_created:
        LOGGER.error("Error creating security lake")
        raise



class CheckLogSourceResult:
    def __init__(self, source_exists: bool, accounts_to_enable: list, accounts_to_disable: list, regions_to_enable: list):
        self.source_exists = source_exists
        self.accounts_to_enable = accounts_to_enable
        self.accounts_to_disable = accounts_to_disable
        self.regions_to_enable = regions_to_enable

def check_log_source_enabled(sl_client: SecurityLakeClient, requested_accounts: list, org_accounts: list, requested_regions: list, log_source_name: AwsLogSourceNameType, log_source_version: str) -> CheckLogSourceResult:
    """Check if AWS log and event source enabled.

    Args:
        sl_client: SecurityLakeClient
        requested_accounts: requested accounts
        org_accounts: organization accounts
        requested_regions: requested regions
        log_source_name: log source name
        log_source_version: log source version
    
    Returns:
        CheckLogSourceResult
    """
    accounts_to_enable: list = []
    accounts_to_disable_log_source: list = []
    regions_with_source_enabled: list = []

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


def add_aws_log_source(sl_client: SecurityLakeClient, aws_log_sources: list) -> None:
    create_log_source_retries = 10
    base_delay = 1
    max_delay = 30
    log_source_created = False
    for attempt in range(create_log_source_retries):
        try:
            LOGGER.info("Configuring requested AWS log and events sources")
            sl_client.create_aws_log_source(sources=aws_log_sources)
            log_source_created = True
            LOGGER.info("AWS log and event sources enabled")
            break
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ConflictException':
                delay = min(base_delay * (2 ** attempt), max_delay)
                delay += random.uniform(0, 1)
                LOGGER.info("'ConflictException' occurred %s. Retrying (%d/%d) in %d seconds...", e, attempt+1, create_log_source_retries, delay)
                sleep(delay)
            else:
                LOGGER.error("Error calling CreateAwsLogSource: %s.", e)
                raise
        attempt += 1
        if log_source_created or attempt >= create_log_source_retries:
            break

    if not log_source_created:
        LOGGER.error("Failed to create log events sources")
        raise


def set_aws_log_source(sl_client: SecurityLakeClient, requested_regions: list, source: AwsLogSourceNameType, requested_accounts: list, org_accounts: list, source_version: str) -> None:
    result = check_log_source_enabled(sl_client, requested_accounts, org_accounts, requested_regions, source, source_version)
    accounts = list(result.accounts_to_enable)
    accounts_to_delete = list(result.accounts_to_disable)
    regions_to_enable = list(result.regions_to_enable)

    configurations: AwsLogSourceConfigurationTypeDef = {'accounts': requested_accounts, 'regions': requested_regions, 'sourceName': source, 'sourceVersion': source_version}
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


def set_org_configuration_log_sources(org_sources: list, source_version: str) -> list:
    org_configuration_sources = []
    for source in org_sources:
        aws_log_source={'sourceName': source, 'sourceVersion': source_version}
        org_configuration_sources.append(aws_log_source)
    return org_configuration_sources


def get_org_configuration(sl_client: SecurityLakeClient) -> tuple:
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


def create_organization_configuration(sl_client: SecurityLakeClient, regions: list, org_sources: list, source_version: str, retry: int = 0) -> None:
    sources = set_org_configuration_log_sources(org_sources, source_version)
    auto_enable_config = []
    for region in regions:
        dis = {'region': region, 'sources': sources}
        auto_enable_config.append(dis)
    if retry < MAX_RETRY:
        try:
            sl_client.create_data_lake_organization_configuration(
                autoEnableNewAccount=auto_enable_config)
        except sl_client.exceptions.ConflictException:
                LOGGER.info("'ConflictException' occurred. Retrying...")
                sleep(5)
                create_organization_configuration(sl_client, regions, org_sources, source_version, retry + 1)
   

def update_security_lake(sl_client: SecurityLakeClient, delegated_admin_acct: str, sl_configurations: list) -> None:  # TODO: parametarize iam role
    try:
        sl_client.update_data_lake(
            configurations= sl_configurations,
            metaStoreManagerRoleArn='arn:aws:iam::' + delegated_admin_acct + ':role/sra-AmazonSecurityLakeMetaStoreManager'
        )
    except ClientError as e:
        LOGGER.error("Error calling UpdateSecurityLake %s", e)
        raise


def set_sources_to_disable(org_configruations: list, region: str) -> list:
    sources_to_disable = []
    for configuration in org_configruations:
        if configuration['region'] == region:
            for source in configuration['sources']:
                sources_to_disable.append(source)

    return sources_to_disable


#  Update org configurations TODO: ieviero refactor
def update_organization_configuration(sl_client: SecurityLakeClient, regions: list, org_source: list, source_version: str, exisiting_org_configuration: list) -> None:
    delete_organization_configuration(sl_client, regions, exisiting_org_configuration)
    sources = set_org_configuration_log_sources(org_source, source_version)
    autoenable_config = []
    for regioin in regions:
        region_config = {'region': regioin, 'sources': sources}
        autoenable_config.append(region_config)
    try:
        response = sl_client.create_data_lake_organization_configuration(autoEnableNewAccount=autoenable_config)
        api_call_details = {"API_Call": "securitylake:CreateDataLakeOrganizationConfiguration", "API_Response": response}
        LOGGER.info(api_call_details)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info("'ResourceNotFoundException' occurred: %s. Skipping delete...", e)
        else:
            LOGGER.error("Error calling securitylake:CreateDataLakeConfiguration: %s.", e)
            raise


#  Delete org configurations
def delete_organization_configuration(sl_client: SecurityLakeClient, regions: list, exisiting_org_configuration: list) -> None:
    # sources_to_disable = set_sources_to_disable(exisiting_org_configuration, regions)
    sources_to_disable =  exisiting_org_configuration  # todo remove
    if sources_to_disable:
        try:
            delete_response = sl_client.delete_data_lake_organization_configuration(
                autoEnableNewAccount=exisiting_org_configuration)
            api_call_details = {"API_Call": "securitylake:DeleteDataLakeOrganizationConfiguration", "API_Response": delete_response}
            LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error("Error calling securitylake:DeleteDataLakeOrganizationConfiguration: %s.", e)
            raise


#  List subscribers
def list_subscribers(sl_client: SecurityLakeClient, subscriber_name: str, next_token: str = EMPTY_STRING) -> tuple:
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


# create
def list_subscriber_resource_share(sl_client: SecurityLakeClient, subscriber_name: str, next_token: str = EMPTY_STRING) -> tuple:
    subscriber_exists = False
    resource_share_arn = ""
    external_id = ""
    try:
        if next_token != EMPTY_STRING:
            response = sl_client.list_subscribers(maxResults=10, nextToken=next_token)
        else:
            response = sl_client.list_subscribers(maxResults=10)
        
        if response['subscribers']:
            for subscriber in response['subscribers']:
                if subscriber_name == subscriber['subscriberName']:
                    external_id = subscriber['subscriberIdentity']['externalId']
                    resource_share_arn = subscriber['resourceShareArn']
                    subscriber_exists = True
                    return subscriber_exists, resource_share_arn, external_id

                elif "nextToken" in response:
                    subscriber_exists, resource_share_arn, external_id = list_subscribers(sl_client, subscriber_name, response["nextToken"])  

                else:
                    pass
            return subscriber_exists, resource_share_arn, external_id
        
        else:
            return subscriber_exists, resource_share_arn, external_id

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            LOGGER.info("Error calling ListSubscribers: %s. Skipping...", e)  # todo: stop process if error
            return subscriber_exists, resource_share_arn, external_id
        else:
            LOGGER.error("Error calling ListSubscribers %s.", e)
            raise


def create_subscribers(sl_client: SecurityLakeClient, data_access: Literal['LAKEFORMATION', 'S3'], source_types: list, external_id: str, principal: str, subscriber_name: str, region: str, source_version: str) -> tuple:
    subscriber_sources = [{'awsLogSource': {'sourceName': source, 'sourceVersion': source_version}} for source in source_types]
    resource_share_arn = ""
    # resource_share_name = ""
    try:
        response: CreateSubscriberResponseTypeDef = sl_client.create_subscriber(
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
        LOGGER.info(api_call_details)
        subscriber_id = response['subscriber']['subscriberId']
        if data_access == 'LAKEFORMATION':
            resource_share_arn = response['subscriber']['resourceShareArn']
            # resource_share_name = response['subscriber']['resourceShareName']
            done = True
            return subscriber_id, resource_share_arn
        else:
            return subscriber_id, "s3_data_access"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ConflictException':
            LOGGER.info("'ConflictException' occurred. Subscriber with specified configurations already exists")
            return "error occured", error_code
        # elif error_code == 'BadRequestException':
        #     LOGGER.info("'BadRequestException' occurred calling securitylake:CreateSubscriber")
        else:
            LOGGER.error(f"Error calling CreateSubscriber: {e}")
            raise

#  create subscriber notification
def create_subscriber_notification(sl_client: SecurityLakeClient, subscriber_id: str) -> None:  # TODO: (ieviero) add https endopoint subscriber
    try:
        response = sl_client.create_subscriber_notification(
            configuration={'sqsNotificationConfiguration': {}},
            subscriberId=subscriber_id
        )
        # api_call_details = {"API_Call": "securitylake:CreateSubscriberNotification", "API_Response": response}
        # LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error("Error calling CreateSubscriberNotification %s.", e)
        raise


#  update subscriber
def update_subscriber(sl_client: SecurityLakeClient, subscriber_id: str, source_types: list, external_id: str, principal: str, subscriber_name: str, source_verison: str) -> str:
    subscriber_sources = []
    for source in source_types:
        aws_log_source={'awsLogSource': {'sourceName': source, 'sourceVersion': source_verison},}
        subscriber_sources.append(aws_log_source)
    retries = 10
    base_delay = 1
    max_delay = 3
    done = False
    for attempt in range(retries):
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
            LOGGER.info("Subscriber '%s' updated", subscriber_name)
            if response['subscriber']['accessTypes'] == ['LAKEFORMATION']:
                resource_share_arn = response['subscriber']['resourceShareArn']
                # resource_share_name = response['subscriber']['resourceShareName']
                sleep(5)
                done = True
                return resource_share_arn
            return "s3_data_access"
        except sl_client.exceptions.BadRequestException:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    delay += random.uniform(0, 1)
                    LOGGER.info("'BadRequestException' occurred calling securitylake:UpdateSubscriber. Retrying (%d/%d) in %d seconds...", attempt+1, retries, delay)
                    sleep(delay)
        attempt += 1
        if done or attempt >= retries:
            break
    if not done:
        LOGGER.error("Subscriber not created. ")
        raise

    return resource_share_arn


#  update subscriber notification
def update_subscriber_notification(sl_client: SecurityLakeClient, subscriber_id: str) -> None:
    try:
        response = sl_client.update_subscriber_notification(
            configuration={'sqsNotificationConfiguration': {}},
            subscriberId=subscriber_id
        )
        # api_call_details = {"API_Call": "securitylake:UpdateSubscriberNotification", "API_Response": response}
        # LOGGER.info(api_call_details)
    except ClientError as e:
        LOGGER.error("Error calling UpdateSubscriberNotification %s.", e)
        raise


#  Configure resources in subscriber account
def configure_resource_share_in_subscriber_acct(ram_client: RAMClient, resource_share_arn: str) -> None:
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
                                LOGGER.info("Resource share invitation accepted")
                                break
                            elif invitation['status'] == 'PENDING':
                                ram_client.accept_resource_share_invitation(
                                    resourceShareInvitationArn=invitation['resourceShareInvitationArn'],
                                )
                                delay = min(base_delay * (2 ** attempt), max_delay)
                                delay += random.uniform(0, 1)
                                LOGGER.info("Accepting resource share invitation for %s. Retrying (%d/%d) in %d seconds...", resource_share_arn, attempt+1, retries, delay)
                                sleep(delay)
                                # break
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
def get_shared_resource_names(ram_client: RAMClient, resource_share_arn: str) -> tuple:
    database_name = ""
    tables = []
    retry = 0
    while retry < MAX_RETRY:
        try:
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
                LOGGER.info("No resources found for %s. Retrying", resource_share_arn)
                retry += 1
                sleep(5)
        except ClientError as e:
            LOGGER.error("Error calling ListResources %s.", e)
            raise

    LOGGER.error("Max retries reached. Unable to retrieve resource names.")
    return database_name, tables


def create_db_in_data_catalog(glue_client: GlueClient, configuration_role_name: str, region: str, subscriber_acct: str, shared_db_name: str) -> None:
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
            # LOGGER.info("Database '%s' exists in %s region.", shared_db_name, region)
            pass
        else:
            LOGGER.error(f"Error calling CreateDatabase: {e}")
            raise


def create_table_in_data_catalog(glue_client: GlueClient, configuration_role_name: str, region: str, subscriber_acct: str, shared_db_name: str, shared_table_names: str, security_lake_acct: str) -> None:
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
            # api_call_details = {"API_Call": "glue:CreateTable", "API_Response": response}
            # LOGGER.info(api_call_details)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AlreadyExistsException':
                # LOGGER.info("Table '%s' already exists in %s region.", table, region)
                pass
            else:
                LOGGER.error("Error calling glue:CreateTable %s", e)
                raise
        
        # subscriber_session = common.assume_role(configuration_role_name, "sra-set-subscriber-permissions", subscriber_acct)
        # lf_client = subscriber_session.client("lakeformation", region)
        # set_lake_formation_permissions(lf_client, configuration_role_name, subscriber_acct, region, shared_db_name, table)


def set_lake_formation_permissions(lf_client: LakeFormationClient, configuration_role_name: str, account: str, region: str, db_name: str, table_name: str) -> None:
    # subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share-link", account)
    # lf_client = subscriber_session.client("lakeformation", region)
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
                    'Name': "rl_" + table_name
                },
                },
            Permissions=["ALL","DESCRIBE"],
            PermissionsWithGrantOption=["DESCRIBE"])
    except ClientError as e:
        LOGGER.error("Error calling GrantPermissions %s.", e)
        raise


def set_lake_formation_permissions_sub(configuration_role_name: str, account: str, region: str, db_name: str, table_name: str) -> None:
    subscriber_session = common.assume_role(configuration_role_name, "sra-set-subscriber-permissions", account)
    lf_client: LakeFormationClient = subscriber_session.client("lakeformation", region)
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


def set_lake_formation_permissions_taget(configuration_role_name: str, account: str, region: str, db_name: str, table_name: str, security_lake_acct: str) -> None:
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


def delete_subscriber_notification(sl_client: SecurityLakeClient, subscriber_name: str, region: str) -> None:
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


def delete_subscriber(sl_client: SecurityLakeClient, subscriber_name: str, region: str) -> None:
    subscriber_exists, subscriber_id, external_id = list_subscribers(sl_client, subscriber_name)
    if subscriber_exists:
        LOGGER.info("Subscriber '%s' found in %s region. Deleting subscriber...", subscriber_name, region)
        try:
            response = sl_client.delete_subscriber(
                subscriberId=subscriber_id
            )
            # api_call_details = {"API_Call": "securitylake:DeleteSubscriber", "API_Response": response}
            # LOGGER.info(api_call_details)
        except ClientError as e:
            LOGGER.error("Error calling DeleteSubscriber %s.", e)
            raise
    else:
        LOGGER.info("Subscriber not found in %s region. Skipping delete subscriber...", region)


def delete_aws_log_source(sl_client: SecurityLakeClient, regions: list, source: AwsLogSourceNameType, accounts: list, source_version: str) -> None:
    configurations: AwsLogSourceConfigurationTypeDef = {'accounts': accounts, 'regions': regions, 'sourceName': source, 'sourceVersion': source_version}
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


def delete_security_lake(configuration_role_name: str, delegated_admin_acct: str, region: str, regions: list) -> None:
    delegated_admin_session = common.assume_role(configuration_role_name, "sra-disable-security-lake", delegated_admin_acct)
    sl_client = delegated_admin_session.client("securitylake", region)
    try:
        response = sl_client.delete_data_lake(
            regions=regions
        )
        # api_call_details = {"API_Call": "securitylake:DeleteDataLake", "API_Response": response}
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
        # api_call_details = {"API_Call": "organizations:DeregisterOrganizationDelegatedAdmin", "API_Response": delegated_admin_response}
        # LOGGER.info(api_call_details)
        LOGGER.info("Delegated admin (%s) deregistered", delegated_admin_account_id)
        delegated_administrators = ORG_CLIENT.list_delegated_administrators(ServicePrincipal=service_principal)

        LOGGER.debug(str(delegated_administrators))

        if not delegated_administrators:
            LOGGER.info("The deregister was successful for the %s delegated administrator", service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException:
        LOGGER.info("Account: %s not registered for %s", delegated_admin_account_id, service_principal)
# type: ignore
"""This script performs operations to enable, configure, update, and disable Security Lake.

Version: 1.0

'security_lake_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import string
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import boto3
import security_lake
import sra_iam
import sra_kms
import sra_s3
import sra_ssm_params
import sra_sns
from crhelper import CfnResource
import common
from time import sleep
from botocore.config import Config

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_sns.client import SNSClient

LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

iam = sra_iam.sra_iam(LOGGER)
ssm = sra_ssm_params.sra_ssm_params(LOGGER)
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=1)  # TODO
s3 = sra_s3.sra_s3(LOGGER)
kms = sra_kms.sra_kms(LOGGER)
sns = sra_sns.sra_sns(LOGGER)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
UNEXPECTED = "Unexpected!"
SERVICE_NAME = "securitylake.amazonaws.com"
META_STORE_MANAGER_ROLE = "sra-AmazonSecurityLakeMetaStoreManager"
META_STORE_MANAGER_POLICY = "AmazonSecurityLakeMetastoreManager"
REPLICATION_ROLE_NAME = "AmazonSecurityLakeS3ReplicationRole"
REPLICATION_ROLE_POLICY_NAME = "AmazonSecurityLakeS3ReplicationRolePolicy"
HOME_REGION = ssm.get_home_region()
AUDIT_ACCT_ID = ssm.get_security_acct()
AUDIT_ACCT_DATA_SUBSCRIBER = "sra-audit-account-data-subscriber"
AUDIT_ACCT_QUERY_SUBSCRIBER = "sra-audit-account-query-subscriber"
ATHENA_QUERY_BUCKET_NAME = "sra-security-lake-query-results"
AWS_LOG_SOURCES = ["ROUTE53", "VPC_FLOW", "SH_FINDINGS", "CLOUD_TRAIL_MGMT", "LAMBDA_EXECUTION", "S3_DATA", "EKS_AUDIT", "WAF"]

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    PARTITION: str = MANAGEMENT_ACCOUNT_SESSION.get_partition_for_region(HOME_REGION)
    SNS_CLIENT: SNSClient = MANAGEMENT_ACCOUNT_SESSION.client("sns")
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


#  add security lake
def process_add_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts

    Returns:
        Status
    """
    LOGGER.info("...process_add_event")

    if params["action"] in ["Add"]:
        create_security_lake(params, regions, accounts)
        for region in regions:
            delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"])
            sl_client = delegated_admin_session.client("securitylake", region)
            if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
                add_audit_acct_as_data_subscriber(sl_client, params, region, AUDIT_ACCT_DATA_SUBSCRIBER)
            if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
                add_audit_acct_as_query_subscriber(sl_client, params, region, AUDIT_ACCT_QUERY_SUBSCRIBER)
        
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            configure_query_access_in_Audit_account(params, regions, AUDIT_ACCT_QUERY_SUBSCRIBER)     

        LOGGER.info("...ADD_COMPLETE")
        return

    LOGGER.info("...ADD_NO_EVENT")


#  update security lake
def process_update_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts

    Returns:
        Status
    """
    LOGGER.info("...process_update_event")

    if params["action"] in ["Update"]:
        update_security_lake(params, regions)
        update_log_sources(params, regions, accounts)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            update_audit_acct_as_data_subscriber(params, regions, AUDIT_ACCT_DATA_SUBSCRIBER)
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            update_audit_acct_as_query_subscriber(params, regions, AUDIT_ACCT_QUERY_SUBSCRIBER)

        LOGGER.info("...UPDATE_COMPLETE")
        return

    LOGGER.info("...UPDATE_NO_EVENT")


def process_delete_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts

    Returns:
        Status
    """
    LOGGER.info("...process_delete_event")

    if params["action"] in ["Remove"]:
        LOGGER.info("...Delete Security Lake")
        disable_security_lake(params, regions, accounts)
        LOGGER.info("...DELETE_COMPLETE")
        return

    LOGGER.info("...DELETE_NO_EVENT")


def process_event(event: dict) -> None:  # TODO: (ieviero) process_executes if resource type not found. Update the function
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    # params = get_validated_parameters({"RequestType": "Update"})
    params = get_validated_parameters(event)

    # excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")

    process_update_event(params, regions, accounts)


def parameter_pattern_validator(parameter_name: str, parameter_value: Optional[str], pattern: str, is_optional: bool = False) -> dict:
    """Validate CloudFormation Custom Resource Properties and/or Lambda Function Environment Variables.

    Args:
        parameter_name: CloudFormation custom resource parameter name and/or Lambda function environment variable name
        parameter_value: CloudFormation custom resource parameter value and/or Lambda function environment variable value
        pattern: REGEX pattern to validate against.
        is_optional: Allow empty or missing value when True

    Raises:
        ValueError: Parameter has a value of empty string.
        ValueError: Parameter is missing
        ValueError: Parameter does not follow the allowed pattern

    Returns:
        Validated Parameter
    """
    if parameter_value == "" and not is_optional:
        raise ValueError(f"({parameter_name}) parameter has a value of empty string.")
    elif not parameter_value and not is_optional:
        raise ValueError(f"({parameter_name}) parameter is missing.")
    elif not re.match(pattern, str(parameter_value)):
        raise ValueError(f"({parameter_name}) parameter with value of ({parameter_value})" + f" does not follow the allowed pattern: {pattern}.")
    return {parameter_name: parameter_value}


def get_validated_parameters(event: Dict[str, Any]) -> dict:  # TODO: (ieviero) get params from lambda env variables after testing complete
    """Validate AWS CloudFormation parameters.

    Args:
        event: event data

    Returns:
        Validated parameters
    """
    # params = event["ResourceProperties"].copy()
    params = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]  # todo: 
    true_false_pattern = r"^true|false$"
    log_source_pattern = r"(?i)^((ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF),?){0,7}($|ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF){1}$"
    version_pattern = r"^[0-9.]+$"
    source_target_pattern = r"^($|ALL|(\d{12})(,\s*\d{12})*)$"
    sns_topic_pattern = r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

    # Required Parameters
    params.update(parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", os.environ.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", os.environ.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$"))
    params.update(parameter_pattern_validator("AWS_PARTITION", os.environ.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$"))
    params.update(parameter_pattern_validator("CONFIGURATION_ROLE_NAME", os.environ.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$"))
    params.update(parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", os.environ.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("SET_AUDIT_ACCT_DATA_SUBSCRIBER", os.environ.get("SET_AUDIT_ACCT_DATA_SUBSCRIBER"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("SET_AUDIT_ACCT_QUERY_SUBSCRIBER", os.environ.get("SET_AUDIT_ACCT_QUERY_SUBSCRIBER"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("SOURCE_VERSION", os.environ.get("SOURCE_VERSION"), pattern=version_pattern))
    params.update(parameter_pattern_validator("SET_ORG_CONFIGURATION", os.environ.get("SET_ORG_CONFIGURATION"), pattern=true_false_pattern))
    params.update(parameter_pattern_validator("SNS_TOPIC_ARN", os.environ.get("SNS_TOPIC_ARN"), pattern=sns_topic_pattern)) # todo: remove not needed

    # Optional Parameters
    params.update(parameter_pattern_validator("ENABLED_REGIONS", os.environ.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True))
    params.update(parameter_pattern_validator("CLOUD_TRAIL_MGMT", os.environ.get("CLOUD_TRAIL_MGMT"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("ROUTE53", os.environ.get("ROUTE53"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("VPC_FLOW", os.environ.get("VPC_FLOW"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("SH_FINDINGS", os.environ.get("SH_FINDINGS"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("LAMBDA_EXECUTION", os.environ.get("LAMBDA_EXECUTION"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("S3_DATA", os.environ.get("S3_DATA"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("EKS_AUDIT", os.environ.get("EKS_AUDIT"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("WAF", os.environ.get("WAF"), pattern=source_target_pattern, is_optional=True))
    params.update(parameter_pattern_validator("ORG_CONFIGURATION_SOURCES", os.environ.get("ORG_CONFIGURATION_SOURCES"), pattern=log_source_pattern, is_optional=True))

    #  Convert true/false string parameters to boolean
    params.update({"SET_AUDIT_ACCT_DATA_SUBSCRIBER": (params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"] == "true")})
    params.update({"SET_AUDIT_ACCT_QUERY_SUBSCRIBER": (params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"] == "true")})
    params.update({"CONTROL_TOWER_REGIONS_ONLY": (params["CONTROL_TOWER_REGIONS_ONLY"] == "true")})
    params.update({"SET_ORG_CONFIGURATION": (params["SET_ORG_CONFIGURATION"] == "true")})

    return params


def check_slr_exists(configuration_role, account, region):
    """Check if service linked role exists.

    Args:
        configuration_role: configuration role name
        account: AWS account
        region: AWS region

    Returns:
        bool: True if the service-linked role exists, False otherwise
    """
    delegated_admin_session = common.assume_role(configuration_role, "sra-configure-security-lake", account)
    iam_client = delegated_admin_session.client("iam", region)
    LOGGER.info("Checking if 'AWSServiceRoleForLakeFormationDataAccess' service-linked role exist")
    role_exists = iam.check_iam_role_exists(iam_client, "AWSServiceRoleForLakeFormationDataAccess")
    if not role_exists:
        LOGGER.info("Service-linked role 'AWSServiceRoleForLakeFormationDataAccess' not found")
    else:
        LOGGER.info("Service-linked role 'AWSServiceRoleForLakeFormationDataAccess' already exists")
    return role_exists


def create_kms_key(configuration_role, account, region, slr_exists):
    """Create KMS key.

    Args:
        configuration_role: configuration role name
        account: AWS account
        region: AWS region
        slr_exists: service linked role exists

    Returns:
        str: KMS key ARN
    """
    key_alias = f"alias/sra-security-lake-{account}-{region}"
    delegated_admin_session = common.assume_role(configuration_role, "sra-configure-security-lake", account)
    kms_client = delegated_admin_session.client("kms", region)
    LOGGER.info(f"Checking/deploying KMS resources in {region}...")  # todo: fix this, do we need to check if
    key_exists, key_arn = kms.check_key_exists(kms_client, key_alias)
    if key_exists:
        LOGGER.info("Key with alias '%s' already exists", key_alias)
        return key_arn
    elif slr_exists and not key_exists:
        LOGGER.info("Key with alias '%s' does not exist. Creating...", key_alias)
        key_policy = kms.define_key_policy(account, PARTITION, region)
        key_info = kms.create_kms_key(kms_client, key_policy, "SRA Security Lake KMS key")
        key_arn = key_info["Arn"]
        key_id = key_info["KeyId"]
        alias_created = kms.create_alias(kms_client, key_alias, key_id)
        if alias_created:
            LOGGER.info("Key with alias '%s' created in %s", key_alias, region)
        kms.enable_key_rotation(kms_client, key_id)
        return key_arn
    else:
        LOGGER.error("Failed to create KMS key")


def create_service_linked_role(iam_client, account_id) -> None:
    """Create service linked role in the given account.

    Args:
        iam_client: boto3 client
        account_id (str): Account ID
    """
    LOGGER.info("Creating 'AWSServiceRoleForLakeFormation' service-linked role")
    iam.create_service_linked_role(
        "AWSServiceRoleForLakeFormationDataAccess",
        "lakeformation.amazonaws.com",
        "A service-linked role to enable the Lake Formation integrated service to access registered locations.",
        iam_client,
    )
    sleep(4)


def create_meta_store_manager_role(iam_client):
    """Create IAM role for Security Lake.

    Args:
        iam_client: boto3 client
    """
    managed_policy_arn = f"arn:{PARTITION}:iam::{PARTITION}:policy/service-role/{META_STORE_MANAGER_POLICY}"  # TODO: should partition be a parameter?

    role_exists = iam.check_iam_role_exists(iam_client, META_STORE_MANAGER_ROLE)
    if role_exists:
        LOGGER.info("IAM role '%s' already exists.", META_STORE_MANAGER_ROLE)
    if not role_exists:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "", "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
        iam.create_role(iam_client, META_STORE_MANAGER_ROLE, trust_policy)
        iam.attach_managed_policy(iam_client, META_STORE_MANAGER_ROLE, managed_policy_arn)


def create_security_lake(params: dict, regions: list, accounts: list) -> None:
    """Enable the security lake service and configure its global settings.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts
    """
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"],
        "sra-enable-security-lake",
        params["DELEGATED_ADMIN_ACCOUNT_ID"],  # TODO: (Ieviero) add sts class instead of common
    )
    iam_client = delegated_admin_session.client("iam", HOME_REGION)
    create_service_linked_role(iam_client, params["DELEGATED_ADMIN_ACCOUNT_ID"])
    create_meta_store_manager_role(iam_client)

    security_lake.register_delegated_admin(params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, SERVICE_NAME)
    deploy_security_lake(params, regions)
    add_log_sources(params, regions, accounts)


def deploy_security_lake(params, regions):
    """Enable Security Lake.

    Args:
        params: parameters
        regions: AWS regions
    """
    slr_exists = check_slr_exists(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION)
    all_data = []
    for region in regions:
        key_arn = create_kms_key(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], region, slr_exists)
        data = {"region": region, "key_arn": key_arn}
        all_data.append(data)
    sl_configurations = [{'encryptionConfiguration': {'kmsKeyId': data['key_arn']}, 'region': data['region']} for data in all_data]
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"],
        "sra-create-data-lake",
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
    )
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    LOGGER.info("Creating Security Lake in %s region(s)...", ', '.join(regions))
    security_lake.create_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations)
    status = security_lake.check_data_lake_status(sl_client, regions)
    if status:
        LOGGER.info("CreateDataLake status 'COMPLETED'")
    process_org_configuration(sl_client, params["SET_ORG_CONFIGURATION"], params["ORG_CONFIGURATION_SOURCES"], regions, params["SOURCE_VERSION"])


def build_log_sources(sources_param: str) -> list:
    """Build list of log sources.

    Args:
        sources_param: Input from cfn parameter

    Returns:
        list of log sources
    """
    log_sources: list = []
    log_sources = sources_param.split(",")

    return log_sources


def update_security_lake(params, regions):  # TODO: (ieviero) execute security_lake.update_security_lake only if changes introduced
    """Update Security Lake.

    Args:
        params: parameters
        regions: AWS regions
    """
    slr_exists = check_slr_exists(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION)
    for region in regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"],
            "sra-update-security-lake",
            params["DELEGATED_ADMIN_ACCOUNT_ID"],  # TODO: (ieviero) use assume_role from sts class
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        LOGGER.info("Checking if Security Lake is enabled in %s region...", region)
        lake_exists = security_lake.check_data_lake_exists(sl_client, region)
        if lake_exists:
            LOGGER.info("Security Lake already enabled in %s region.", region)
            # security_lake.update_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations)
        else:
            LOGGER.info("Security Lake not found in %s region. Enabling Security Lake...", region)
            key_arn = create_kms_key(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], region, slr_exists)
            sl_configurations = [{'encryptionConfiguration': {'kmsKeyId': key_arn}, 'region': region}]
            security_lake.create_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations, region)
            lake_exists = security_lake.check_data_lake_exists(sl_client, region)
            if lake_exists:
                LOGGER.info("Security Lake is enabled in %s.", region)

    process_org_configuration(sl_client, params["SET_ORG_CONFIGURATION"], params["ORG_CONFIGURATION_SOURCES"], regions, params["SOURCE_VERSION"])


def process_org_configuration(sl_client, set_org_configuration, org_confiugration_sources, regions, source_version):
    """Set Security Lake organization configuration for new accounts.

    Args:
        sl_client: boto3 client
        set_org_configuration: enable organization configurations for new accounts
        org_confiugration_sources: list of aws log sources
        region: AWS region
        source_version: source version
    """
    LOGGER.info("Checking if Organization Configuration enabled in %s region(s)", ', '.join(regions))
    org_configuration_exists, exisiting_org_configuration = security_lake.get_org_configuration(sl_client)
    if set_org_configuration:
        sources = build_log_sources(org_confiugration_sources)
        if not org_configuration_exists:
            LOGGER.info("Organization Configuration not enabled in %s region(s). Creating...", ', '.join(regions))
            security_lake.create_organization_configuration(sl_client, regions, sources, source_version)
            LOGGER.info("Organization Configuration enabled")
        else:
            security_lake.update_organization_configuration(
                sl_client, regions, sources, source_version, exisiting_org_configuration
                )
    else:
        if org_configuration_exists:
            LOGGER.info("Deleting Organization Configuration in %s region(s)...", r', '.join(regions))  # TODO: fix this region/regions
            security_lake.delete_organization_configuration(sl_client, regions, exisiting_org_configuration)
            LOGGER.info("Organization Configuration deleted")


def add_log_sources(params, regions, org_accounts):
    """Configure aws log sources.

    Args:
        params: Configuration parameters
        regions: A list of AWS regions.
        org_accounts: A list of AWS accounts.
    """
    aws_log_sources = []
    org_accounts_ids = [account["AccountId"] for account in org_accounts]
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-add-log-sources", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    for log_source in AWS_LOG_SOURCES:
        if params[log_source] != "":
            accounts = params[log_source].split(",") if params[log_source] != "ALL" else org_accounts_ids
            configurations = {'accounts': accounts, 'regions': regions, 'sourceName': log_source, 'sourceVersion': params["SOURCE_VERSION"]}
            aws_log_sources.append(configurations)
    
    security_lake.add_aws_log_source(sl_client, aws_log_sources)


def update_log_sources(params, regions, org_accounts):
    """Configure aws log sources.

    Args:
        params: Configuration parameters
        regions: A list of AWS regions.
        org_accounts: A list of AWS accounts.
    """
    org_accounts_ids = [account["AccountId"] for account in org_accounts]
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-update-log-sources", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    for log_source in AWS_LOG_SOURCES:
        if params[log_source] != "":
            accounts = params[log_source].split(",") if params[log_source] != "ALL" else org_accounts_ids
            security_lake.set_aws_log_source(sl_client, regions, log_source, accounts, org_accounts_ids, params["SOURCE_VERSION"])
        elif params[log_source] == "":
            result = security_lake.check_log_source_enabled(sl_client, [], org_accounts_ids, regions, log_source, params["SOURCE_VERSION"])
            accounts = list(result.accounts_to_disable)
            if result.source_exists:
                security_lake.delete_aws_log_source(sl_client, regions, log_source, accounts, params["SOURCE_VERSION"])
        else:
            LOGGER.info("Error reading value for %s parameter", log_source)


def update_audit_acct_as_data_subscriber(params, regions, subscriber_name):
    """Configure Audit (Security Tooling) account as data access subscriber.

    Args:
        params: parameters
        regions: AWS regions
        subscriber_name: subscriber name
    """
    s3_access = "s3"
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for data access subscriber. Skipping...")
        return
    else:
        for region in regions:
            delegated_admin_session = common.assume_role(
                params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
            )
            sl_client = delegated_admin_session.client("securitylake", region, config=BOTO3_CONFIG)
            subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, subscriber_name)
            if subscriber_exists:
                resource_share_arn = security_lake.update_subscriber(
                    sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
                )
                LOGGER.info("Updating Audit account subscriber notification '%s' in %s region...", subscriber_name, region)
                security_lake.update_subscriber_notification(sl_client, subscriber_id)
            else:
                characters = string.ascii_letters + string.digits
                external_id = "".join(random.choices(characters, k=8))
                LOGGER.info("Creating Audit account subscriber '%s' in %s region...", subscriber_name, region)
                subscriber_id, resource_share_arn = security_lake.create_subscribers(
                    sl_client, s3_access, sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
                )
                LOGGER.info("Creating SQS notification for Audit account subscriber '%s' in %s region...", subscriber_name, region)
                security_lake.create_subscriber_notification(sl_client, subscriber_id)


def add_audit_acct_as_data_subscriber(sl_client, params, region, subscriber_name):
    """Configure Audit (Security Tooling) account as data access subscriber.

    Args:
        params: parameters
        regions: AWS regions
        subscriber_name: subscriber name
    """
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for data access subscriber. Skipping...")
        return
    else:
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, subscriber_name)
        if subscriber_exists:
            resource_share_arn = security_lake.update_subscriber(
                sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
            )
            LOGGER.info("Updating Audit account subscriber notification '%s' in %s region...", subscriber_name, region)
            security_lake.update_subscriber_notification(sl_client, subscriber_id)
        else:
            characters = string.ascii_letters + string.digits
            external_id = "".join(random.choices(characters, k=8))
            LOGGER.info("Creating Audit account subscriber '%s' in %s region...", subscriber_name, region)
            subscriber_id, resource_share_arn = security_lake.create_subscribers(
                sl_client, "S3", sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
            )
            LOGGER.info("Creating SQS notification for Audit account subscriber '%s' in %s region...", subscriber_name, region)
            security_lake.create_subscriber_notification(sl_client, subscriber_id)


def update_audit_acct_as_query_subscriber(params, regions, subscriber_name):
    """Configure Audit (Security tooling) account as query access subscribe.

    Args:
        params: parameters
        regions: AWS regions
        subscriber_name: subscriber name
    """
    lakeformation_access = "LAKEFORMATION"
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for query access subscriber. Skipping...")
        return
    else:
        for region in regions:
            delegated_admin_session = common.assume_role(
                params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
            )
            sl_client = delegated_admin_session.client("securitylake", region)
            subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, subscriber_name)
            if subscriber_exists:
                LOGGER.info("Audit account subscriber '%s' exists in %s region. Updating subscriber...", subscriber_name, region)
                resource_share_arn = security_lake.update_subscriber(
                    sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
                )
            else:
                characters = string.ascii_letters + string.digits
                external_id = "".join(random.choices(characters, k=8))
                LOGGER.info("Audit account subscriber '%s' does not exist in %s region. Creating subscriber...", subscriber_name, region)
                subscriber_id, resource_share_arn = security_lake.create_subscribers(
                    sl_client, lakeformation_access, sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
                )
            configure_query_subscriber(
                "sra-security-lake-query-subscriber", AUDIT_ACCT_ID, subscriber_name, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, resource_share_arn
            )
            create_athena_query_bucket("sra-security-lake-query-subscriber", AUDIT_ACCT_ID, region)


def add_audit_acct_as_query_subscriber(sl_client, params, region, subscriber_name):
    """Configure Audit (Security tooling) account as query access subscribe.

    Args:
        params: parameters
        regions: AWS regions
        subscriber_name: subscriber name
    """
    sources = [source for source in AWS_LOG_SOURCES if params[source]]
    if sources == []:
        LOGGER.info("No log sources selected for query access subscriber. Skipping...")
        return
    else:
        characters = string.ascii_letters + string.digits
        external_id = "".join(random.choices(characters, k=8))
        LOGGER.info("Audit account subscriber '%s' does not exist in %s region. Creating subscriber...", subscriber_name, region)
        subscriber_id, resource_share_arn = security_lake.create_subscribers(sl_client, "LAKEFORMATION", sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"])

def configure_query_access_in_Audit_account(params, regions, subscriber_name):    
    for region in regions:
        delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"])
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_created, resource_share_arn, external_id = security_lake.list_subscriber_resource_share(sl_client, subscriber_name)
        if subscriber_created:
            LOGGER.info("Audit account subscriber '%s' created in %s region. Configuring subscriber...", subscriber_name, region)
            configure_query_subscriber("sra-security-lake-query-subscriber", AUDIT_ACCT_ID, subscriber_name, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, resource_share_arn)
            create_athena_query_bucket("sra-security-lake-query-subscriber", AUDIT_ACCT_ID, region)


def build_subscriber_regions(subscriber_regions_param, security_lake_regions):
    """Set subscriber regions.

    Args:
        subscriber_regions_param: subscriber regions
        security_lake_regions: security lake regions

    Returns:
        list of subscriber regions
    """
    subscriber_regions = []
    subscriber_regions = subscriber_regions_param.split(",")
    subscriber_regions = [region for region in subscriber_regions if region in security_lake_regions]

    return subscriber_regions


def configure_query_subscriber(configuration_role_name, subscriber_acct, subscriber_name, security_lake_acct, region, resource_share_arn):
    """Configure query access subscriber.

    Args:
        configuration_role_name: configuration role name
        subscriber_acct: subscriber AWS account
        subscriber_name: subscriber name
        security_lake_acct: Security Lake delegated administrator account
        region: AWS region
        resource_share_arn: RAM resource share arn
    """
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    ram_client = subscriber_session.client("ram", region)
    LOGGER.info("Configuring resource share link for subscriber '%s' in %s region...", subscriber_name, region)
    security_lake.configure_resource_share_in_subscriber_acct(ram_client, resource_share_arn)
    shared_db_name, shared_tables = security_lake.get_shared_resource_names(ram_client, resource_share_arn)
    if shared_tables == "" or shared_db_name == "":
        LOGGER.info("No shared resource names found for subscriber '%s' in %s region...", subscriber_name, region)
    else:
        subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share-link", subscriber_acct)
        glue_client = subscriber_session.client("glue", region)
        LOGGER.info("Creating database '%s_subscriber' data catalog for subscriber '%s' in %s region...", shared_db_name, subscriber_name, region)
        security_lake.create_db_in_data_catalog(glue_client, configuration_role_name, region, subscriber_acct, shared_db_name)
        security_lake.create_table_in_data_catalog(
            glue_client, configuration_role_name, region, subscriber_acct, shared_db_name, shared_tables, security_lake_acct
        )


def create_athena_query_bucket(configuration_role_name, subscriber_acct_id, region):  # TODO: (ieviero) add bucket policy and kms key
    """Check if Athena query results bucket exists, if not, create it.

    Args:
        configuration_role_name: configuration role name
        subscriber_acct_id: subscriber AWS account
        region: AWS region
    """
    LOGGER.info("Checking/deploying Athena S3 resources...")
    subscriber_acct_session = common.assume_role(configuration_role_name, "sra-delete-security-lake-subscribers", subscriber_acct_id)
    s3_client = subscriber_acct_session.client("s3", region)
    bucket_name = f"{ATHENA_QUERY_BUCKET_NAME}-{subscriber_acct_id}-{region}"
    bucket_exists = s3.query_for_s3_bucket(s3_client, bucket_name)
    if bucket_exists is True:
        LOGGER.info("Bucket %s already exists.", bucket_name)
    if bucket_exists is False:
        LOGGER.info("Creating %s s3 bucket...", bucket_name)
        s3.create_s3_bucket(s3_client, bucket_name, "bucket_policy", "kms_key_id", region)


def disable_security_lake(
    params: dict, regions: list, accounts
) -> None:  # TODO: (ieviero) should parameter or event "Delete" be added? Need to address subscriber deletion workflow
    """Disable Security Lake service.

    Args:
        params: Configuration Parameters
        regions: AWS regions
        accounts: AWS accounts
    """
    for region in regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-delete-security-lake-subscribers", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            security_lake.delete_subscriber_notification(sl_client, AUDIT_ACCT_DATA_SUBSCRIBER, region)
            security_lake.delete_subscriber(sl_client, AUDIT_ACCT_DATA_SUBSCRIBER, region)
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            security_lake.delete_subscriber(sl_client, AUDIT_ACCT_QUERY_SUBSCRIBER, region)

        org_configuration_exists, exisiting_org_configuration = security_lake.get_org_configuration(sl_client)
        if org_configuration_exists:
            LOGGER.info("Deleting Organization Configuration in %s region...", region)
            security_lake.delete_organization_configuration(sl_client, region, exisiting_org_configuration)

    all_accounts = []
    for account in accounts:
        all_accounts.append(account["AccountId"])
    for source in AWS_LOG_SOURCES:
        security_lake.delete_aws_log_source(sl_client, regions, source, all_accounts, params["SOURCE_VERSION"])

    security_lake.delete_security_lake(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, regions)

    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-delete-security-lake-roles", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )  # todo: add sts class, initiate iam_client and pass it
    iam_client = delegated_admin_session.client("iam", HOME_REGION)

    meta_store_policy_arn: str = f"arn:{PARTITION}:iam::{PARTITION}:policy/service-role/{META_STORE_MANAGER_POLICY}"
    delete_iam_resources(iam_client, META_STORE_MANAGER_ROLE, meta_store_policy_arn)


def delete_iam_resources(iam_client: IAMClient, role_name: str, policy_arn: str) -> None:
    """Delete IAM resources.

    Args:
        iam_client: IAM client
        role_name: role name
        policy_arn: policy arn

    Raises:
        ValueError: Invalid policy_arn parameter
    """
    role_exists = iam.check_iam_role_exists(iam_client, role_name)
    if role_exists:
        if not policy_arn or not isinstance(policy_arn, str):
            raise ValueError("Invalid policy_arn parameter")
        iam.detach_policy(iam_client, role_name, policy_arn)
        iam.delete_role(iam_client, role_name)
    if not role_exists:
        LOGGER.info("...Role %s does not exist...", role_name)


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):
        LOGGER.info("...calling helper...")
        helper(event, context)
    else:
        LOGGER.info("...else...just calling process_event...")
        process_event(event)


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    """Lambda Handler.

    Args:
        event: event data
        context: runtime information

    Raises:
        ValueError: Unexpected error executing Lambda function
    """
    LOGGER.info("....Lambda Handler Started....")
    boto3_version = boto3.__version__
    LOGGER.info("boto3 version: %s", boto3_version)
    # event_info = {"Event": event}
    # LOGGER.info(event_info)
    try:
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None


@helper.create
@helper.update
@helper.delete
def process_event_cloudformation(event: CloudFormationCustomResourceEvent, context: Context) -> str:  # noqa U100
    """Process Event from AWS CloudFormation.

    Args:
        event: event data
        context: runtime information

    Returns:
        AWS CloudFormation physical resource id
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    params = get_validated_parameters(event)
    # params = get_validated_parameters({"RequestType": event["RequestType"]})
    # excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]
    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"])
    if params["action"] == "Add":
        process_add_event(params, regions, accounts)
    elif params["action"] == "Update":
        process_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Security Lake from (process_event_cloudformation)")
        process_delete_event(params, regions, accounts)

    return f"sra-security-lake-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"

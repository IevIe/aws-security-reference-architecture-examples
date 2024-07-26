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
from crhelper import CfnResource
import common

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_organizations import OrganizationsClient

LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

iam = sra_iam.sra_iam(LOGGER)
ssm = sra_ssm_params.sra_ssm_params(LOGGER)
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=1)  # TODO
s3 = sra_s3.sra_s3(LOGGER)
kms = sra_kms.sra_kms(LOGGER)

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
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            set_audit_acct_as_data_subscriber(params, regions, AUDIT_ACCT_DATA_SUBSCRIBER)
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            set_audit_acct_as_query_subscriber(params, regions, AUDIT_ACCT_QUERY_SUBSCRIBER)
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
        add_update_log_sources(params, regions, accounts)
        if params["CREATE_QUERY_SUBSCRIBER"]:
            process_query_subscriber(params, regions)
        if params["CREATE_DATA_SUBSCRIBER"]:
            process_data_subscriber(params, regions)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            set_audit_acct_as_data_subscriber(params, regions, AUDIT_ACCT_DATA_SUBSCRIBER)
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            set_audit_acct_as_query_subscriber(params, regions, AUDIT_ACCT_QUERY_SUBSCRIBER)
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
    params = event["ResourceProperties"].copy()
    # params = {}
    actions = {"Create": "Add", "Update": "Update", "Delete": "Remove"}
    params["action"] = actions[event.get("RequestType", "Create")]
    true_false_pattern = r"^true|false$"
    log_source_pattern = r"(?i)^((ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF),?){0,7}($|ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF){1}$"
    version_pattern = r"^[0-9.]+$"
    source_target_pattern = r"^($|ALL|(\d{12})(,\s*\d{12})*)$"

    # Required Parameters
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$")
    parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", params.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$")
    parameter_pattern_validator("AWS_PARTITION", params.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$")
    parameter_pattern_validator("CONFIGURATION_ROLE_NAME", params.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern)
    parameter_pattern_validator("SET_AUDIT_ACCT_DATA_SUBSCRIBER", params.get("SET_AUDIT_ACCT_DATA_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("SET_AUDIT_ACCT_QUERY_SUBSCRIBER", params.get("SET_AUDIT_ACCT_QUERY_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("SOURCE_VERSION", params.get("SOURCE_VERSION"), pattern=version_pattern)
    parameter_pattern_validator("SET_ORG_CONFIGURATION", params.get("SET_ORG_CONFIGURATION"), pattern=true_false_pattern)

    # QUERY
    parameter_pattern_validator("CREATE_QUERY_SUBSCRIBER", params.get("CREATE_QUERY_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("QUERY_SUBSCRIBER_NAME", params.get("QUERY_SUBSCRIBER_NAME"), pattern=r"^$|^[a-zA-Z][-a-zA-Z0-9]*$", is_optional=True)
    parameter_pattern_validator("QUERY_EXTERNAL_ID", params.get("QUERY_EXTERNAL_ID"), pattern=r"^$|^[a-zA-Z0-9-]{1,64}$", is_optional=True)
    parameter_pattern_validator("QUERY_SUBSCRIBER_REGIONS", params.get("QUERY_SUBSCRIBER_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True)
    parameter_pattern_validator("QUERY_LOG_SOURCES", params.get("QUERY_LOG_SOURCES"), pattern=log_source_pattern, is_optional=True)
    parameter_pattern_validator("QUERY_SUBSCRIBER_ACCT", params.get("QUERY_SUBSCRIBER_ACCT"), pattern=r"^\d{12}$", is_optional=True)

    # DATA
    parameter_pattern_validator("CREATE_DATA_SUBSCRIBER", params.get("CREATE_DATA_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("DATA_SUBSCRIBER_NAME", params.get("DATA_SUBSCRIBER_NAME"), pattern=r"^$|^[a-zA-Z][-a-zA-Z0-9]*$", is_optional=True)
    parameter_pattern_validator("DATA_EXTERNAL_ID", params.get("DATA_EXTERNAL_ID"), pattern=r"^$|^[a-zA-Z0-9-]{1,64}$", is_optional=True)
    parameter_pattern_validator("DATA_SUBSCRIBER_REGIONS", params.get("DATA_SUBSCRIBER_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True)
    parameter_pattern_validator("DATA_LOG_SOURCES", params.get("DATA_LOG_SOURCES"), pattern=log_source_pattern, is_optional=True)
    parameter_pattern_validator("DATA_SUBSCRIBER_ACCT", params.get("DATA_SUBSCRIBER_ACCT"), pattern=r"^\d{12}$", is_optional=True)
    # Optional Parameters
    parameter_pattern_validator("CREATE_NOTIFICATION", params.get("CREATE_NOTIFICATION"), pattern=r"(?i)^(ignore|SQS){1}$", is_optional=True)

    parameter_pattern_validator("ENABLED_REGIONS", params.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True)

    parameter_pattern_validator("CLOUD_TRAIL_MGMT", params.get("CLOUD_TRAIL_MGMT"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("ROUTE53", params.get("ROUTE53"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("VPC_FLOW", params.get("VPC_FLOW"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("SH_FINDINGS", params.get("SH_FINDINGS"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("LAMBDA_EXECUTION", params.get("LAMBDA_EXECUTION"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("S3_DATA", params.get("S3_DATA"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("EKS_AUDIT", params.get("EKS_AUDIT"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("WAF", params.get("WAF"), pattern=source_target_pattern, is_optional=True)
    parameter_pattern_validator("ORG_CONFIGURATION_SOURCES", params.get("ORG_CONFIGURATION_SOURCES"), pattern=log_source_pattern, is_optional=True)

    #  Convert true/false string parameters to boolean
    params.update({"CREATE_QUERY_SUBSCRIBER": (params["CREATE_QUERY_SUBSCRIBER"] == "true")})
    params.update({"CREATE_DATA_SUBSCRIBER": (params["CREATE_DATA_SUBSCRIBER"] == "true")})
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
    LOGGER.info("Checking if 'AWSServiceRoleForLakeFormationDataAccess' service-linked role exist")  # TODO: role name
    delegated_admin_session = common.assume_role(configuration_role, "sra-configure-security-lake", account)
    iam_client = delegated_admin_session.client("iam", region)
    role_exists = iam.check_iam_role_exists(iam_client, "AWSServiceRoleForLakeFormationDataAccess")
    if not role_exists:
        LOGGER.info("Service-linked role 'AWSServiceRoleForLakeFormationDataAccess' not found")
    else:
        LOGGER.info("Service-linked role 'AWSServiceRoleForLakeFormationDataAccess' found")
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
    LOGGER.info("Checking/deploying KMS resources...")  # todo: fix this, do we need to check if
    key_alias = f"alias/sra-security-lake-{account}-{region}"
    delegated_admin_session = common.assume_role(configuration_role, "sra-configure-security-lake", account)
    kms_client = delegated_admin_session.client("kms", region)
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
            LOGGER.info("Alias %s created", key_alias)
        kms.enable_key_rotation(kms_client, key_id)
        return key_arn
    # elif not slr_exists and not key_exists:  # TODO: ieviero remove after testing
    #     delegated_admin_session = common.assume_role(
    #         configuration_role, "sra-enable-security-lake", account
    #     )  # TODO: (Ieviero) add sts class instead of common
    #     iam_client = delegated_admin_session.client("iam", HOME_REGION)
    #     create_service_linked_role(iam_client, account)
    #     LOGGER.info("Key with alias '%s' does not exist.  Creating...", key_alias)
    #     key_policy = kms.define_key_policy(account, PARTITION, region)
    #     key_info = kms.create_kms_key(kms_client, key_policy, "SRA Security Lake KMS key")
    #     key_arn = key_info["Arn"]
    #     key_id = key_info["KeyId"]
    #     alias_created = kms.create_alias(kms_client, key_alias, key_id)
    #     if alias_created:
    #         LOGGER.info("Alias %s created", key_alias)
    #     kms.enable_key_rotation(kms_client, key_id)
    #     return key_arn
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
    add_update_log_sources(params, regions, accounts)

    if params["CREATE_QUERY_SUBSCRIBER"]:
        process_query_subscriber(params, regions)
    if params["CREATE_DATA_SUBSCRIBER"]:
        process_data_subscriber(params, regions)


def deploy_security_lake(params, regions):
    """Enable Security Lake.

    Args:
        params: parameters
        regions: AWS regions
    """
    slr_exists = check_slr_exists(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION)
    for region in regions:
        LOGGER.info("Creating Security Lake in %s region...", region)
        key_arn = create_kms_key(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], region, slr_exists)
        sl_configurations = security_lake.set_configurations(region, key_arn)
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"],
            "sra-enable-security-lake",
            params["DELEGATED_ADMIN_ACCOUNT_ID"],
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        security_lake.create_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations, region)


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
        LOGGER.info("Checking if Security Lake is enabled in %s region...", region)
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"],
            "sra-update-security-lake",
            params["DELEGATED_ADMIN_ACCOUNT_ID"],  # TODO: (ieviero) use assume_role from sts class
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        lake_exists = security_lake.check_data_lake_exists(sl_client, region)
        if lake_exists:
            LOGGER.info("Security Lake already enabled in %s region.", region)
            # security_lake.update_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations)
        else:
            key_arn = create_kms_key(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], region, slr_exists)
            sl_configurations = security_lake.set_configurations(region, key_arn)
            LOGGER.info("Security Lake not found in %s region. Creating Security Lake...", region)
            security_lake.create_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations, region)
            lake_exists = security_lake.check_data_lake_exists(sl_client, region)
            if lake_exists:
                LOGGER.info("Security Lake enabled in %s.", region)

        process_org_configuration(sl_client, params["SET_ORG_CONFIGURATION"], params["ORG_CONFIGURATION_SOURCES"], region, params["SOURCE_VERSION"])


def process_org_configuration(sl_client, set_org_configuration, org_confiugration_sources, region, source_version):
    """Set Security Lake organization configuration for new accounts.

    Args:
        sl_client: boto3 client
        set_org_configuration: enable organization configurations for new accounts
        org_confiugration_sources: list of aws log sources
        region: AWS region
        source_version: source version
    """
    LOGGER.info("Checking if Organization Configuration configured in %s region", region)
    org_configuration_exists, exisiting_org_configuration = security_lake.get_org_configuration(sl_client)
    if set_org_configuration:
        sources = build_log_sources(org_confiugration_sources)
        if not org_configuration_exists:
            LOGGER.info("Creating Organization Configuration in %s region...", region)
            security_lake.create_organization_configuration(sl_client, region, sources, source_version)
        else:
            LOGGER.info("Updating Organization Configuration in %s region...", region)
            security_lake.update_organization_configuration(
                sl_client, region, sources, source_version, exisiting_org_configuration
            )  # TODO add delete action
    else:
        if org_configuration_exists:
            LOGGER.info("Deleting Organization Configuration in %s region...", region)
            security_lake.delete_organization_configuration(sl_client, region, exisiting_org_configuration)


def add_update_log_sources(params, regions, org_accounts):
    """Configure aws log sources.

    Args:
        params: parameters
        regions: AWS regions
        org_accounts: AWS accounts
    """
    org_accounts_ids = []
    for account in org_accounts:
        org_accounts_ids.append(account["AccountId"])  # TODO: just get accounts only
    all_regions = common.get_available_regions()  # TODO: (ieviero) address the need of getting the regions
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-add-update-log-sources", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    for i in AWS_LOG_SOURCES:
        if params[i] != "":
            if params[i] == "ALL":
                accounts = []
                for account in org_accounts:
                    accounts.append(account["AccountId"])
            else:
                accounts = params[i].split(",")
            source = i
            security_lake.set_aws_log_source(sl_client, regions, all_regions, source, accounts, org_accounts_ids, params["SOURCE_VERSION"])
        elif params[i] == "":
            result = security_lake.check_log_source(sl_client, org_accounts_ids, regions, i, params["SOURCE_VERSION"])
            accounts_to_dis = list(result.accounts_to_disable)
            if result.source_exists:
                LOGGER.info("Deleting %s log and event source...", i)
                regions = list(result.regions_to_disable)
                security_lake.delete_aws_log_source(sl_client, regions, i, accounts_to_dis, params["SOURCE_VERSION"])  # TODO: rename
        else:
            LOGGER.info("Error reading value for %s parameter", i)


def set_audit_acct_as_data_subscriber(params, regions, subscriber_name):
    """Configure Audit (Security Tooling) account as data access subscriber.

    Args:
        params: parameters
        regions: AWS regions
        subscriber_name: subscriber name
    """
    for region in regions:
        sources = get_log_sources_for_audit_subscriber(params)  # TODO: (ieviero) get existing sources from list_sources
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, subscriber_name)
        if subscriber_exists:
            resource_share_arn = security_lake.update_subscriber(
                sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"]
            )
            LOGGER.info("Updating subscriber Audit account subscriber '%s' in %s region...", subscriber_name, region)
            security_lake.update_subscriber_notification(sl_client, subscriber_id)
        else:
            characters = string.ascii_letters + string.digits
            external_id = "".join(random.choices(characters, k=8))
            LOGGER.info("Creating subscriber Audit account subscriber '%s' in %s region...", subscriber_name, region)
            subscriber_id, resource_share_arn = security_lake.create_subscribers(
                sl_client, "S3", sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
            )
            LOGGER.info("Creating SQS notification for Audit account subscriber '%s' in %s region...", subscriber_name, region)
            security_lake.create_subscriber_notification(sl_client, subscriber_id)


# TODO: (ieviero) check which sources are enabled using list_sources
def get_log_sources_for_audit_subscriber(params):
    """Set aws log sources for subscriber.

    Args:
        params: parameters

    Returns:
        list of log sources
    """
    return [source for source in AWS_LOG_SOURCES if params[source]]


def set_audit_acct_as_query_subscriber(params, regions, subscriber_name):
    """Configure Audit (Security tooling) account as query access subscribe.

    Args:
        params: parameters
        regions: AWS regions
        subscriber_name: subscriber name
    """
    for region in regions:
        sources = get_log_sources_for_audit_subscriber(params)
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
                sl_client, "LAKEFORMATION", sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
            )
        configure_query_subscriber(
            "sra-security-lake-query-subscriber", AUDIT_ACCT_ID, subscriber_name, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, resource_share_arn
        )
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


def process_query_subscriber(params, regions):  # TODO: update subscriber external_id?
    """Confiure query access subscriber.

    Args:
        params: parameters
        regions: AWS regions
    """
    sources = build_log_sources(params["QUERY_LOG_SOURCES"])
    subscriber_regions = build_subscriber_regions(params["QUERY_SUBSCRIBER_REGIONS"], regions)

    for region in subscriber_regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-process-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, params["QUERY_SUBSCRIBER_NAME"])

        if subscriber_exists:
            LOGGER.info("Subscriber '%s' exists in %s region. Updating subscriber...", params['QUERY_SUBSCRIBER_NAME'], region)
            update_query_subscriber(sl_client, params, sources, region, subscriber_id)

        else:
            LOGGER.info("Subscriber '%s' does not exist in %s region. Creating subscriber...", params['QUERY_SUBSCRIBER_NAME'], region)
            add_query_subscriber(sl_client, params, sources, region)


def process_data_subscriber(params, regions):  # TODO: update subscriber external_id?
    """Confiure data access subscriber.

    Args:
        params: parameters
        regions: AWS regions
    """
    sources = build_log_sources(params["DATA_LOG_SOURCES"])
    subscriber_regions = build_subscriber_regions(params["DATA_SUBSCRIBER_REGIONS"], regions)

    for region in subscriber_regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-process-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, params["DATA_SUBSCRIBER_NAME"])

        if subscriber_exists:
            LOGGER.info("Subscriber '%s' exists in %s region. Updating subscriber...", params['DATA_SUBSCRIBER_NAME'], region)
            update_data_subscriber(sl_client, params, sources, region, subscriber_id)

        else:
            LOGGER.info("Subscriber '%s' does not exist in %s region. Creating subscriber...", params['DATA_SUBSCRIBER_NAME'], region)
            add_data_subscriber(sl_client, params, sources, region)


def add_query_subscriber(sl_client, params, sources, region):
    """Create query access subscriber.

    Args:
        params: parameters
        sources: AWS log sources
        region: AWS region
        sl_client: boto3 client
    """
    subscriber_id, resource_share_arn = security_lake.create_subscribers(
        sl_client,
        "LAKEFORMATION",
        sources,
        params["QUERY_EXTERNAL_ID"],
        params["QUERY_SUBSCRIBER_ACCT"],
        params["QUERY_SUBSCRIBER_NAME"],
        region,
        params["SOURCE_VERSION"],
    )
    if subscriber_id == "error occured":  # TODO: Ieviero - ???
        pass
    configure_query_subscriber(
        "sra-security-lake-query-subscriber",
        params["QUERY_SUBSCRIBER_ACCT"],
        params["QUERY_SUBSCRIBER_NAME"],
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
        region,
        resource_share_arn,
    )
    create_athena_query_bucket("sra-security-lake-query-subscriber", params["QUERY_SUBSCRIBER_ACCT"], region)


def add_data_subscriber(sl_client, params, sources, region):
    """Add data access subscriber.

    Args:
        params: parameters
        sources: sources
        region: AWS region
        sl_client: boto3 client
    """
    subscriber_id, resource_share_arn = security_lake.create_subscribers(
        sl_client,
        "S3",
        sources,
        params["DATA_EXTERNAL_ID"],
        params["DATA_SUBSCRIBER_ACCT"],
        params["DATA_SUBSCRIBER_NAME"],
        region,
        params["SOURCE_VERSION"],
    )
    if subscriber_id == "error occured":
        pass
    if params["CREATE_NOTIFICATION"] != "ignore":
        LOGGER.info("Creating subscriber notification for subscriber '%s' in %s region...", params['SUBSCRIBER_NAME'], region)
        security_lake.create_subscriber_notification(sl_client, subscriber_id)


def update_query_subscriber(sl_client, params, sources, region, subscriber_id):
    """Update query access subscriber.

    Args:
        params: parameters
        sources: AWS log sources
        region: AWS region
        sl_client: boto3 client
        subscriber_id: subscriber id
    """
    resource_share_arn = security_lake.update_subscriber(
        sl_client,
        subscriber_id,
        sources,
        params["QUERY_EXTERNAL_ID"],
        params["QUERY_SUBSCRIBER_ACCT"],
        params["QUERY_SUBSCRIBER_NAME"],
        params["SOURCE_VERSION"],
    )

    configure_query_subscriber(
        "sra-security-lake-query-subscriber",
        params["QUERY_SUBSCRIBER_ACCT"],
        params["QUERY_SUBSCRIBER_NAME"],
        params["DELEGATED_ADMIN_ACCOUNT_ID"],
        region,
        resource_share_arn,
    )
    create_athena_query_bucket("sra-security-lake-query-subscriber", params["QUERY_SUBSCRIBER_ACCT"], region)


def update_data_subscriber(sl_client, params, sources, region, subscriber_id):
    """Update data access subscriber.

    Args:
        params: parameters
        sources: aws log sources
        region: AWS region
        sl_client: boto3 client
        subscriber_id: subscriber id
    """
    resource_share_arn = security_lake.update_subscriber(
        sl_client,
        subscriber_id,
        sources,
        params["DATA_EXTERNAL_ID"],
        params["DATA_SUBSCRIBER_ACCT"],
        params["DATA_SUBSCRIBER_NAME"],
        params["SOURCE_VERSION"],
    )
    if params["CREATE_NOTIFICATION"] != "ignore":
        LOGGER.info("Updating subscriber notification for subscriber '%s' in %s region...", params['SUBSCRIBER_NAME'], region)  # TODO: remove notificaiton configuration
        security_lake.update_subscriber_notification(sl_client, subscriber_id)


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
    LOGGER.info("Configuring resource share for subscriber '%s' in %s region...", subscriber_name, region)
    security_lake.configure_resource_share_in_subscriber_acct(ram_client, resource_share_arn)
    shared_db_name, shared_tables = security_lake.get_shared_resource_names(ram_client, resource_share_arn)
    if shared_tables == "" or shared_db_name == "":
        LOGGER.info("No shared resource names found for subscriber '%s' in %s region...", subscriber_name, region)
    else:
        LOGGER.info("Creating database '%s' data catalog for subscriber '%s' in %s region...", shared_db_name, subscriber_name, region)
        security_lake.create_db_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name)
        security_lake.create_table_in_data_catalog(
            configuration_role_name, region, subscriber_acct, shared_db_name, shared_tables, security_lake_acct
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
        if params["CREATE_DATA_SUBSCRIBER"]:
            if params["CREATE_NOTIFICATION"] != "ignore":
                security_lake.delete_subscriber_notification(sl_client, params["DATA_SUBSCRIBER_NAME"], region)
            security_lake.delete_subscriber(sl_client, params["DATA_SUBSCRIBER_NAME"], region)
        if params["CREATE_QUERY_SUBSCRIBER"]:
            security_lake.delete_subscriber(sl_client, params["QUERY_SUBSCRIBER_NAME"], region)
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
    print(event)
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


# def verify_creation_successful(params, regions):
#     for region in regions:
#         delegated_admin_session = common.assume_role(
#             params["CONFIGURATION_ROLE_NAME"], "sra-enable-security-lake", params["DELEGATED_ADMIN_ACCOUNT_ID"]   # TODO: (ieviero) use assume_role from sts class
#         )
#         sl_client = delegated_admin_session.client("securitylake", region)
#         lake_exists = security_lake.check_data_lake_exists(sl_client, region)
#         if lake_exists:
#             process_org_configuration(sl_client, params["SET_ORG_CONFIGURATION"], params["ORG_CONFIGURATION_SOURCES"], region, params["SOURCE_VERSION"])

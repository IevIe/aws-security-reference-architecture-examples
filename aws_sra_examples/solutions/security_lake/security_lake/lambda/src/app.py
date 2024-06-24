"""This script performs operations to enable, configure, update, and disable Security Lake.

Version: 1.0

'security_lake_org' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

import logging
import os
import re
from time import sleep
from typing import TYPE_CHECKING, Any, Dict, Optional, List

import boto3
import common
import security_lake
import sra_iam
import sra_ssm_params
import sra_s3
from crhelper import CfnResource
from pathlib import Path
import json
import random
import string

if TYPE_CHECKING:
    from aws_lambda_typing.context import Context
    from aws_lambda_typing.events import CloudFormationCustomResourceEvent
    from mypy_boto3_organizations import OrganizationsClient
    from mypy_boto3_iam.client import IAMClient

LOGGER = logging.getLogger("sra")
log_level: str = os.environ.get("LOG_LEVEL", "ERROR")
LOGGER.setLevel(log_level)

iam = sra_iam.sra_iam(LOGGER)
ssm = sra_ssm_params.sra_ssm_params(LOGGER)
helper = CfnResource(json_logging=True, log_level=log_level, boto_level="CRITICAL", sleep_on_delete=120)
s3 = sra_s3.sra_s3(LOGGER)

UNEXPECTED = "Unexpected!"
SERVICE_NAME = "securitylake.amazonaws.com"
META_STORE_MANAGER_ROLE = "AmazonSecurityLakeMetaStoreManagerV2"
META_STORE_MANAGER_POLICY = "AmazonSecurityLakeMetastoreManager"
REPLICATION_ROLE_NAME = "AmazonSecurityLakeS3ReplicationRole"
REPLICATION_ROLE_POLICY_NAME = "AmazonSecurityLakeS3ReplicationRolePolicy"
HOME_REGION = ssm.get_home_region()
AUDIT_ACCT_ID = ssm.get_security_acct()
ATHENA_QUERY_BUCKET_NAME = "sra-security-lake-query-results"


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
        regions: list of regions
        accounts: list of accounts

    Returns:
        Status
    """
    LOGGER.info("...process_add_event")

    if params["action"] in ["Add"]:
        LOGGER.info("...Create Security Lake")
        create_security_lake(params, regions, accounts)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            set_audit_acct_as_data_subscriber(params, regions, "sra-audit-account-data-subscriber")
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            set_audit_acct_as_query_subscriber(params, regions, "sra-audit-account-query-subscriber")
        LOGGER.info("...ADD_COMPLETE")
        return

    LOGGER.info("...ADD_NO_EVENT")


#  update security lake
def process_update_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts

    Returns:
        Status
    """
    LOGGER.info("...process_update_event")

    if params["action"] in ["Update"]:
        LOGGER.info("...Update Security Lake")
        update_security_lake(params, regions)
        add_update_log_sources(params, regions, accounts)
        if params["CREATE_SUBSCRIBER"]:
            process_subscriber(params, regions)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:
            set_audit_acct_as_data_subscriber(params, regions, "sra-audit-account-data-subscriber")
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            set_audit_acct_as_query_subscriber(params, regions, "sra-audit-account-query-subscriber")
        LOGGER.info("...UPDATE_COMPLETE")
        return

    LOGGER.info("...UPDATE_NO_EVENT")


def process_delete_event(params: dict, regions: list, accounts: list) -> None:
    """Process Add or Update Events.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts

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
    subscriber_log_source_pattern=r"(?i)^((ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF),?){0,7}($|ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF){1}$"
    version_pattern = r"^[0-9.]+$"

    # Required Parameters
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$")
    parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", params.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$")
    parameter_pattern_validator("AWS_PARTITION", params.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$")
    parameter_pattern_validator("CONFIGURATION_ROLE_NAME", params.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$")
    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern)
    parameter_pattern_validator(
        "CREATE_KMS_KEY", params.get("CREATE_KMS_KEY"), pattern=true_false_pattern
    )  #  TODO: have managed preset as default unless key created

    parameter_pattern_validator("SET_AUDIT_ACCT_DATA_SUBSCRIBER", params.get("SET_AUDIT_ACCT_DATA_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("SET_AUDIT_ACCT_QUERY_SUBSCRIBER", params.get("SET_AUDIT_ACCT_QUERY_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("CREATE_SUBSCRIBER", params.get("CREATE_SUBSCRIBER"), pattern=true_false_pattern)
    parameter_pattern_validator("SOURCE_VERSION", params.get("SOURCE_VERSION"), pattern=version_pattern)

    # Optional Parameters
    parameter_pattern_validator("SUBSCRIBER_NAME", params.get("SUBSCRIBER_NAME"), pattern=r"^$|^[a-zA-Z][-a-zA-Z0-9]*$", is_optional=True)
    parameter_pattern_validator("EXTERNAL_ID", params.get("EXTERNAL_ID"), pattern=r"^$|^[a-zA-Z0-9-]{1,64}$", is_optional=True)
    parameter_pattern_validator(
        "SUBSCRIBER_REGIONS",
        params.get("SUBSCRIBER_REGIONS"),
        pattern=r"^$|^([a-z0-9-]{1,64})$|^(([a-z0-9-]{1,64},)*[a-z0-9-]{1,64})$",
        is_optional=True,
    )
    parameter_pattern_validator(
        "DATA_ACCESS_METHOD", params.get("DATA_ACCESS_METHOD"), pattern=r"(?i)^(LAKEFORMATION|S3){1}$", is_optional=True
    )
    parameter_pattern_validator(
        "SUBSCRIBER_LOG_SOURCES",
        params.get("SUBSCRIBER_LOG_SOURCES"),
        pattern=subscriber_log_source_pattern,
        is_optional=True,
    )
    parameter_pattern_validator("SUBSCRIBER_ACCT", params.get("SUBSCRIBER_ACCT"), pattern=r"^\d{12}$", is_optional=True)
    parameter_pattern_validator(
        "CREATE_NOTIFICATION", params.get("CREATE_NOTIFICATION"), pattern=r"(?i)^(ignore|SQS){1}$", is_optional=True
    )

    parameter_pattern_validator("ENABLED_REGIONS", params.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True)

    parameter_pattern_validator("CLOUD_TRAIL_MGMT", params.get("CLOUD_TRAIL_MGMT"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("ROUTE53", params.get("ROUTE53"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("VPC_FLOW", params.get("VPC_FLOW"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("SH_FINDINGS", params.get("SH_FINDINGS"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("LAMBDA_EXECUTION", params.get("LAMBDA_EXECUTION"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("S3_DATA", params.get("S3_DATA"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("EKS_AUDIT", params.get("EKS_AUDIT"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)
    parameter_pattern_validator("WAF", params.get("WAF"), pattern=r"^($|ALL|(\d{12})(,\s*\d{12})*)$", is_optional=True)

    #  Convert true/false string parameters to boolean
    params.update({"CREATE_SUBSCRIBER": (params["CREATE_SUBSCRIBER"] == "true")})
    params.update({"SET_AUDIT_ACCT_DATA_SUBSCRIBER": (params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"] == "true")})
    params.update({"SET_AUDIT_ACCT_QUERY_SUBSCRIBER": (params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"] == "true")})
    params.update({"CREATE_KMS_KEY": (params["CREATE_KMS_KEY"] == "true")})
    params.update({"CONTROL_TOWER_REGIONS_ONLY": (params["CONTROL_TOWER_REGIONS_ONLY"] == "true")})

    return params


def create_meta_store_manager_role(iam_client):  # TODO: should partition be a parameter?
    managed_policy_arn = f"arn:{PARTITION}:iam::{PARTITION}:policy/service-role/{META_STORE_MANAGER_POLICY}"

    role_exists = iam.check_iam_role_exists(iam_client, META_STORE_MANAGER_ROLE)
    if role_exists:
        LOGGER.info(f"IAM role '{META_STORE_MANAGER_ROLE}' already exists.")
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
        regions: list of regions
        accounts: list of accounts
    """

    for account in accounts:
        security_lake.create_service_linked_role(account["AccountId"], params["CONFIGURATION_ROLE_NAME"])

    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-enable-security-lake", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )  # TODO: (Ieviero) add sts class instead of common
    iam_client = delegated_admin_session.client("iam", HOME_REGION)
    create_meta_store_manager_role(iam_client)

    security_lake.register_delegated_admin(params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, SERVICE_NAME)
    deploy_security_lake(params, regions)
    add_update_log_sources(params, regions, accounts)

    if params["CREATE_SUBSCRIBER"]:
        process_subscriber(params, regions)


def deploy_security_lake(params, regions):  # TODO ieviero is there a need to check if security lake already exists?
    for region in regions:
        LOGGER.info(f"Creating Security Lake in {region} region...")
        sl_configurations = security_lake.set_configurations(region)
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-enable-security-lake", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )  # TODO: (ieviero) use assume_role from sts class
        sl_client = delegated_admin_session.client("securitylake", region)
        security_lake.create_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations, region)
        sleep(15)
        LOGGER.info(f"Security Lake created in {region} with configurations {sl_configurations}")


def build_subscriber_log_sources(sources_param: str) -> list:
    """Build list of log sources.

    Args:
        source_param: Input from cfn parameter

    Returns:
        list of log sources
    """
    log_sources: list = []
    log_sources = sources_param.split(",")

    return log_sources


def update_security_lake(params, regions):  # TODO: (ieviero) execute security_lake.update_security_lake only if changes introduced
    for region in regions:
        sl_configurations = security_lake.set_configurations(region)
        LOGGER.info(f"Checking if Security Lake exists in {region} region...")
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-update-security-lake", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )  # TODO: (ieviero) use assume_role from sts class
        sl_client = delegated_admin_session.client("securitylake", region)
        lake_exists = security_lake.check_data_lake_exists(sl_client, region)
        if lake_exists:
            LOGGER.info(f"Security Lake already exists in {region} region. Updating...")
            # security_lake.update_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations)
            # sleep(15)
        else:
            LOGGER.info(f"Security Lake not found in {region} region. Creating Security Lake...")
            security_lake.create_security_lake(sl_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], sl_configurations, region)
            sleep(15)


def add_update_log_sources(params, regions, org_accounts):
    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-add-update-log-sources", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )
    sl_client = delegated_admin_session.client("securitylake", HOME_REGION)
    log_sources = ["ROUTE53", "VPC_FLOW", "SH_FINDINGS", "CLOUD_TRAIL_MGMT", "LAMBDA_EXECUTION", "S3_DATA", "EKS_AUDIT", "WAF"]
    for i in log_sources:
        if params[i] != "":
            if params[i] == "ALL":
                accounts = []
                for account in org_accounts:
                    accounts.append(account["AccountId"])
            else:
                accounts = params[i].split(",")
            source = i
            security_lake.set_aws_log_source(sl_client, regions, source, accounts, params["SOURCE_VERSION"])
        elif params[i] == "":
            LOGGER.info(f"Skipping {i} log and event source...")
        else:
            LOGGER.info(f"Error reading value for {i} parameter")


def set_audit_acct_as_data_subscriber(params, regions, subscriber_name):
    for region in regions:
        sources = get_log_sources_for_audit_subscriber(params)  # TODO: (ieviero) get existing sources from list_sources
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, subscriber_name)
        if subscriber_exists:
            LOGGER.info(f"Audit account subscriber '{subscriber_name}' exists in {region} region. Updating subscriber...")
            resource_share_arn = security_lake.update_subscriber(sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"])
            #  TODO: should there be options for notifications endpoint?
            LOGGER.info(f"Updating subscriber notification for Audit account subscriber '{subscriber_name}' in {region} region...")
            security_lake.update_subscriber_notification(sl_client, subscriber_id)
        else:
            characters = string.ascii_letters + string.digits
            external_id = "".join(random.choices(characters, k=8))
            LOGGER.info(f"Audit account subscriber '{subscriber_name}' does not exist in {region} region. Creating subscriber...")
            subscriber_id, resource_share_arn = security_lake.create_subscribers(
                sl_client, "S3", sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
            )
            LOGGER.info(f"Creating SQS notification for Audit account subscriber '{subscriber_name}' in {region} region...")
            security_lake.create_subscriber_notification(sl_client, subscriber_id)


def get_log_sources_for_audit_subscriber(params):  # TODO: (ieviero) check which sources are enabled using list_sources
    log_sources = []
    for source in ["ROUTE53", "VPC_FLOW", "SH_FINDINGS", "CLOUD_TRAIL_MGMT", "LAMBDA_EXECUTION", "S3_DATA", "EKS_AUDIT", "WAF"]:
        if params[source] != "":
            log_sources.append(source)
    return log_sources


def set_audit_acct_as_query_subscriber(params, regions, subscriber_name):
    for region in regions:
        sources = get_log_sources_for_audit_subscriber(params)
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-configure-audit-acct-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, subscriber_name)
        if subscriber_exists:
            LOGGER.info(f"Audit account subscriber '{subscriber_name}' exists in {region} region. Updating subscriber...")
            resource_share_arn = security_lake.update_subscriber(sl_client, subscriber_id, sources, external_id, AUDIT_ACCT_ID, subscriber_name, params["SOURCE_VERSION"])
        else:
            characters = string.ascii_letters + string.digits
            external_id = "".join(random.choices(characters, k=8))
            LOGGER.info(f"Audit account subscriber '{subscriber_name}' does not exist in {region} region. Creating subscriber...")
            subscriber_id, resource_share_arn = security_lake.create_subscribers(
                sl_client, "LAKEFORMATION", sources, external_id, AUDIT_ACCT_ID, subscriber_name, region, params["SOURCE_VERSION"]
            )
        configure_query_subscriber(
            params["CONFIGURATION_ROLE_NAME"], AUDIT_ACCT_ID, subscriber_name, params["DELEGATED_ADMIN_ACCOUNT_ID"], region, resource_share_arn
        )
        create_athena_query_bucket(params["CONFIGURATION_ROLE_NAME"], AUDIT_ACCT_ID, region)


def build_subscriber_regions(subscriber_regions_param, security_lake_regions):
    subscriber_regions = []
    subscriber_regions = subscriber_regions_param.split(",")
    subscriber_regions = [region for region in subscriber_regions if region in security_lake_regions]

    return subscriber_regions


def process_subscriber(params, regions):  # TODO: how to update subscriber external_id? 
    sources = build_subscriber_log_sources(params["SUBSCRIBER_LOG_SOURCES"])
    subscriber_regions = build_subscriber_regions(params["SUBSCRIBER_REGIONS"], regions)

    for region in subscriber_regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-process-subscriber", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        subscriber_exists, subscriber_id, external_id = security_lake.list_subscribers(sl_client, params["SUBSCRIBER_NAME"])
        
        if subscriber_exists:
            LOGGER.info(f"Subscriber '{params['SUBSCRIBER_NAME']}' exists in {region} region. Updating subscriber...")
            update_subscriber(sl_client, params, sources, region, subscriber_id)

        else:
            LOGGER.info(f"Subscriber '{params['SUBSCRIBER_NAME']}' does not exist in {region} region. Creating subscriber...")
            add_subscriber(sl_client, params, sources, region)


def add_subscriber(sl_client, params, sources, region):
    subscriber_id, resource_share_arn = security_lake.create_subscribers(
        sl_client,
        params["DATA_ACCESS_METHOD"],
        sources,
        params["EXTERNAL_ID"],
        params["SUBSCRIBER_ACCT"],
        params["SUBSCRIBER_NAME"],
        region,
        params["SOURCE_VERSION"]
    )
    if subscriber_id == 'error occured':
        pass
    else: 
        if params["DATA_ACCESS_METHOD"] == "S3":
            if params["CREATE_NOTIFICATION"] != "ignore":
                LOGGER.info(f"Creating subscriber notification for subscriber '{params['SUBSCRIBER_NAME']}' in {region} region...")
                security_lake.create_subscriber_notification(sl_client, subscriber_id)
        if params["DATA_ACCESS_METHOD"] == "LAKEFORMATION":
            configure_query_subscriber(
                params["CONFIGURATION_ROLE_NAME"],
                params["SUBSCRIBER_ACCT"],
                params["SUBSCRIBER_NAME"],
                params["DELEGATED_ADMIN_ACCOUNT_ID"],
                region,
                resource_share_arn,
            )
            create_athena_query_bucket(params["CONFIGURATION_ROLE_NAME"], params["SUBSCRIBER_ACCT"], region)


def update_subscriber(sl_client, params, sources, region, subscriber_id):
    resource_share_arn = security_lake.update_subscriber(
        sl_client, subscriber_id, sources, params["EXTERNAL_ID"], params["SUBSCRIBER_ACCT"], params["SUBSCRIBER_NAME"], params["SOURCE_VERSION"]
    )
    if params["DATA_ACCESS_METHOD"] == "S3":
        if params["CREATE_NOTIFICATION"] != "ignore":
            LOGGER.info(f"Updating subscriber notification for subscriber '{params['SUBSCRIBER_NAME']}' in {region} region...")
            security_lake.update_subscriber_notification(sl_client, subscriber_id)
    if params["DATA_ACCESS_METHOD"] == "LAKEFORMATION":
        configure_query_subscriber(
            params["CONFIGURATION_ROLE_NAME"],
            params["SUBSCRIBER_ACCT"],
            params["SUBSCRIBER_NAME"],
            params["DELEGATED_ADMIN_ACCOUNT_ID"],
            region,
            resource_share_arn,
        )
        create_athena_query_bucket(params["CONFIGURATION_ROLE_NAME"], params["SUBSCRIBER_ACCT"], region)


def configure_query_subscriber(configuration_role_name, subscriber_acct, subscriber_name, security_lake_acct, region, resource_share_arn):
    subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
    ram_client = subscriber_session.client("ram", region)
    LOGGER.info(f"Configuring resource share for subscriber '{subscriber_name}' in {region} region...")
    security_lake.configure_resource_share_in_subscriber_acct(ram_client, resource_share_arn)
    LOGGER.info(f"Getting shared resource database and table names for subscriber '{subscriber_name}' in {region} region...")
    shared_db_name, shared_tables = security_lake.get_shared_resource_names(ram_client, resource_share_arn)
    if shared_tables == "" or shared_db_name == "":
        LOGGER.info(f"No shared resource names found for subscriber '{subscriber_name}' in {region} region...")
        pass
    else:
        LOGGER.info(f"Creating database '{shared_db_name}' data catalog for subscriber '{subscriber_name}' in {region} region...")
        security_lake.create_db_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name)
        security_lake.create_table_in_data_catalog(
            configuration_role_name, region, subscriber_acct, shared_db_name, shared_tables, security_lake_acct
        )


def create_athena_query_bucket(configuration_role_name, subscriber_acct_id, region): # TODO: (ieviero) add bucket policy and kms key
    """Check if Athena query results bucket exists, if not, create it."""
    LOGGER.info("Checking/deploying Athena S3 resources...")
    subscriber_acct_session = common.assume_role(configuration_role_name, "sra-delete-security-lake-subscribers", subscriber_acct_id)
    s3_client = subscriber_acct_session.client("s3", region)
    bucket_name = f"{ATHENA_QUERY_BUCKET_NAME}-{subscriber_acct_id}-{region}"
    bucket_exists = s3.query_for_s3_bucket(s3_client, bucket_name)
    if bucket_exists is True:
        LOGGER.info(f"Bucket {bucket_name} already exists.")
    if bucket_exists is False:
        LOGGER.info(f"Bucket not found, creating {bucket_name} s3 bucket...")
        s3.create_s3_bucket(s3_client, bucket_name, "bucket_policy", "kms_key_id", region)


# def update_query_subscriber(configuration_role_name, subscriber_acct, subscriber_name, security_lake_acct, region, resource_share_arn):
#     subscriber_session = common.assume_role(configuration_role_name, "sra-create-resource-share", subscriber_acct)
#     ram_client = subscriber_session.client("ram", region)
#     LOGGER.info(f"Getting shared resource database and table names for subscriber '{subscriber_name}' in {region} region...")
#     shared_db_name, shared_tables = security_lake.get_shared_resource_names(ram_client, resource_share_arn)
#     if shared_tables == "" or shared_db_name == "":
#         LOGGER.info(f"No shared resource names found for subscriber '{subscriber_name}' in {region} region...")
#         pass
#     else:
#         LOGGER.info(f"Creating database '{shared_db_name}' data catalog for subscriber '{subscriber_name}' in {region} region...")
#         security_lake.create_db_in_data_catalog(configuration_role_name, region, subscriber_acct, shared_db_name)
#         security_lake.create_table_in_data_catalog(
#             configuration_role_name, region, subscriber_acct, shared_db_name, shared_tables, security_lake_acct
#         )


def disable_security_lake(params: dict, regions: list, accounts) -> None:  #  TODO: (ieviero) should parameter or event "Delete" be added?
    """Disable the security lake service.

    Args:
        params: Configuration Parameters
    """
    for region in regions:
        delegated_admin_session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-delete-security-lake-subscribers", params["DELEGATED_ADMIN_ACCOUNT_ID"]
        )
        sl_client = delegated_admin_session.client("securitylake", region)
        if params["CREATE_SUBSCRIBER"]:
            if params["CREATE_NOTIFICATION"] != 'ignore' and params["DATA_ACCESS_METHOD"] == "S3":
                security_lake.delete_subscriber_notification(sl_client, params["SUBSCRIBER_NAME"], region)
            security_lake.delete_subscriber(sl_client, params["SUBSCRIBER_NAME"], region)
        if params["SET_AUDIT_ACCT_DATA_SUBSCRIBER"]:  # TODO: (ieviero) parameterize/set global var for audit account subscriber name.
            security_lake.delete_subscriber_notification(sl_client, "sra-audit-account-data-subscriber", region)
            security_lake.delete_subscriber(sl_client, "sra-audit-account-data-subscriber", region)
        if params["SET_AUDIT_ACCT_QUERY_SUBSCRIBER"]:
            security_lake.delete_subscriber(sl_client, "sra-audit-account-query-subscriber", region)
        
    security_lake.delete_security_lake(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, regions)

    delegated_admin_session = common.assume_role(
        params["CONFIGURATION_ROLE_NAME"], "sra-delete-security-lake-roles", params["DELEGATED_ADMIN_ACCOUNT_ID"]
    )  # todo: add sts class, initiate iam_client and pass it
    iam_client = delegated_admin_session.client("iam", HOME_REGION)

    meta_store_policy_arn: str = f"arn:{PARTITION}:iam::{PARTITION}:policy/service-role/{META_STORE_MANAGER_POLICY}"
    delete_iam_resources(iam_client, META_STORE_MANAGER_ROLE, meta_store_policy_arn)

    for account in accounts:
        session = common.assume_role(
            params["CONFIGURATION_ROLE_NAME"], "sra-delete-security-lake-slr", account["AccountId"]
        )  # TODO: add sts class, initiate iam_client and pass it
        iam_client = session.client("iam", HOME_REGION)
        deletion_task_id = iam.delete_service_linked_role(iam_client, "AWSServiceRoleForSecurityLake")
        sleep(2)
        iam.get_deletion_status(iam_client, deletion_task_id)  # TODO: (ieviero) update get_deletion_status function

    security_lake.deregister_administrator_organizations(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)
    # disable_aws_service_access(SERVICE_NAME)


def delete_iam_resources(iam_client: IAMClient, role_name: str, policy_arn: str) -> None:
    role_exists = iam.check_iam_role_exists(iam_client, role_name)
    if role_exists:
        if not policy_arn or not isinstance(policy_arn, str):
            raise ValueError("Invalid policy_arn parameter")
        iam.detach_policy(iam_client, role_name, policy_arn)
        iam.delete_role(iam_client, role_name)
    if not role_exists:
        LOGGER.info(f"...Role {role_name} does not exist...")


def disable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
    """Disable service access for the provided service principal within AWS Organizations.

    Args:
        service_principal: Service Principal
    """
    try:
        LOGGER.info(f"Disabling service access for '{service_principal}' service principal...")

        ORG_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)
    except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
        LOGGER.info(f"Service ({service_principal}) does not have organizations access revoked: {error}")


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
    LOGGER.info(f"boto3 version: {boto3_version}")
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
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
    if params["action"] == "Add":
        LOGGER.info("calling process_add_event")
        process_add_event(params, regions, accounts)
    elif params["action"] == "Update":
        LOGGER.info("calling process_update_event")
        process_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Security Lake from (process_event_cloudformation)")
        process_delete_event(params, regions, accounts)

    return f"sra-security-lake-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


# TODO: iev deregister delegated administrator using securitylake api
# def deregister_delegated_administrator(delegated_admin_account_id: str, service_principal: str = SERVICE_NAME) -> None:
#     """Deregister the delegated administrator account for the provided service principal within AWS Organizations.

#     Args:
#         delegated_admin_account_id: Delegated Admin Account
#         service_principal: Service Principal
#     """
#     try:
#         LOGGER.info(f"Deregistering the delegated admin {delegated_admin_account_id} for {service_principal}")
#         ORG_CLIENT.deregister_delegated_administrator(AccountId=delegated_admin_account_id, ServicePrincipal=service_principal)
#     except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
# LOGGER.error(f"AccountNotRegisteredException: Account ({delegated_admin_account_id}) is not a registered delegated administrator: {error}")


# def check_aws_service_access(service_principal: str = SERVICE_NAME) -> bool:
#     """Check service access for the provided service principal within AWS Organizations.

#     Args:
#         service_principal: Service principal

#     Returns:
#         True or False
#     """
#     aws_service_access_enabled = False
#     LOGGER.info(f"Checking service access for {service_principal}...")
#     try:
#         org_svc_response = ORG_CLIENT.list_aws_service_access_for_organization()
#         api_call_details = {
#             "API_Call": "organizations:ListAwsServiceAccessForOrganization",
#             "API_Response": org_svc_response,
#         }
#         LOGGER.info(api_call_details)

#         for service in org_svc_response["EnabledServicePrincipals"]:
#             if service["ServicePrincipal"] == service_principal:
#                 aws_service_access_enabled = True
#                 return True
#     except ORG_CLIENT.exceptions.AccessDeniedException as error:
#         LOGGER.error(f"AccessDeniedException: unable to check service access for {service_principal}: {error}")
#     return aws_service_access_enabled


# def enable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
#     """Enable service access for the provided service principal within AWS Organizations.

#     Args:
#         service_principal: Service Principal
#     """
#     if check_aws_service_access(service_principal) is False:
#         try:
#             LOGGER.info(f"Enabling service access for {service_principal}")
#             ORG_CLIENT.enable_aws_service_access(ServicePrincipal=service_principal)
#         except ORG_CLIENT.exceptions.AccessDeniedException as error:
#             LOGGER.info(f"Failed to enable service access for {service_principal} in organizations: {error}")
#     else:
#         LOGGER.info(f"Organizations service access for {service_principal} is already enabled")


# def disable_security_lake_service(params: dict) -> None:
#     """Primary function to remove all components of the security lake sra feature.

#     Args:
#         params: Configuration Parameters
#     """
#     LOGGER.info("Remove security lake")

#     deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

#     disable_aws_service_access(SERVICE_NAME)


# create role for subscriber data access.
# TODO: IS THIS ROLE FOR HTTP ENDPOINT ONLY?
# def add_update_subscriber_role(iam_client, regions, role_name, policy_name, delegated_admin_id):
#     resources_list = []
#     for region in regions:
#         resources_list.append(f"arn:aws:events:{region}:{delegated_admin_id}:api-destination/AmazonSecurityLake*/*")
#     policy_document = {
#         "Version": "2012-10-17",
#         "Statement": [
#             {"Sid": "AllowInvokeApiDestination", "Effect": "Allow", "Action": ["events:InvokeApiDestination"], "Resource": delegated_admin_id}
#         ],
#     }
#     role_exists = iam.check_iam_role_exists(iam_client, role_name)
#     if role_exists:
#         LOGGER.info(f"...Role {role_name} already exists")
#         iam.delete_policy(iam_client, policy_arn)
#         iam.attach_policy(iam_client, role_name, policy_name, policy_document)
#     if not role_exists:
#         trust_policy = {
#             "Version": "2012-10-17",
#             "Statement": [
#                 {"Sid": "AllowEventBridgeToAssume", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole"}
#             ],
#         }
#         iam.create_role(iam_client, role_name, trust_policy)
#         iam.attach_policy(iam_client, role_name, policy_name, policy_document)
#     return role_name


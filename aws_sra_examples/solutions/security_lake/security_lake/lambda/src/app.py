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
from crhelper import CfnResource
from pathlib import Path
import json

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

UNEXPECTED = "Unexpected!"
SERVICE_NAME = "securitylake.amazonaws.com"
META_STORE_MANAGER_ROLE = "AmazonSecurityLakeMetaStoreManagerV2"
META_STORE_MANAGER_POLICY = "AmazonSecurityLakeMetastoreManager"
REPLICATION_ROLE_NAME = "AmazonSecurityLakeS3ReplicationRole"
REPLICATION_ROLE_POLICY_NAME = "AmazonSecurityLakeS3ReplicationRolePolicy"
HOME_REGION = ssm.get_home_region()

try:
    MANAGEMENT_ACCOUNT_SESSION = boto3.Session()
    ORG_CLIENT: OrganizationsClient = MANAGEMENT_ACCOUNT_SESSION.client("organizations")
    PARTITION: str = MANAGEMENT_ACCOUNT_SESSION.get_partition_for_region(HOME_REGION)
except Exception:
    LOGGER.exception(UNEXPECTED)
    raise ValueError("Unexpected error executing Lambda function. Review CloudWatch logs for details.") from None


# add security lake
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
        LOGGER.info("...Configure Security Lake")
        setup_security_lake(params, regions, accounts)
        LOGGER.info("...ADD_COMPLETE")
        return

    LOGGER.info("...ADD_NO_EVENT")


# update security lake
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
        update_security_lake(params, regions, accounts)
        LOGGER.info("...UPDATE_COMPLETE")
        return

    LOGGER.info("...UPDATE_NO_EVENT")


def process_event(event: dict) -> None:
    """Process Event.

    Args:
        event: event data
    """
    event_info = {"Event": event}
    LOGGER.info(event_info)
    # params = get_validated_parameters({"RequestType": "Update"})
    params = get_validated_parameters(event)  # todo: set env params in lambda after testing complete

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


def get_validated_parameters(event: Dict[str, Any]) -> dict:
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

    # Required Parameters
    # params.update(
    parameter_pattern_validator("DELEGATED_ADMIN_ACCOUNT_ID", params.get("DELEGATED_ADMIN_ACCOUNT_ID"), pattern=r"^\d{12}$")
    # )
    # params.update(
    parameter_pattern_validator("MANAGEMENT_ACCOUNT_ID", params.get("MANAGEMENT_ACCOUNT_ID"), pattern=r"^\d{12}$")
    # )
    # params.update(
    parameter_pattern_validator("AWS_PARTITION", params.get("AWS_PARTITION"), pattern=r"^(aws[a-zA-Z-]*)?$")
    # )
    # params.update(
    parameter_pattern_validator("CONFIGURATION_ROLE_NAME", params.get("CONFIGURATION_ROLE_NAME"), pattern=r"^[\w+=,.@-]{1,64}$")
    # )
    # params.update(
    parameter_pattern_validator("CONTROL_TOWER_REGIONS_ONLY", params.get("CONTROL_TOWER_REGIONS_ONLY"), pattern=true_false_pattern)
    # )
    # params.update(
    parameter_pattern_validator("CREATE_KMS_KEY", params.get("CREATE_KMS_KEY"), pattern=true_false_pattern)  #  TODO: have managed preset as default unles key created
    # )
    parameter_pattern_validator("SOURCES", params.get("SOURCES"), pattern=r"(?i)^((ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF),?){0,7}(ROUTE53|VPC_FLOW|SH_FINDINGS|CLOUD_TRAIL_MGMT|LAMBDA_EXECUTION|S3_DATA|EKS_AUDIT|WAF){1}$")

    # Optional Parameters
    # params.update(
    parameter_pattern_validator("ENABLED_REGIONS", params.get("ENABLED_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True)
    # )
    # params.update(
    parameter_pattern_validator("REPLICATION_REGIONS", params.get("REPLICATION_REGIONS"), pattern=r"^$|[a-z0-9-, ]+$", is_optional=True)
    # )
    # params.update(
    parameter_pattern_validator("EXPIRATION_DAYS", params.get("EXPIRATION_DAYS"), pattern=r"^[0-9]+$|^$", is_optional=True)
    # )
    # params.update(
    parameter_pattern_validator("TRANSITION_DAYS", params.get("TRANSITION_DAYS"), pattern=r"^[1-9]$|^[0-9][0-9]$|^[0-9][0-9][0-9]$|^[0-1][0]([0-8][0-9]|[9][0-5])$", is_optional=True)  # TODO: update pattern
    # )
    # params.update(
    parameter_pattern_validator("STORAGE_CLASS", params.get("STORAGE_CLASS"), pattern=r"^(ONEZONE_IA|GLACIER|STANDARD_IA|INTELLIGENT_TIERING|DEEP_ARCHIVE){1}$", is_optional=True)
    # )
    
    
    # convert str o int
    params.update({"EXPIRATION_DAYS": (int(params["EXPIRATION_DAYS"]))})
    params.update({"TRANSITION_DAYS": (int(params["TRANSITION_DAYS"]))})
    
    # Convert true/false string parameters to boolean
    # params.update({"ALL_SUPPORTED": (params["ALL_SUPPORTED"] == "true")})
    # params.update({"INCLUDE_GLOBAL_RESOURCE_TYPES": (params["INCLUDE_GLOBAL_RESOURCE_TYPES"] == "true")})
    LOGGER.info(f"Parameters: {params}")
    return params


def create_meta_store_manager_role(iam_client):  # TODO: should partition be a parameter?
    managed_policy_arn = f"arn:{PARTITION}:iam::{PARTITION}:policy/service-role/{META_STORE_MANAGER_POLICY}"

    role_exists = iam.check_iam_role_exists(iam_client, META_STORE_MANAGER_ROLE)
    if role_exists:
        LOGGER.info(f"...Role {META_STORE_MANAGER_ROLE} already exists")
    if not role_exists:
        trust_policy = {"Version":"2012-10-17","Statement":[{"Sid":"","Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
        iam.create_role(iam_client, META_STORE_MANAGER_ROLE, trust_policy)
        iam.attach_managed_policy(iam_client, META_STORE_MANAGER_ROLE, managed_policy_arn)


def set_replication_policy(regions, rollup_regions, control_tower_only, enabled_regions, admin_account_id):
    with Path("data_replication_policy.json").open() as policy_file:
        policy = json.load(policy_file)

    source: List[str] = []
    destination: List[str] = []
    if control_tower_only == "false" and enabled_regions == "":
        source = [
                "arn:aws:s3:::aws-security-data-lake*",
                "arn:aws:s3:::aws-security-data-lake*/*"
            ]
    else:
        for region in regions:
            if region in rollup_regions:
                pass
        else:
            source.append(f"arn:aws:s3:::aws-security-data-lake-{region}*")
            source.append(f"arn:aws:s3:::aws-security-data-lake-{region}*/*")
    source_regions = ', '.join(F'"{item}"' for item in source)

    for region in rollup_regions:
        destination.append(f"arn:aws:s3:::aws-security-data-lake-{region}*/*")
    destination_regions = ', '.join(F'{item}' for item in destination)
    replication_policy = (json.dumps(policy)
                          .replace("BUCKET_OWNER_ACCOUNT", admin_account_id)
                          .replace('"SOURCE_REGIONS"', source_regions)
                          .replace("DESTINATION_REGIONS", destination_regions)
    )
    return replication_policy


def create_replication_role(iam_client, delegated_admin_id, regions, rollup_regions, control_tower_only, enabled_regions):
    policy = set_replication_policy(regions, rollup_regions, control_tower_only, enabled_regions, delegated_admin_id)
    
    policy_arn = f"arn:{PARTITION}:iam::{delegated_admin_id}:policy/{REPLICATION_ROLE_POLICY_NAME}"
    trust_policy = {"Version":"2012-10-17","Statement":[{"Sid":"","Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}
    
    role_exists = iam.check_iam_role_exists(iam_client, REPLICATION_ROLE_NAME)
    if role_exists:
        LOGGER.info(f"...Role {REPLICATION_ROLE_NAME} already exist, updating policy")
        iam.update_policy(iam_client, policy_arn, policy)
    if not role_exists:
        iam.create_policy(iam_client, REPLICATION_ROLE_POLICY_NAME, policy)
        iam.create_role(iam_client, REPLICATION_ROLE_NAME, trust_policy)
        iam.attach_managed_policy(iam_client, REPLICATION_ROLE_NAME, policy_arn)


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


# def disable_aws_service_access(service_principal: str = SERVICE_NAME) -> None:
#     """Disable service access for the provided service principal within AWS Organizations.

#     Args:
#         service_principal: Service Principal
#     """
#     try:
#         LOGGER.info(f"Disabling service access for {service_principal}")

#         ORG_CLIENT.disable_aws_service_access(ServicePrincipal=service_principal)
#     except ORG_CLIENT.exceptions.AccountNotRegisteredException as error:
#         LOGGER.info(f"Service ({service_principal}) does not have organizations access revoked: {error}")


# def disable_security_lake_service(params: dict) -> None:
#     """Primary function to remove all components of the security lake sra feature.

#     Args:
#         params: Configuration Parameters
#     """
#     LOGGER.info("Remove security lake")

#     deregister_delegated_administrator(params["DELEGATED_ADMIN_ACCOUNT_ID"], SERVICE_NAME)

#     disable_aws_service_access(SERVICE_NAME)


def build_log_sources(sources_param: str) -> list:
    """Build list of datasource packages. Adds required value of DETECTIVE_CORE.

    Args:
        datasource_packages_param: Input from cfn parameter

    Returns:
        list of datasource packages
    """
    # ROUTE53, VPC_FLOW, SH_FINDINGS, CLOUD_TRAIL_MGMT, LAMBDA_EXECUTION', S3_DATA, EKS_AUDIT, WAF
    log_sources: list = []
    # if "ASFF_SECURITYHUB_FINDING".lower() in datasource_packages_param.lower() or "EKS_AUDIT".lower() in datasource_packages_param.lower():
    log_sources = sources_param.split(",")

    return log_sources


def set_rollup_regions_list(rollup_regions: list = None):
    rollup_region_list = []
    LOGGER.info(f"Rollup regions, {rollup_regions}")
    if rollup_regions.strip():
        for region in rollup_regions.split(","):
            if region != "":
                rollup_region_list.append(region.strip())

    return rollup_region_list


def get_contributing_regions(regions, rollup_regions_list: list = None) -> list:
    contributing_regions = []

    for region in regions:
        if region in rollup_regions_list:
            pass
        else:
            contributing_regions.append(region)

    LOGGER.info(f"Contributing regions: {contributing_regions}")
    return contributing_regions


def setup_security_lake(params: dict, regions: list, accounts: list) -> None:
    """Enable the security lake service and configure its global settings.

    Args:
        params: Configuration Parameters
        regions: list of regions
        accounts: list of accounts
    """
    rollup_regions_list = set_rollup_regions_list(params["REPLICATION_REGIONS"])
    contributing_regions = get_contributing_regions(regions, rollup_regions_list)
    # enable_aws_service_access(SERVICE_NAME)
    security_lake.create_service_linked_role(params["MANAGEMENT_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"])

    for account in accounts:
        security_lake.create_service_linked_role(
            account["AccountId"],
            params["CONFIGURATION_ROLE_NAME"],
        )
    delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-enable-security-lake", params["DELEGATED_ADMIN_ACCOUNT_ID"])  # TODO: (Ieviero) add sts class instead of common
    iam_client = delegated_admin_session.client("iam", HOME_REGION)
    create_meta_store_manager_role(iam_client)
    create_replication_role(iam_client, params["DELEGATED_ADMIN_ACCOUNT_ID"], regions, rollup_regions_list, params["CONTROL_TOWER_REGIONS_ONLY"], params["ENABLED_REGIONS"])


    security_lake.register_delegated_admin(params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION)
    deploy_security_lake(params, rollup_regions_list, contributing_regions)
    sources = build_log_sources(params["SOURCES"])
    security_lake.set_aws_log_source(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], regions, sources)


def deploy_security_lake(params, rollup_regions_list, contributing_regions):  # TODO 
    #  create security lake in the rollup regions first
    for region in rollup_regions_list:
        LOGGER.info(f"Creating Security Lake created in {region} (rollup region)")
        sl_configurations = security_lake.set_configurations(params["DELEGATED_ADMIN_ACCOUNT_ID"], region, params["EXPIRATION_DAYS"], params["TRANSITION_DAYS"], params["STORAGE_CLASS"])
        security_lake.create_sec_lake_in_rollup_regions(region, params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], sl_configurations)
        sleep(30)
        LOGGER.info(f"Security Lake created in {region} (rollup region) with configurations {sl_configurations}")
    
    #  create security lake in the contributing regions
    for region in contributing_regions:
        LOGGER.info(f"Creating Security Lake created in {region}")
        sl_configurations = security_lake.set_configurations(params["DELEGATED_ADMIN_ACCOUNT_ID"], region, params["EXPIRATION_DAYS"], params["TRANSITION_DAYS"], params["STORAGE_CLASS"], rollup_regions_list)
        security_lake.create_security_lake(region, params["DELEGATED_ADMIN_ACCOUNT_ID"], params["CONFIGURATION_ROLE_NAME"], sl_configurations)
        sleep(30)
        LOGGER.info(f"Security Lake created in {region} with configurations {sl_configurations}")


def disable_security_lake(params: dict, regions: list) -> None:  #  TODO: (ieviero) should parameter or event "Delete" be added?
    """Disable the security lake service.

    Args:
        params: Configuration Parameters
    """
    security_lake.delete_security_lake(params["CONFIGURATION_ROLE_NAME"], params["DELEGATED_ADMIN_ACCOUNT_ID"], HOME_REGION, regions)

    delegated_admin_session = common.assume_role(params["CONFIGURATION_ROLE_NAME"], "sra-enable-security-lake", params["DELEGATED_ADMIN_ACCOUNT_ID"])  # todo: add sts class, initiate iam_client and pass it
    iam_client = delegated_admin_session.client("iam", HOME_REGION)
    
    LOGGER.info(f"...Deleting {REPLICATION_ROLE_NAME} IAM role in {params['DELEGATED_ADMIN_ACCOUNT_ID']} account...")
    policy_arn = f"arn:{PARTITION}:iam::{params['DELEGATED_ADMIN_ACCOUNT_ID']}:policy/{REPLICATION_ROLE_POLICY_NAME}"  # TODO: should policy arn be set in iam class or as a global var
    delete_iam_resources(iam_client, REPLICATION_ROLE_NAME, policy_arn)

    LOGGER.info(f"...Deleting {META_STORE_MANAGER_ROLE} IAM role in {params['DELEGATED_ADMIN_ACCOUNT_ID']} account...")
    meta_store_policy_arn: str = f"arn:{PARTITION}:iam::{PARTITION}:policy/service-role/{META_STORE_MANAGER_POLICY}"
    delete_iam_resources(iam_client, META_STORE_MANAGER_ROLE, meta_store_policy_arn)

    LOGGER.info(f"...Deleting service linked 'AWSServiceRoleForSecurityLake' IAM role in {params['DELEGATED_ADMIN_ACCOUNT_ID']} account...")
    deletion_task_id = iam.delete_service_linked_role(iam_client, "AWSServiceRoleForSecurityLake")  # TODO: delete role in every account
    sleep(10)
    iam.get_deletion_status(iam_client,  deletion_task_id)


def delete_iam_resources(iam_client: IAMClient, role_name: str, policy_arn: str) -> None:
    role_exists = iam.check_iam_role_exists(iam_client, role_name)
    if role_exists:
        if not policy_arn or not isinstance(policy_arn, str):
            raise ValueError("Invalid policy_arn parameter")
        iam.detach_policy(iam_client, role_name, policy_arn)
        iam.delete_role(iam_client, role_name)
        if role_name == REPLICATION_ROLE_NAME:
            iam.delete_policy_versions(iam_client, policy_arn)
            iam.delete_policy(iam_client, policy_arn)

    if not role_exists:
        LOGGER.info(f"...Role {role_name} does not exist...")


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
    LOGGER.info(f"CFN EVENT {event_info}")

    params = get_validated_parameters(event)
    # params = get_validated_parameters({"RequestType": event["RequestType"]})
    # excluded_accounts: list = [params["DELEGATED_ADMIN_ACCOUNT_ID"]]  # TODO: Iev change for rollout regions
    accounts = common.get_active_organization_accounts()
    regions = common.get_enabled_regions(params["ENABLED_REGIONS"], params["CONTROL_TOWER_REGIONS_ONLY"] == "true")
\
    if params["action"] == "Add":
        LOGGER.info("calling process_add_event")
        process_add_event(params, regions, accounts)
    elif params["action"] == ["Update"]:
        LOGGER.info("calling process_add_update_event")
        process_update_event(params, regions, accounts)
    else:
        LOGGER.info("...Disable Security Lake from (process_event_cloudformation)")
        disable_security_lake(params, regions)

    return f"sra-security-lake-org-{params['DELEGATED_ADMIN_ACCOUNT_ID']}"


def orchestrator(event: Dict[str, Any], context: Any) -> None:
    """Orchestration.

    Args:
        event: event data
        context: runtime information
    """
    if event.get("RequestType"):  # todo iev if event from cloudformation
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
    event_info = {"Event": event}
    LOGGER.info(event_info)
    try:
        orchestrator(event, context)
    except Exception:
        LOGGER.exception(UNEXPECTED)
        raise ValueError(f"Unexpected error executing Lambda function. Review CloudWatch logs ({context.log_group_name}) for details.") from None

"""Custom Resource to gather data and create SSM paramters in the management account.

Version: 1.0

'common_prerequisites' solution in the repo, https://github.com/aws-samples/aws-security-reference-architecture-examples

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from __future__ import annotations

from botocore.exceptions import ClientError


class sra_sns:
    """SRA SNS class."""

    def __init__(self, logger):
        """Initialize the class.

        Args:
            logger: Logger object.
        """
        self.LOGGER = logger
        self.sleep_time = 30

    def create_sns_topic(self, sns_client, topic_name):
        """Create SNS Topic.

        Args:
            sns_client: SNS client.
            topic_name: Name of the topic.

        Returns:
            response: Response.

        Raises:
            ValueError: If error occurs.
        """
        try:
            response = sns_client.create_topic(Name=topic_name)
            return response
        except ClientError as err:
            self.LOGGER.exception(err)
            raise ValueError(f"Error: {err}") from None

    def set_topic_attributes(self, sns_client, topic_arn, policy_value):
        """Set SNS Topic Attributes.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.
            policy_value: Policy value.

        Raises:
            ValueError: If error occurs.
        """
        try:
            sns_client.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy_value)
        except ClientError as err:
            self.LOGGER.exception(err)
            raise ValueError(f"Error: {err}") from None

    def set_topic_kms_key_attribute(self, sns_client, topic_arn, kms_value):
        """Set SNS Topic KMS Key Attribute.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.
            kms_value: KMS value.

        Raises:
            ValueError: If error occurs.
        """
        try:
            sns_client.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName="KmsMasterKeyId",
                AttributeValue=kms_value,
            )
        except ClientError as err:
            self.LOGGER.exception(err)
            raise ValueError(f"Error: {err}") from None

    def subscribe_to_sns_topic(self, sns_client, topic_arn, protocol, endpoint):
        """Subscribe to SNS Topic.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.
            protocol: Protocol.
            endpoint: Endpoint.

        Returns:
            True if successful, False otherwise.
        """
        try:
            subscription = sns_client.subscribe(TopicArn=topic_arn, Protocol=protocol, Endpoint=endpoint)
            print("!!!!! SUB", subscription)
            return True
        except ClientError as err:
            self.LOGGER.info(f"Unexpected error: {err}")
            return False

    def query_for_sns_topic(self, sns_client, topic_arn):
        """Check if SNS Topic exists.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.

        Returns:
            True if topic exists, False otherwise.
        """
        try:
            sns_client.get_topic_attributes(TopicArn=topic_arn)
            self.LOGGER.info(f"Topic {topic_arn} already exists")
            # subscription_arns = self.get_subscription_arns(sns_client, topic_arn)
            # print("!!!!! SUBS ARNS", subscription_arns)
            return True
        except sns_client.exceptions.NotFoundException:
            return False

    def get_subscription_arns(self, sns_client, topic_arn):
        """Get subscription ARN from topic name.

        Args:
            sns_client: SNS client.
            topic_arn: Topic name.

        Returns:
            subscription_arn: Subscription ARN.
        """
        self.LOGGER.info(f"Checking subscriptions for {topic_arn} topic...")
        subscription_arns = []
        try:
            paginator = sns_client.get_paginator("list_subscriptions_by_topic")

            for page in paginator.paginate(TopicArn=topic_arn):
                for subscription in page["Subscriptions"]:
                    print("!!!!! SUBS subscription", subscription)
                    subscription_arns.append(subscription["SubscriptionArn"])
            number = len(subscription_arns)
            self.LOGGER.info(f"Topic {topic_arn} has {number} subscriptions...")
            return subscription_arns
        except ClientError as err:
            self.LOGGER.info(f"Unexpected error: {err}")
            return subscription_arns

    def create_configuration_topic(self, sns_client, topic_arn, topic_name, kms_value, lambda_arn, policy_value):
        """Check if SNS Topic exists.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.
            topic_name: Topic name.
            kms_value: KMS value.
            lambda_arn: Lambda ARN.
            policy_value: Access policy value.
        """
        self.LOGGER.info(f"Topic not found, creating {topic_name} topic...")
        self.create_sns_topic(sns_client, topic_name)
        self.set_topic_attributes(sns_client, topic_arn, policy_value)
        self.set_topic_kms_key_attribute(sns_client, topic_arn, kms_value)
        self.subscribe_to_sns_topic(sns_client, topic_arn, "lambda", lambda_arn)

    def create_config_delivery_topic(self, sns_client, topic_arn, topic_name, kms_value, policy_value):
        """Check if SNS Topic exists and create the topic if it does not exist.

        Args:
            sns_client: SNS client.
            topic_arn: SNS topic arn.
            topic_name: SNS topic name.
            kms_value: KMS key value.
            policy_value: Access policy value.
        """
        self.LOGGER.info(f"Topic not found, creating {topic_name} topic...")
        self.create_sns_topic(sns_client, topic_name)
        self.set_topic_attributes(sns_client, topic_arn, policy_value)
        self.set_topic_kms_key_attribute(sns_client, topic_arn, kms_value)

    def unsubscribe_from_sns_topic(self, sns_client, topic_arn):
        """Unsubscribe from SNS Topic.

        Args:
            sns_client: SNS client.
            topic_arn: Subscription ARN.

        Returns:
            True if successful, False otherwise.
        """
        try:
            sns_client.unsubscribe(SubscriptionArn=topic_arn)
            return True
        except ClientError as err:
            self.LOGGER.info(f"Unexpected error: {err}")
            return False

    def delete_sns_topic(self, sns_client, topic_arn):
        """Delete SNS Topic.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.

        Returns:
            response: Response.

        Raises:
            ValueError: If error occurs.
        """
        try:
            sns_client.delete_topic(TopicArn=topic_arn)
            return True
        except ClientError as err:
            self.LOGGER.exception(err)
            raise ValueError(f"Error: {err}") from None

    def delete_sns_resources(self, sns_client, topic_arn):
        """Delete SNS Resources.

        Args:
            sns_client: SNS client.
            topic_arn: Topic ARN.
        """
        subscription_arns = self.get_subscription_arns(sns_client, topic_arn)
        for arn in subscription_arns:
            self.LOGGER.info(f"Unsubscribing from subscription arn {arn}...")
            self.unsubscribe_from_sns_topic(sns_client, arn)
        self.LOGGER.info(f"Deleting SNS topic {topic_arn}...")
        self.delete_sns_topic(sns_client, topic_arn)

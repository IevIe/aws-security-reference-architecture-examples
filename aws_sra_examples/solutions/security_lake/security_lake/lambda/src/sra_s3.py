"""Custom Resource to check to see if a resource exists.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import boto3
from botocore.client import ClientError
import json


class sra_s3:
    def __init__(self, logger):
        self.LOGGER = logger

    def query_for_s3_bucket(self, s3_client , bucket_name):
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            self.LOGGER.info(f"Bucket {bucket_name} already exists...")
            return True
        except ClientError:
            return False

    def create_s3_bucket(self, s3_client, bucket_name, bucket_policy, kms_key_id, region):
        if region != "us-east-1":
            created_bucket = s3_client.create_bucket(
                ACL="private",
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": region
                },
                ObjectOwnership="BucketOwnerPreferred",
            )
        else:
            created_bucket = s3_client.create_bucket(
                ACL="private",
                Bucket=bucket_name,
                ObjectOwnership="BucketOwnerPreferred",
            )
        self.LOGGER.info(f"Bucket created: {created_bucket}")
        # self.apply_bucket_policy(bucket_policy, bucket_name)
        # self.apply_bucket_encryption_policy(kms_key_id)

    def apply_bucket_policy(self, bucket_policy, bucket_name):
        self.LOGGER.info(bucket_policy)
        for sid in bucket_policy["Statement"]:
            if isinstance(sid["Resource"], list):
                sid["Resource"] = list(
                    map(
                        lambda x: x.replace("BUCKET_NAME", bucket_name),
                        sid["Resource"],
                    )
                )  # noqa C417
            else:
                sid["Resource"] = sid["Resource"].replace(
                    "BUCKET_NAME", bucket_name
                )
        self.LOGGER.info(bucket_policy)
        bucket_policy_response = self.s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy),
        )
        self.LOGGER.info(bucket_policy_response)

    def apply_bucket_encryption_policy(self, kms_key_id):
        response = self.s3_client.put_bucket_encryption(
            Bucket=self.CONFIG_BUCKET,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key_id,  #  TODO: add key here
                        },
                        "BucketKeyEnabled": True,
                    },
                ]
            },
        )
        self.LOGGER.info(response)

    def s3_resource_check(self, bucket_name):
        self.LOGGER.info(f"Checking for {bucket_name} s3 bucket...")
        if self.query_for_s3_bucket() is False:
            self.LOGGER.info(
                f"Bucket not found, creating {bucket_name} s3 bucket..."
            )
            self.create_s3_bucket()

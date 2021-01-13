import boto3
import logging
from src import config
from botocore.exceptions import ClientError, NoCredentialsError

CONFIG = config.configuration()

def _get_api_keys() -> tuple:

    access_key = CONFIG.aws_access_key
    secret_key = CONFIG.aws_secret_key
    return (secret_key, access_key)


def aws_api_keys_exist() -> bool:
    """
    Make sure that the API keys have been entered into secrets.conf
    """
    sk, ak = _get_api_keys()
    if (sk != "None") and (ak != "None"):
        return True
    return False


def check_bucket_exists(bucket_name: str) -> bool:
    """
    Check if am AWS bucket exists
    """
    try:
        region="us-east-1"
        secret_key, access_key = _get_api_keys()
        s3 = boto3.client('s3', region_name=region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        response = s3.list_buckets()
        return bucket_name in response["Buckets"]
    except ClientError as e:
        logging.error(e)
        exit(1)


def create_bucket(bucket_name: str) -> bool:
    """
    Create an S3 bucket in a defined region (us-east-1) that
    will hold our saved aircraft information. 
    """
    try:
        region="us-east-1"
        secret_key, access_key = _get_api_keys()
        s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        s3_client.create_bucket(Bucket=bucket_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def upload_to_s3(bucket_name: str, local_file: str, s3_file_name: str) -> bool:
    """
    Uploads the gzip file to S3
    """
    try:
        region="us-east-1"
        secret_key, access_key = _get_api_keys()
        s3_client = boto3.client('s3', region_name=region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        response = s3_client.upload_file(local_file, bucket_name, s3_file_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True
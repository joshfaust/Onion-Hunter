import hashlib
import re
import os
import sys
import requests
import linecache
import gzip
import time
import json
import datetime
import logging
import base64

from src import aws as aws
from src import config
from src import onion_analysis as onion
from src import db_manager as db

from datetime import datetime as dt
from datetime import date, timedelta

#GLOBAL
CONFIG = config.configuration()
PREVIOUS_DB_HASH = ""
START_TIME = dt.now()
DB_NAME = CONFIG.db_name


def check_program_runtime():
    # Upload the db every 10 min.
    global START_TIME
    runtime = get_script_runtime_minutes(START_TIME)

    if runtime >= 10:
        START_TIME = dt.now()
        logging.info(f"[{dt.now()}]:10 minute db check")
        if CONFIG.aws_access_key != "":
            check_db_diff(True)


def check_db_diff(using_aws: bool):
    """
    Check if the DB has changed and if so, upload to 
    """
    global PREVIOUS_DB_HASH, DB_NAME
    current_hash = get_file_md5_hash(DB_NAME)

    if using_aws and has_database_changed(PREVIOUS_DB_HASH, current_hash):

        if (gzip_file(DB_NAME, f"{DB_NAME}.gz")):

            write_to_s3(f"{DB_NAME}.gz", "onion-hunter", "databases")
            os.remove(f"{DB_NAME}.gz")
            logging.info(f"DB Change Detected, uploaded to S3:prev_hash={PREVIOUS_DB_HASH}:cur_hash={current_hash}")
            PREVIOUS_DB_HASH = current_hash
    else:
        logging.info("No Change in DB. Continuing")


def get_script_runtime_minutes(start_time: datetime) -> float:
    """
    Calculates the time difference from when the program
    started to the current time
    """
    time_delta = dt.now() - start_time
    time_delta_minutes = divmod(time_delta.total_seconds(), 60)[0]
    return time_delta_minutes


def gzip_file(filepath: str, output_filename: str) -> bool:
    """ 
    Gzip compress any file
    """
    try:
        with open(filepath, "rb") as f_in:
            with gzip.open(output_filename, "wb") as f_out:
                f_out.writelines(f_in)
        return True
    except Exception as e:
        logging.error(f"gzip ERROR:{e}")
        return False

def write_json_to_gzip_stream(json_data: dict, output_filename: str) -> bool:
    """
    Takes in a Dictionary and writes it to a gzipped json file
    """
    try:
        json_str = json.dumps(str(json_data)) + "\n"
        json_bytes = json_str.encode("utf-8")
        with gzip.open(output_filename, "w") as out:
            out.write(json_bytes)
    except json.JSONDecodeError as e:
        logging.write(f"write_json_to_gzip_stream() JSON Decode Error:{e}")
    except Exception as e:
        logging.write(f"write_json_to_gzip_stream() ERROR:{e}")


def write_to_s3(filename: str, bucket_name: str, s3_folder_name: str) -> None:
    """
    Write a file to AWS S3
    """
    if not aws.check_bucket_exists(bucket_name):
        if not aws.create_bucket(bucket_name):
            logging.error(f"Unable to Create bucket")
            exit(1)
    if s3_folder_name is not None:
        if not aws.upload_to_s3(bucket_name, filename, f"{s3_folder_name}/{filename}"):
            logging.error(f"Unable to upload gzipped file to S3")
    else:
        if not aws.upload_to_s3(bucket_name, filename, filename):
            logging.error(f"Unable to upload gzipped file to S3")


def chill() -> None:
    """
    pause the program for a little bit to rest the API loads
    """
    print(f"\n[i] {datetime.datetime.now()}: Sleeping for 20 Minutes.")
    time.sleep(1200)
    print(f"[i] {datetime.datetime.now()}: Restarting Search.")


def has_database_changed(previous_hash: str, current_hash: str) -> bool:
    """
    comapre DB hashes and determine if we need to upload to S3
    """
    if previous_hash != current_hash:
        return True
    return False


def get_sha256(data: str) -> str:
    """
    Get the SHA256 value of a string
    """
    try:
        n_hash = hashlib.sha256(str(data).strip().encode()).hexdigest()
        return n_hash
    except Exception as e:
        logging.error(f"Utilities_SHA256_ERROR:{e}")


def get_file_md5_hash(filename: str) -> str:
    """
    Get an MD5 hash of a file
    """
    if not os.path.exists(filename):
        logging.error(f"get_file_md5_hash() File Does Not Exist: {filename}")
    else:
        with open(filename, "rb") as f:
            file_hash = hashlib.md5()
            chunk = f.read(8192)
            while chunk:
                file_hash.update(chunk)
                chunk = f.read(8192)
        return file_hash.hexdigest()


def get_string_md5_hash(data: str) -> str:
    """
    Get the MD5 hash of a string
    """
    hash = hashlib.md5(data.strip().encode()).hexdigest()
    return hash


def create_b64_from_string(data: str) -> bytes:
    data = str(data).strip().encode("utf-8")
    b64 = base64.encodebytes(data)
    return b64


def deep_paste_enum(onion_source: str) -> list:
    """
    DeepPaste uses MD5SUM's for each post, this function
    enumerates all of the MD5 hashes found that will be used
    to compile known/valid deeppaste domains. 
    """
    md5_list = []
    try:
        md5_list = re.findall(r"md5=[0-9a-fA-F]{32}", onion_source)
        return md5_list
    except Exception as e:
        logging.error(f"MD5SUM_ERROR:{e}")
        return md5_list


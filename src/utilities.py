import hashlib
import re
import os
import sys
import requests
import linecache
import gzip
import time
import datetime
import logging

from src import aws as aws
from src import config
from src import onion_analysis as onion
from src import db_manager as db

from datetime import datetime as dt
from datetime import date, timedelta

#GLOBAL
CONFIG = config.configuration()
PREVIOUS_DB_HASH = ""
DB_NAME = CONFIG.db_name


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
    time_delta_hours = divmod(time_delta.total_seconds(), 60)[0]
    return time_delta_hours


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


def is_fresh_onion_site(source: str) -> bool:
    """
    Checks to see if a domain is a Fresh Onion
    """
    try:
        if not db.is_duplicate_fresh_onion(domain):
            keyword_index = 0
            keywords = [
                "fresh onions",
                "fresh onion",
                "freshonion",
                "freshonions",
                "new",
                "fresh",
                "onions",
                "onion",
            ]

            onion_addresses = onion.find_all_onion_base_addresses(source)
            count = len(onion_addresses)

            # Checks if any known keywords are in source code:
            for word in keywords:
                if word.lower() in source.lower():
                    keyword_index += 1

            # Determine if this site is a Fresh Onion site:
            if count >= 50 and keyword_index > 2:
                return True  # This is probably a Fresh Onion site
            return False  # Naa, this is just a regular onion address.
        else:
            return False # The URI already exists, skip it. 

    except Exception as e:
        exc_type, exc_obj, tb = sys.exc_info()
        tmp_file = tb.tb_frame
        lineno = tb.tb_lineno
        filename = tmp_file.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, tmp_file.f_globals)
        logging.error(f"is_fresh_onion_site() ERROR:{e}-linenum:{lineno}-Filename:{filename}-Line:{line}-ExecObj:{exc_obj}")

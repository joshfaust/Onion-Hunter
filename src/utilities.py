import hashlib
import re
import os
import requests
import time
import datetime
import logging

from src import aws as aws
from src import onion_analysis as onion


def write_to_s3(filename: str, bucket_name: str) -> None:
    """
    Write a file to AWS S3
    """
    if not aws.check_bucket_exists(bucket_name):
        if not aws.create_bucket(bucket_name):
            logging.error(f"Unable to Create bucket")
            exit(1)
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

# Gets the SHA256 hash for a string
## Returns: String
def getSHA256(data):
    try:
        n_hash = hashlib.sha256(str(data).strip().encode()).hexdigest()
        return n_hash
    except Exception as e:
        logging.error(f"Utilities_SHA256_ERROR:{e}")
        print(f"[!] ERROR: {e}")


def get_file_md5_hash(filename: str):
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


# Get the MD5's in the deep psate site.
def deep_paste_enum(onion_source: str):
    md5_list = []
    try:
        md5_list = re.findall(r"md5=[0-9a-fA-F]{32}", onion_source)
        return md5_list
    except Exception as e:
        logging.error(f"MD5SUM_ERROR:{e}")
        return md5_list


# Checks to see if a domain is a Fresh Onion
def is_fresh_onion_site(source: str) -> bool:
    try:
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
        count = len(onion.find_all_onion_addresses(source))

        # Checks if any known keywords are in source code:
        for word in keywords:
            if word.lower() in source.lower():
                keyword_index += 1

        # Determine if this site is a Fresh Onion site:
        if count >= 50 and keyword_index > 2:
            return True  # This is probably a Fresh Onion site
        return False  # Naa, this is just a regular onion address.

    except Exception as e:
        logging.error(f"is_fresh_onion_site() ERROR:{e}")

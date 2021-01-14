import argparse
import time
import os
import re
import requests
import logging

from tqdm import tqdm
from datetime import date
from src.tor_web_requests import is_tor_established, check_tor_connection
from src import config

import src.utilities as util
import src.reddit as reddit
import src.onion_analysis as onion

logname = f"tor_search_{date.today()}.log"
logging.basicConfig(filename=logname, level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S")

# ==================================#
# MAIN                              #
# ==================================#
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    me = parser.add_mutually_exclusive_group()
    me.add_argument(
        "-s", 
        "--scan", 
        action="store_true", 
        dest="scan", 
        help="Scan All The Things"
    )
    me.add_argument(
        "-f", 
        "--file", 
        metavar="",
        dest="file_data", 
        help="Import Onions from txt file"
    )
    me.add_argument(
        "-p",
        "--purge",
        action="store_true",
        dest="purge",
        help="Purge the whole database",
    )
    parser.add_argument(
        "--s3",
        action="store_true",
        required=False,
        dest="aws_api",
        default=False,
        help="Upload compressed flight data to S3",
    )

    args = parser.parse_args()

    if args.scan or args.file_data:
        if not is_tor_established():
            print(f"[!] Not Connected to a TOR Proxy, exiting")
            exit(1)

    if args.scan:

        while True:
            check_tor_connection()
            onion.deep_paste_search()
            if args.aws_api:
                util.write_to_s3("onion.db", "onion-hunter")
            reddit.redditScraper()
            if args.aws_api:
                util.write_to_s3("onion.db", "onion-hunter")
            onion.scrape_known_fresh_onions()
            if args.aws_api:
                util.write_to_s3("onion.db", "onion-hunter")
            onion.analyze_onions_from_file("docs/additional_onions.txt")
            os.remove("docs/additional_onions.txt")  # Delete the file after
            if args.aws_api:
                util.write_to_s3("onion.db", "onion-hunter")
            util.chill()

    elif args.file_data is not None:

        # check if file exists:
        if os.path.isfile(args.file_data):
            onion.analyze_onions_from_file(args.file_data)
            onion.analyze_onions_from_file("docs/additional_onions.txt")
            os.remove("docs/additional_onions.txt")
            if args.aws_api:
                util.write_to_s3("onion.db", "onion-hunter")
        else:
            print("[!] File Does Not Exist")
            exit(0)

    elif args.purge:
        DB = db_manager.db_manager()
        last_chance_check = input(
            "[!] This will DELETE All Data in DB - Are You Sure? (Y|N): "
        )
        if last_chance_check.lower() == "y" or last_chance_check.lower() == "yes":
            DB.deleteAll()
        else:
            print("[i] Exiting.")
            exit(0)


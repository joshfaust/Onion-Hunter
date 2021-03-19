import argparse
import time
import os
import re
import requests
import logging

from tqdm import tqdm
from datetime import date
from src import aws as aws
from src.tor_web_requests import is_tor_established, check_tor_connection
from src import db_manager as db
from src import utilities as util

import src.reddit as reddit
import src.onion_analysis as onion
import src.onion_utilities as o_utils

logname = f"tor_search_{date.today()}.log"
logging.basicConfig(
    filename=logname, 
    format='%(asctime)s-%(levelname)s-%(message)s',
    level=logging.INFO, 
    datefmt="%Y-%m-%d %H:%M:%S"
    )
logging.info("Script Started")


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
        "-u",
        "--uri",
        dest="uri",
        metavar='',
        help="Analyze an Individual Onion Domain"
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
        help="Purge the whole database"
    )
    me.add_argument(
        "-n",
        "--new",
        action="store_true",
        default=False,
        dest="new_db",
        help="Create a fresh/new Database"
    )
    me.add_argument(
        "-c",
        "--clean",
        action="store_true",
        default=False,
        dest="dedup",
        help="Clean the DB by removing duplicates and unworthy domains"
    )
    parser.add_argument(
        "--s3",
        action="store_true",
        required=False,
        dest="aws_api",
        default=False,
        help="Upload database to S3"
    )
    args = parser.parse_args()

    if args.new_db:
        db.create_new_database()
        exit(0)

    if args.dedup:
        db.dedup_fresh_onion_sources()
        db.dedup_seen_onions()
        db.delete_news_domains_from_onions()
        db.vaccum_database()
        exit(0)

    #if args.scan or args.file_data:
     #   if not is_tor_established():
      #      print(f"[!] Not Connected to a TOR Proxy, exiting")
       #     exit(1)

    if args.aws_api:
        if not aws.aws_api_keys_exist():
            print("[!] If you're going to use --s3, add your S3 credentials.")
            exit(1)

    if args.scan:
        previous_db_hash = ""

        while True:
            check_tor_connection()
            onion.deep_paste_search()
            util.check_db_diff(args.aws_api)
            reddit.redditScraper()
            util.check_db_diff(args.aws_api)
            onion.scrape_known_fresh_onions()
            util.check_db_diff(args.aws_api)
            onion.analyze_unanalyzed_onions()
            util.check_db_diff(args.aws_api)
            util.chill()

    elif args.uri is not None:
        print(f"[i] Analyzing {args.uri}")
        if onion.analyze_onion_address("manual", args.uri):
            print("[i] URI Analysis added to ONIONS table.")
        else:
            print(f"[i] Duplicate Entry")
        exit(0)

    elif args.file_data is not None:

        # check if file exists:
        if os.path.isfile(args.file_data):
            onion.analyze_onions_from_file(args.file_data)
            onion.analyze_onions_from_file("docs/additional_onions.txt")
            os.remove("docs/additional_onions.txt")
            util.check_db_diff(args.aws_api)
        else:
            print(f"[!] File Does Not Exist: {args.file_data}")
            exit(1)

    elif args.purge:
        db = db_manager.db_manager()
        last_chance_check = input(
            "[!] This will DELETE All Data in DB - Are You Sure? (Y|N): "
        )
        if last_chance_check.lower() == "y" or last_chance_check.lower() == "yes":
            db.delete_all_db_data()
        else:
            print("[i] Exiting.")
            exit(0)


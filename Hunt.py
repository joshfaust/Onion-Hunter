import argparse
import time
import os
import re
import requests
import logging

from tqdm import tqdm
from src import config
from datetime import date
from src.tor_web_requests import is_tor_established

import src.utilities as util
import src.reddit as reddit
import src.onion_analysis as onion

logname = f"tor_search_{date.today()}.log"
logging.basicConfig(filename=logname, level=logging.INFO)

# Class Objects
CONFIG = config.configuration()

# ==================================#
# Search TOR Deep Paste             #
# ==================================#
def deepPaseSearch():
    md5_uri_list = []
    deep_paste_keys = ['http://depastedihrn3jtw.onion/last.php',
                       'http://depastedihrn3jtw.onion/top.php']

    # Start to enumerate by getting the source then MD5's
    try:
        for domain in deep_paste_keys:
            origin_address = domain.strip()
            print(f"\n\t[+] Searching: {origin_address}")

            data = getOnionSource(origin_address)
            onions_source = data["source"]
            md5_list = util.deepPasteEnum(onions_source)

            #interate through list and append MD5's to full URI
            for md5 in md5_list:
                uri = f'http://depastedihrn3jtw.onion/show.php?{str(md5).strip()}'
                md5_uri_list.append(uri)

            # Append key URI to the list as well
            md5_uri_list.append(origin_address)
            analyzeOnionList(origin_address, md5_uri_list, len(md5_uri_list))
            md5_uri_list.clear()
            
    except Exception as e:
        print(f"[!] Error: {e}")



# ==================================#
# MAIN                              #
# ==================================#
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    me = parser.add_mutually_exclusive_group()
    me.add_argument("-s", "--scan", action="store_true", dest="scan", help="Scan All The Things")
    me.add_argument("-f", "--file", metavar='', dest="file_data", help="Import Onions from txt file")
    me.add_argument("-p", "--purge", action="store_true", dest="purge", help="Purge the whole database")
    me.add_argument("-c", "--clean", action="store_true", dest="clean", help="Cleanup the DB")
    args = parser.parse_args()

    #getOnionSource("protonirockerxow.onion")
    #exit(0)

    if (args.scan):

        if (not is_tor_established()):
            print(f"[!] Not Connected to a TOR Proxy, exiting")
            exit(1)
        else:
            while True:
                reddit.redditScraper()
                #deepPaseSearch()                                # Search DeepPaste for onions addresses
                onion.scrape_known_fresh_onions()
                onion.analyze_onions_from_file("docs/additional_onions.txt")
                os.remove("docs/additional_onions.txt")         # Delete the file after
                util.chill()

    elif (args.file_data is not None):
        if (not is_tor_established()):
            print(f"[!] Not Connected to a TOR Proxy, exiting")
            exit(1)
        else:
            # check if file exists:
            if (os.path.isfile(args.file_data)):
                bn = os.path.basename(args.file_data)
                print(f"[i] Analyzing Onions Addresses in {bn}")
                onion.analyze_onions_from_file(args.file_data)
                onion.analyze_onions_from_file("docs/additional_onions.txt")
                os.remove("docs/additional_onions.txt")
            else:
                print("[!] File Does Not Exist")
                exit(0)

    elif (args.purge):
        DB = db_manager.db_manager()
        last_chance_check = input("[!] This will DELETE All Data in DB - Are You Sure? (Y|N): ")
        if (last_chance_check.lower() == "y" or last_chance_check.lower() == "yes"):
            DB.deleteAll()
        else:
            print("[i] Exiting.")
            exit(0)

    elif (args.clean):
        DB = db_manager.db_manager()
        DB.cleanupFreshOnions()
        DB.cleanupOnions()

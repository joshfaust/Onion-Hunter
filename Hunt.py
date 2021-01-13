import argparse
import datetime
import time
import os
import re
import certifi
import requests
import logging

from tqdm import tqdm
from src import config
from src import db_manager
from src import utilities
from datetime import date

logname = f"tor_search_{date.today()}.log"
logging.basicConfig(filename=logname, level=logging.info)

# Class Objects
DB = db_manager.db_manager()
UTIL = utilities.util()
CONFIG = config.configuration()


# ==================================#
# Search the Fresh Onion domains    #
# ==================================#
def freshOnionsScraper():
    print(f"[i] Starting Fresh Onion Searches")
    domains = DB.getFreshOnionDomains()

    # Iterate through the known Fresh Onions domains/lists
    for origin_address in domains:
        origin_address = str(origin_address).replace("('", "").replace("',)", "").strip()
        print(f"\n\t[+] Searching: {origin_address}")
        try:

            data = getOnionSource(origin_address)
            fresh_onions_source = data["source"]
            new_domains = UTIL.getOnions(fresh_onions_source)

            # If there are onion addresses found, continue:
            if (len(new_domains) > 0):
                analyzeOnionList(origin_address, new_domains, len(new_domains))
                new_domains.clear()

        except Exception as e:
            print(f"[!] Fresh Scraper ERROR: {e}")
            continue

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
            md5_list = UTIL.deepPasteEnum(onions_source)

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



# ===================================#
# Will analyze .Onions from txt file #
# ===================================#
def importFromFile(file_path):
    with open(file_path, "r") as f:
        for domain in f:
            try:
                origin_address = domain.strip()

                print(f"\n\t[+] Searching: {origin_address}")
                data = getOnionSource(origin_address)
                onions_source = data["source"]
                new_domains = UTIL.getOnions(onions_source)

                if (len(new_domains) > 0):
                    new_domains.append(origin_address)  # Append the source address to get analyzed as well.
                    analyzeOnionList(origin_address, new_domains, len(new_domains))
                    new_domains.clear()

            except Exception as e:
                print(f"[!] Import From File ERROR: {e}")
                continue
    f.close()


# ==================================#
# Checks Tor Connection Status      #
# ==================================#
def checkConnection():
    try:
        con_attempts = 0
        # print("[!] We have had 20 Timeouts. Checking to see if we're still connected to TOR")
        if (UTIL.isTorEstablished() is False):
            print("[!] NOT Connected to TOR. Please Re-connect.")
            print("[i] Sleeping for 30 seconds then checking again")
            time.sleep(30)

            while (UTIL.isTorEstablished() is False):
                print("[i] Sleeping for 30 seconds then checking again")
                time.sleep(30)
                con_attempts += 1

                if (con_attempts >= 15):
                    print("[!] 15 Attempts to Re-Connected Failed. Exiting.")
                    exit(0)

    except Exception as e:
        print(f"[!] Check Connection ERROR: {e}")
        exit(1)



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

        if (not UTIL.isTorEstablished()):
            print(f"[!] Not Connected to a TOR Proxy, exiting")
            exit(1)
        else:
            while True:
                redditScraper()                                # Search Reddit for onion addresses
                deepPaseSearch()                                # Search DeepPaste for onions addresses
                freshOnionsScraper()                            # Search known Fresh Onions Sources
                importFromFile("docs/additional_onions.txt")    # Search any additional Onions found
                os.remove("docs/additional_onions.txt")         # Delete the file after
                print(f"[i] {datetime.datetime.now()}: Sleeping for 20 Minutes.")
                time.sleep(1200)
                print(f"[i] {datetime.datetime.now()}: Restarting Search.")

    elif (args.file_data is not None):
        if (not UTIL.isTorEstablished()):
            print(f"[!] Not Connected to a TOR Proxy, exiting")
            exit(1)
        else:
            # check if file exists:
            path = args.file_data
            if (os.path.isfile(path)):
                bn = os.path.basename(path)
                print(f"[i] Analyzing Onions Addresses in {bn}")
                importFromFile(path)
                importFromFile("docs/additional_onions.txt")
                os.remove("docs/additional_onions.txt")
            else:
                print("[!] File Does Not Exist")
                exit(0)

    elif (args.purge):
        last_chance_check = input("[!] This will DELETE All Data in DB - Are You Sure? (Y|N): ")
        if (last_chance_check.lower() == "y" or last_chance_check.lower() == "yes"):
            DB.deleteAll()
        else:
            print("[i] Exiting.")
            exit(0)

    elif (args.clean):
        DB.cleanupFreshOnions()
        DB.cleanupOnions()

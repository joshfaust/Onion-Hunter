import argparse
import datetime
import time
import os
import re
import certifi
import praw
import urllib3

from bs4 import BeautifulSoup
from tqdm import tqdm
from src import config
from src import db_manager
from src import utilities

# ---------------------------------------|
# Author: @jfaust0                       |
#                                        |
# Requirements:                          |
# You must be connected to a TOR gateway |
# There are many ways to traffic your    |
# HTTP requests via TOR subject to your  |
# OS. Choose whichever you like.         |
#                                        |
# Description: Maps Tor domains by       |
# searching for keywords in each of the  |
# domains index source code.             |
# ---------------------------------------|

# Class Objects
DB = db_manager.db_manager()
UTIL = utilities.util()
CONFIG = config.configuration()

# ===================================#
# Reddit Login Function              #
# ===================================#
def reddit_login():
    try:
        r = praw.Reddit(username=CONFIG.r_username,
                        password=CONFIG.r_password,
                        client_id=CONFIG.r_client_id,
                        client_secret=CONFIG.r_client_secret,
                        user_agent=CONFIG.r_user_agent)

        username = r.user.me()

        if (username is None):
            raise Exception("Failed to Login. Please Check Configuration Settings.")

        print(f"[i] Logged In As: {r.user.me()}")
        return r
    except Exception as e:
        print(f"[!] Reddit Connection Error: {e}")
        exit(1)


# ===================================#
# Scans pre-defined sub-reddits      #
# ===================================#
def redditScraper():
    r = reddit_login()

    for sub in CONFIG.sub_reddits:

        try:
            subreddit = r.subreddit(sub)
            print(f"\n\t[+] Analyzing {subreddit.display_name} Subreddit.")

            for submission in subreddit.hot(limit=75):
                sub_content = submission.selftext
                sub_link = submission.url
                sub_links = UTIL.getOnions(sub_content)
                domain_source = str(sub_link).strip()

                # Check the top 15 comments in the Subreddit as well.
                for comment in submission.comments.list()[:10]:
                    addresses = UTIL.getOnions(comment.body)
                    if (len(addresses) > 0):
                        for i, item in enumerate(addresses) :
                            sub_links.append(addresses[i])

                # If there are onions found, continue
                if (len(sub_links) > 0):
                    analyzeOnionList(domain_source, sub_links, len(sub_links))

        except Exception as e:
            print(f"[!] Reddit Scraper ERROR: {e}")
            continue


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
# Analyze a list on Onion Addresses #
# ==================================#
def analyzeOnionList(origin_address, list_object, list_len):
    try:
        i = 0                   # Index counter for each matched word
        timeout_index = 0       # Index counter for timout domains
        matches = []            # Array to keep matched words.
        good_domain = True      # Used to enumerate good domains
        additional_onions = []  # Used to save subsequent onions that were found during the source analysis
        bad_domains = ["facebook", "facebo", "nytimes", "nytime", "twitter.com"]

        pbar = tqdm(total=list_len, desc=f"Analysing {list_len} new Onions")
        for new_address in list_object:

            # Dictate if domain is plain-ol' stupid
            for bad_domain in bad_domains:
                if (bad_domain in new_address):
                    good_domain = False

            domain_hash = UTIL.getSHA256(new_address)

            # Verify it's not a duplicate
            if (DB.checkOnionsDuplicate(domain_hash) is False and good_domain is True):
                data = getOnionSource(new_address)
                new_source = data["source"]
                title = data["title"]

                # If we didn't get a timeout, continue to analyze
                if (new_source != "timeout"):

                    # If the onion address meets the "Fresh Onions" criteria, add to table
                    fresh = UTIL.isFreshOnionRepo(new_source)
                    if (fresh):
                        DB.freshInsert(str(new_address), str(domain_hash))

                    # Search for keywords in source.
                    for word in CONFIG.keywords:
                        if (word in new_source):
                            i += 1
                            matches.append(word)

                    DB.onionsInsert(origin_address, new_address, title, domain_hash,
                                    str(matches), str(i), new_source)

                    # add any new onions found
                    tmp = UTIL.getOnions(new_source)
                    additional_onions = additional_onions + tmp

                    pbar.update(1)

                else:
                    timeout_index += 1
                    pbar.update(1)

            else:
                pbar.update(1)
                good_domain = True  # Reset the good_domain status

            i = 0               # Reset Index Counter for each link
            matches.clear()     # Reset keywords for each link.

            # Check timout counter:
            if (timeout_index >= 20):
                checkConnection()
                timeout_index = 0
        pbar.close()

        # Save the additional Onions to a file for later analysis
        with open("docs/additional_onions.txt", "a") as f:
            for address in additional_onions:
                f.write(address + "\n")
        f.close()
        additional_onions.clear()   # Clear the list

    except Exception as e:
        print(f"[!] Analyze Error: {e}")
        exit(1)


# ==================================#
# Pulls .Onion address source code  #
# ==================================#
def getOnionSource(url):
    timeout = {"source": "timeout", "title": "timeout"}
    try:
        user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0'}
        to = urllib3.Timeout(connect=7, read=2)
        http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where(), headers=user_agent,
                                   retries=2, timeout=to)
        html = http.request("GET", url)
        soup = BeautifulSoup(html.data, "html.parser")

        try:
            title = soup.find('title').text
        except Exception as e:
            title = None

        final = {"source": str(soup).lower(), "title": title}
        return final
    except urllib3.exceptions.ConnectTimeoutError as t:
        return timeout
    except Exception as e:
        return timeout


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

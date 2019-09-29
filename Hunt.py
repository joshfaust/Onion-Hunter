import argparse
import datetime
import time
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
        if (username == None):
            raise Exception("Failed to Login. Please Check Configuration Settings.")
        else:
            print(f"[i] Logged In As: {r.user.me()}")
            return r
    except Exception as e:
        print(f"[!] Reddit Connection Error: {e}")
        exit(1)


# ===================================#
# Scans pre-defined sub-reddits      #
# ===================================#
def redditScraper():
    i = 0  # Index counter for each matched word
    matches = []  # Array to keep matched words.
    r = reddit_login()

    for sub in CONFIG.sub_reddits:

        try:
            subreddit = r.subreddit(sub)
            print(f"\n\t[+] Analyzing {subreddit.display_name} Subreddit.")

            for submission in subreddit.hot(limit=75):
                sub_content = submission.selftext
                sub_link = submission.url
                sub_links = UTIL.getOnions(sub_content)

                # Check the top 15 comments in the Subreddit as well.
                for comment in submission.comments.list()[:10]:
                    addresses = UTIL.getOnions(comment.body)
                    if (len(addresses) > 0):
                        for i in range(0, len(addresses)):
                            sub_links.append(addresses[i])

                # If there are onions found, continue
                if (len(sub_links) > 0):
                    # print(f"\t[+] Found {len(sub_links)} Onion Addresses.")

                    # Iterate through each link found.
                    pbar = tqdm(total=len(sub_links), desc=f"Analysing {len(sub_links)} new Onions")
                    for link in sub_links:
                        domain_hash = UTIL.getSHA256(link)

                        # If this is a new domain we do not have categorized, continue
                        if (DB.checkOnionsDuplicate(domain_hash) == False):
                            domain_source = str(sub_link).strip()
                            clean_link = str(link).strip()
                            source_code = getOnionSource(clean_link)

                            if (source_code != "timeout"):

                                # Check if domain is a fresh onion source:
                                fresh = UTIL.isFreshOnionRepo(source_code)
                                if (fresh == True):
                                    DB.freshInsert(str(clean_link), str(domain_hash))

                                # Determine keywords
                                for word in CONFIG.keywords:
                                    if (word in source_code):
                                        i += 1
                                        matches.append(word)

                                DB.onionsInsert(domain_source, clean_link, domain_hash,
                                                str(matches), str(i), source_code)
                                pbar.update(1)
                            else:

                                DB.onionsInsert(domain_source, clean_link, domain_hash,
                                                "timeout", "timeout", "timeout")
                                pbar.update(1)

                        else:
                            pbar.update(1)

                        i = 0  # Reset Index Counter for each link
                        matches.clear()  # Reset keywords for each link.

                    pbar.close()

        except Exception as e:
            print(f"[!] ERROR: {e}")
            continue


# ===================================#
# Search the Fresh Onion domains    #
# ===================================#
def freshOnionsScraper():
    print(f"[i] Starting Fresh Onion Searches")

    i = 0  # Index counter for each matched word
    matches = []  # Array to keep matched words.
    domains = DB.getFreshOnionDomains()

    # Iterate through the known Fresh Onions domains/lists
    for origin_address in domains:
        origin_address = str(origin_address).replace("('", "").replace("',)", "").strip()
        print(f"\n\t[+] Searching: {origin_address}")
        try:

            fresh_onions_source = getOnionSource(origin_address)
            new_domains = UTIL.getOnions(fresh_onions_source)
            # print(f"\t[+] Found {len(new_domains)} new domains")

            # If there are onion addresses found, continue:
            if (len(new_domains) > 0):

                pbar = tqdm(total=len(new_domains), desc=f"Analysing {len(new_domains)} new Onions")
                for new_address in new_domains:
                    # print(f"Searching subdomain: {new_address}")
                    domain_hash = UTIL.getSHA256(new_address)

                    # Verify it's not a duplicate
                    if (DB.checkOnionsDuplicate(domain_hash) == False):
                        new_source = getOnionSource(new_address)

                        if (new_source != "timeout"):

                            # If the onion address meets the "Fresh Onions" criteria, add to table
                            fresh = UTIL.isFreshOnionRepo(new_source)
                            if (fresh == True):
                                DB.freshInsert(str(new_address), str(domain_hash))

                            # Determine keywords
                            for word in CONFIG.keywords:
                                if (word in new_source):
                                    i += 1
                                    matches.append(word)

                            DB.onionsInsert(origin_address, new_address, domain_hash,
                                            str(matches), str(i), new_source)
                            pbar.update(1)
                        else:

                            DB.onionsInsert(origin_address, new_address, domain_hash,
                                            "timeout", "timeout", "timeout")
                            pbar.update(1)

                    else:
                        pbar.update(1)

                    i = 0  # Reset Index Counter for each link
                    matches.clear()  # Reset keywords for each link.

                pbar.close()

        except Exception as e:
            print(f"[!] ERROR: {e}")
            continue


# ===================================#
# Pulls .Onion address source code  #
# ===================================#
def getOnionSource(url):
    try:
        user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0'}
        to = urllib3.Timeout(connect=7, read=2)
        http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where(), headers=user_agent,
                                   retries=2, timeout=to)
        html = http.request("GET", url)
        soup = BeautifulSoup(html.data, "html.parser")
        return str(soup).lower()
    except Exception as e:
        return "timeout"


# ===================================#
# MAIN                              #
# ===================================#
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    me = parser.add_mutually_exclusive_group()
    me.add_argument("-s", "--scan", action="store_true", dest="scan", help="Scan All The Things")
    me.add_argument("-p", "--purge", action="store_true", dest="purge", help="Purge the whole database")
    me.add_argument("-c", "--clean", action="store_true", dest="clean", help="Cleanup the DB")
    args = parser.parse_args()

    if (args.scan):

        if (not UTIL.isTorEstablished()):
            print(f"[!] Not Connected to a TOR Proxy, exiting")
            exit(1)
        else:
            while True:
                redditScraper()
                freshOnionsScraper()
                print(f"[i] {datetime.datetime.now()}: Sleeping for 20 Minutes.")
                time.sleep(1200)
                print(f"[i] {datetime.datetime.now()}: Restarting Search.")

    elif (args.purge):
        last_chance_check = input("[!] This will DELETE All Data in DB - Are You Sure? (Y|N): ")
        if (last_chance_check.lower() == "y" or last_chance_check.lower() == "yes"):
            DB.deleteAll()
        else:
            print("[i] Exiting.")
            exit(0)

    elif (args.clean):
        DB.cleanupFreshOnions()

import re
import os
import sys
import logging

from src import utilities as util
from src import db_manager as db
from src import onion_utilities as onion_utils
from src import config

from datetime import datetime as dt
from tqdm import tqdm
from src.tor_web_requests import get_tor_site_source

#GLOBAL
CONFIG = config.configuration()
START_TIME = dt.now()



def get_onion_data(full_domain: str) -> dict:
    """
    Pull all the needed data for a single .onion domain to perform
    a full analysis.
    """
    base_domain = onion_utils.get_onion_base_address(full_domain)
    full_hash = util.get_sha256(full_domain)
    base_hash = util.get_sha256(base_domain)

    onion_information = {
        "full_domain": full_domain, # Holds the full domain name and path
        "base_domain": base_domain, # Holds only the base domain
        "full_hash": full_hash,     # Full Domain Hash value
        "base_hash": base_hash,     # Base Domain Hash Valud
        "onion_source": None,       # Onions HTML Source code
        "onion_title": None,        # Onion HTML Title
        "keywords": None,           # Matched keywords in config.py
        "keywords_len": None,       # A count of all the keywords found
        "found_onions": None,       # Additional Onions founds in source
        "duplicate": False,         # false=Domain is not a duplicate
        "status": False             # false=failed to pull source/get information
    }
    try:

        # Make sure this domain is not a duplicate
        if not db.is_duplicate_onion(full_hash) and not db.is_duplicate_onion(base_hash):
            if not onion_utils.is_unworthy_domain(base_domain):

                onion_data = get_tor_site_source(full_domain)
                onion_source = onion_data["source"]
                onion_title = onion_data["title"]

                if (onion_source != "timeout" and not onion_utils.is_failed_http_request(onion_title)):

                    keywords_found = onion_utils.search_onion_source_for_keywords(onion_source)
                    additional_onions = onion_utils.find_all_onion_base_addresses(onion_source)

                    onion_information = {
                        "full_domain": full_domain,
                        "base_domain": base_domain,
                        "full_hash": full_hash,
                        "base_hash": base_hash,
                        "onion_source": onion_source,
                        "onion_title": onion_title,
                        "keywords": keywords_found,
                        "keywords_len": len(keywords_found),
                        "found_onions": additional_onions,
                        "duplicate": False,
                        "status": True
                    }
        else:
            onion_information["duplicate"] = True

    except Exception as e:
        logging.error(f"get_onion_data() ERROR:{e}")
        exit(1)

    return onion_information


def check_if_fresh_onion_domain(onion_information: dict) -> None:
    """
    Check if an onion domain is a fresh onion source. If so, add
    the base domain to the fresh_onions_source table.
    """
    try:
        if not db.is_duplicate_fresh_onion(onion_information["base_hash"]):
            fresh_keywords_index = 0
            fresh_keywords = [
                "fresh onions",
                "fresh onion",
                "freshonion",
                "freshonions",
                "new",
                "fresh",
                "onions",
                "onion",
            ]

            additional_onions = len(onion_information["found_onions"])
            source = onion_information["onion_source"].lower()
            for keyword in fresh_keywords:
                if keyword in source:
                    fresh_keywords_index += 1

            if additional_onions >= 75 and fresh_keywords_index > 2:
                db.fresh_onions_insert(onion_information["base_domain"], onion_information["base_hash"])

    except Exception as e:
        logging.error(f"check_if_fresh_onion_domain() ERROR:{e}")



def analyze_onion_address(origin_address: str, domain: str) -> bool:
    """
    takes the origin address when the domain was found and the domain name
    as import. Pulls the domain source, reviews for keyswords, and stores
    the data in the sqlite db. 
    """
    try:
        onion_information = get_onion_data(domain)

        if onion_information["status"]: # if the domain lookup was successful:

            # Add the new domain information to both the ONIONS and SEEN_ONIONS table
            db.onions_insert(origin_address, onion_information["base_domain"], onion_information["onion_title"], onion_information["base_hash"], str(onion_information["keywords"]), str(onion_information["keywords_len"]), onion_information["onion_source"])

            db.seen_onions_insert(onion_information["base_domain"], onion_information["base_hash"])

            # Check if we have a Fresh Onion Domain:
            check_if_fresh_onion_domain(onion_information)

            # Check if the user wants to save data to a JSON Gzip file:
            if CONFIG.save_all_data_to_json_file:
                util.write_json_to_gzip_stream(onion_information, "onion_hunter.json.gz")

            # Save the additional onions we found during get_onion_data()
            with open("docs/additional_onions.txt", "a+") as f:
                for address in onion_information["found_onions"]:
                    f.write(address + "\n")
            f.close()

        else:   # If the domain lookup failed:
            if not onion_information["duplicate"]:
                db.seen_onions_insert(onion_information["base_domain"], onion_information["base_hash"])

        util.check_program_runtime()
        return onion_information["status"]

    except Exception as e:
        logging.error(f"analyze_onion_address() ERROR:{e}-DOMAIN:{domain}")
        exit(1)


def analyze_onions_from_file(file_path: str) -> None:
    """
    Given a txt file where each new line contains a different
    .onion address, analyze that onion. 
    """
    try:
        if os.path.exists(file_path):
            onion_addresses = open(file_path, "r").readlines()
            pbar = tqdm(total=len(onion_addresses), desc=f"Analyzing Onion Addresses from {file_path}")

            for domain in onion_addresses:
                origin_address = onion_utils.clean_onion_address(domain)
                if origin_address != "":
                    analyze_onion_address("file_import", origin_address)
                pbar.update(1)

            pbar.close()
        
    except Exception as e:
        logging.error(f"analyze_onions_from_file() ERROR:{e}")
        exit(1)


def scrape_known_fresh_onions() -> None:
    """
    with the .onion address we have denoted as Fresh in the SQLITE3 db,
    go an analyze each of the sites for new domains. 
    """
    domains = db.get_fresh_onion_domains()

    # Iterate through the known Fresh Onions domains/lists
    for i, origin_address in enumerate(domains):
        origin_address = str(origin_address).replace("('", "").replace("',)", "").strip()
        try:

            origin_onion_information = get_tor_site_source(origin_address)
            fresh_onions_source = origin_onion_information["source"]
            new_domains = onion_utils.find_all_onion_addresses(fresh_onions_source)

            # If there are onion addresses found, continue:
            if origin_onion_information["title"] != "timeout":
                pbar = tqdm(total=len(new_domains), desc=f"Searching Fresh Onion Domain #{i}")
                for domain in new_domains:
                    analyze_onion_address(origin_address, domain)
                    pbar.update(1)
                pbar.close()

        except Exception as e:
            logging.error(f"scrape_known_fresh_onions() ERROR:{e}")
            exit(1)


def deep_paste_search() -> None:
    """
    Scrapes the darknet deeppaste site (pastebin essentially)
    for domains and keyworkds. 
    """
    md5_uri_list = []
    deep_paste_keys = ['http://depastedihrn3jtw.onion/last.php',
                       'http://depastedihrn3jtw.onion/top.php',
                       "http://nzxj65x32vh2fkhk.onion/trending"]

    # Start to enumerate by getting the source then MD5's
    try:
        for i, domain in enumerate(deep_paste_keys):
            origin_address = domain.strip()

            data = get_tor_site_source(origin_address)
            onion_source = data["source"]
            md5_list = util.deep_paste_enum(onion_source)

            #interate through list and append MD5's to full URI
            for md5 in md5_list:
                uri = f'http://depastedihrn3jtw.onion/show.php?{str(md5).strip()}'
                md5_uri_list.append(uri)

            # Append key URI to the list as well
            pbar = tqdm(total=len(md5_uri_list), desc=f"Analyzing deep paste domain #{i}")
            for domain in md5_uri_list:
                analyze_onion_address(origin_address, domain)
                pbar.update(1)
            pbar.close()
            
    except Exception as e:
        logging.error(f"deep_paste_search() ERROR:{e}")
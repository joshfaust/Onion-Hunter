import re
import sys
import logging

from src import utilities as util
from src import db_manager as DB
from src import config

from tqdm import tqdm
from src.tor_web_requests import get_tor_site_source, is_tor_established, check_tor_connection

CONFIG = config.configuration()


def find_all_onion_addresses(source: str) -> list:
    """
    finds all .onion domains gived HTML source or other text. 
    """
    addresses = []
    dirty_addresses = re.findall(r'(?:https?://|)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.onion(?:\S+|)', source)
    for address in dirty_addresses:
        addresses.append(clean_onion_address(address))
    return addresses


def clean_onion_address(domain: str) -> str:
    if "<" in domain:
        domain = domain.split("<")[0]
    if (":80" in domain):
        domain = domain.split(":80")[0]
    if (":443" in domain):
        domain = domain.split(":443")[0]
    domain = re.sub(r'[()"\'{}\[\]]', '', domain)
    return domain.strip()


def is_unworthy_domain(domain_name: str) -> bool:
    """
    Check if domain is a known, not interesting domain
    """
    bad_domains = ["facebook", "facebo", "nytimes", "nytime", "twitter.com"]
    return domain_name in bad_domains


def is_failed_http_request(site_title: str) -> bool:
    """
    Check if the title contains known HTTP errors we don't
    want to collect
    """
    failures = ["Proxy error", "504", "404", "General SOCKS server failure"]
    return bool([f for f in failures if (f in str(site_title))])


def analyze_onion_address(origin_address: str, domain: str) -> None:
    """
    takes the origin address when the domain was found and the domain name
    as import. Pulls the domain source, reviews for keyswords, and stores
    the data in the sqlite DB. 
    """
    try:
        matches = set()             # Array to keep matched words.
        found_addresses = []        # placeholder for newly found onion addresses.
        domain_hash = util.getSHA256(domain)

        # Verify it's not a duplicate
        if (not DB.is_duplicate_onion(domain_hash) and not is_unworthy_domain(domain)):
            tor_dict = get_tor_site_source(domain)
            tor_source = tor_dict["source"]
            title = tor_dict["title"]

            # If we didn't get a timeout, continue to analyze
            if (tor_source != "timeout" and not is_failed_http_request(title)):

                # If the onion address meets the "Fresh Onions" criteria, add to table
                if (util.is_fresh_onion_site(tor_source)):
                    DB.freshInsert(str(domain), str(domain_hash))

                # Search for keywords in source.
                matches = get_onion_source_keywords(tor_source)
                DB.onionsInsert(origin_address, domain, title, domain_hash,
                                str(matches), str(len(matches)), tor_source)

                # add any new onions found
                found_addresses = find_all_onion_addresses(tor_source)

            # Check timout counter:
            if (tor_source == "timeout"):
                check_tor_connection()

        # Save the additional Onions to a file for later analysis
        with open("docs/additional_onions.txt", "a") as f:
            for address in found_addresses:
                f.write(address + "\n")
        f.close()

    except Exception as e:
        exec_type, exec_obj, tb = sys.exc_info()
        logging.error(f"analyze_onion_address() ERROR:{e}:linenum:{tb.tb_lineno}")
        exit(1)


def analyze_onions_from_file(file_path: str) -> None:
    """
    Given a txt file where each new line contains a different
    .onion address, analyze that onion. 
    """
    onion_addresses = open(file_path, "r").readlines()
    pbar = tqdm(total=len(onion_addresses), desc=f"Analyzing Onion Addressed from {file_path}")
    for domain in onion_addresses:
        try:
            origin_address = clean_onion_address(domain)
            if not origin_address == "":
                analyze_onion_address("file_import", origin_address)
            pbar.update(1)

        except Exception as e:
            print(f"[!] Import From File ERROR: {e}")
            exit(1)


def get_onion_source_keywords(source_code: str) -> set:
    """
    find all the keywords that match the source html code. 
    """
    matches = set()
    for word in CONFIG.keywords:
        if word in source_code:
            matches.add(word)

    return matches


def scrape_known_fresh_onions() -> None:
    """
    with the .onion address we have denoted as Fresh in the SQLITE3 DB,
    go an analyze each of the sites for new domains. 
    """
    print(f"[i] Starting Fresh Onion Searches")
    domains = DB.getFreshOnionDomains()

    # Iterate through the known Fresh Onions domains/lists
    for origin_address in domains:
        origin_address = str(origin_address).replace("('", "").replace("',)", "").strip()
        print(f"\n\t[+] Searching: {origin_address}")
        try:

            data = get_tor_site_source(origin_address)
            fresh_onions_source = data["source"]
            new_domains = find_all_onion_addresses(fresh_onions_source)

            # If there are onion addresses found, continue:
            for domain in new_domains:
                analyze_onion_address(origin_address, domain)

        except Exception as e:
            logging.error(f"scrape_known_fresh_onions ERROR:{e}")
            exit(0)


def deep_paste_search() -> None:
    md5_uri_list = []
    deep_paste_keys = ['http://depastedihrn3jtw.onion/last.php',
                       'http://depastedihrn3jtw.onion/top.php']

    # Start to enumerate by getting the source then MD5's
    try:
        for domain in deep_paste_keys:
            origin_address = domain.strip()
            print(f"[+] Searching: {origin_address}")

            data = get_tor_site_source(origin_address)
            onion_source = data["source"]
            md5_list = util.deep_paste_enum(onion_source)

            #interate through list and append MD5's to full URI
            for md5 in md5_list:
                uri = f'http://depastedihrn3jtw.onion/show.php?{str(md5).strip()}'
                md5_uri_list.append(uri)

            # Append key URI to the list as well
            for domain in md5_uri_list:
                analyze_onion_address(origin_address, domain)
            
    except Exception as e:
        print(f"[!] Error: {e}")
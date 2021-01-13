import hashlib
import re
import requests
import time
import datetime

from src import onion_analysis as onion

def chill() -> None:
    """
    pause the program for a little bit to rest the API loads
    """
    print(f"[i] {datetime.datetime.now()}: Sleeping for 20 Minutes.")
    time.sleep(1200)
    print(f"[i] {datetime.datetime.now()}: Restarting Search.")

# Gets the SHA256 hash for a string
## Returns: String
def getSHA256(data):
    try:
        n_hash = hashlib.sha256(str(data).strip().encode()).hexdigest()
        return n_hash
    except Exception as e:
        logging.error(f"Utilities_SHA256_ERROR:{e}")
        print(f"[!] ERROR: {e}")

# Get the MD5's in the deep psate site.
def deepPasteEnum(data):
    md5_list = []
    try:
        md5_list = re.findall(r'md5=[0-9a-fA-F]{32}', data)
        return md5_list
    except Exception as e:
        logging.error(f"MD5SUM_ERROR:{e}")
        return md5_list

# Checks to see if a domain is a Fresh Onion
def is_fresh_onion_site(source: str) -> bool:
    try:
        keyword_index = 0
        keywords = ["fresh onions", "fresh onion", "freshonion", "freshonions", "new", "fresh", "onions", "onion"]
        count = len(onion.find_all_onion_addresses(source))

        # Checks if any known keywords are in source code:
        for word in keywords:
            if (word.lower() in source.lower()):
                keyword_index += 1

        # Determine if this site is a Fresh Onion site:
        if (count >= 50 and keyword_index > 2):
            return True  # This is probably a Fresh Onion site
        return False  # Naa, this is just a regular onion address.

    except Exception as e:
        logging.error(f"is_fresh_onion_site() ERROR:{e}")



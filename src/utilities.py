import hashlib
import re
import certifi
import urllib3
import requests

# ---------------------------------------|
# Utilities Class                        |
#                                        |
# Author: @jfaust0                       |
#                                        |
# Description: Handles any random or     |
# otherwise needed functions             |
# ---------------------------------------|

class util:

    def __init__(self):
        self.i = 0

    # Gets the SHA256 hash for a string
    ## Returns: String
    def getSHA256(self, data):
        try:
            n_hash = hashlib.sha256(str(data).strip().encode()).hexdigest()
            return n_hash
        except Exception as e:
            print(f"[!] ERROR: {e}")

    # Pulls all of the oninos addresses resident on a single HTML page
    def getOnions(self, data):
        addresses = re.findall(r'(?:https?://|)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.onion(?:\S+|)', data)
        return addresses

    # Get the MD5's in the deep psate site.
    def deepPasteEnum(self, data):
        md5_list = []
        try:
            md5_list = re.findall(r'md5=[0-9a-fA-F]{32}', data)
            return md5_list
        except Exception as e:
            print(f"[!] Error: {e}")
            return md5_list

    # Checks to see if a domain is a Fresh Onion
    def isFreshOnionRepo(self, source):
        try:
            keyword_index = 0
            keywords = ["fresh onions", "fresh onion", "freshonion", "freshonions", "new", "fresh", "onions", "onion"]
            count = len(self.getOnions(source))

            # Checks if any known keywords are in source code:
            for word in keywords:
                if (word.lower() in source.lower()):
                    keyword_index += 1

            # Determine if this site is a Fresh Onion site:
            if (count >= 50 and keyword_index > 2):
                return True  # This is probably a Fresh Onion site
            return False  # Naa, this is just a regular onion address.

        except Exception as e:
            print(f"[!] Error: {e}")

    # Check if we are truly connected to TOR.
    def isTorEstablished(self):
        try:
            proxy = {"http":"socks5@127.0.0.1:8123","https":"socks5@127.0.0.1:8123"}
            url = "https://check.torproject.org/"
            headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0'}
            r = requests.get(url, proxies=proxy, headers=headers)
            html = r.text
            if ("congratulations" in html.lower()):
                return True
            return False

        except Exception as e:
            return False

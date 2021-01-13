
from tqdm import tqdm
from src.tor_web_requests import get_tor_site_source

DB = db_manager.db_manager()
UTIL = utilities.util()

    # Pulls all of the oninos addresses resident on a single HTML page
def find_all_onion_addresses(self, data):
    addresses = re.findall(r'(?:https?://|)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.onion(?:\S+|)', data)
    return addresses


def analyze_list_of_onions(origin_address: str, list_object: list, list_len: int) -> None:
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
            if (DB.is_duplicate_onion(domain_hash) is False and good_domain is True):
                data = get_tor_site_source(new_address)
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


# ===================================#
# Will analyze .Onions from txt file #
# ===================================#
def analyze_onions_from_file(file_path: str) -> None:
    """
    Given a txt file where each new line contains a different
    .onion address, analyze that onion. 
    """
    with open(file_path, "r") as f:
        for domain in f:
            try:
                origin_address = domain.strip()

                print(f"\n\t[+] Searching: {origin_address}")
                source_dict = get_tor_site_source(origin_address)
                onion_source = source_dict["source"]
                new_domains = find_all_onion_addresses(onion_source)

                if (len(new_domains) > 0):
                    new_domains.append(origin_address)  # Append the source address to get analyzed as well.
                    analyze_list_of_onions(origin_address, new_domains, len(new_domains))
                    new_domains.clear()

            except Exception as e:
                print(f"[!] Import From File ERROR: {e}")
                continue
    f.close()


def analyze_onion_source_for_keywords(source_code: str) -> None:
  # Search for keywords in source.
    matches = set()
    for word in CONFIG.keywords:
        if word in new_source:
            i += 1
            matches.append(word)
            
    return matches
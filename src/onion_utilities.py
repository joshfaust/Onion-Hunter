import re
from src import config

#GLOBAL
CONFIG = config.configuration()

def find_all_onion_addresses(source: str) -> list:
    """
    finds all .onion domains given HTML source or other text. 
    """
    addresses = []
    dirty_addresses = re.findall(r'(?:https?://|)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.onion(?:\S+|)', source)
    for address in dirty_addresses:
        addresses.append(clean_onion_address(address))
    return addresses


def find_all_onion_base_addresses(source: str) -> list:
    """
    finds all .onion domains base address given HTML 
    source or other text. 
    """
    addresses = re.findall(r'(?:https?://|)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.onion', source)
    addresses = list(set(addresses))
    return addresses


def get_onion_base_address(domain: str) -> str:
    """
    extract the base onion address from a domain. 
    """
    base_address = re.findall(r'(?:https?://|)(?:[-\w.]|(?:%[\da-fA-F]{2}))+\.onion', domain)
    if len(base_address) > 0:
        return base_address[0]
    else: 
        return domain


def clean_onion_address(domain: str) -> str:
    """
    Looks for characters we don't really want in our domain and
    removes them since the .onion regex pulls in things we sometimes
    do not want. 
    """
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
    social_domains = ["facebook", "facebo", "nytimes", "nytime", "twitter.com", "beautybo"]
    news_domains = ["tdwj7xgc5s2k6bmv", "s5rhoqqosmcispfb", "bbcnewsv2vjtpsuy",
    "bfnews3u2ox4m4ty", "7rmath4ro2of2a42", "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd", "s5rhoqqosmcispfb", "dwnewsvdyyiamwnp", "dstormer6em3i4km"]
    bad_domains = social_domains + news_domains
    return bool([f for f in bad_domains if (f in str(domain_name).lower())])


def is_failed_http_request(site_title: str) -> bool:
    """
    Check if the title contains known HTTP errors we don't
    want to collect
    """
    failures = ["Proxy error", "504", "404", "General SOCKS server failure", "not found"]
    return bool([f for f in failures if (f in str(site_title))])


def search_onion_source_for_keywords(source_code: str) -> list:
    """
    find all the keywords that match the source html code. 
    """
    matches = []
    for word in CONFIG.keywords:
        if word in source_code:
            matches.append(word)

    return matches
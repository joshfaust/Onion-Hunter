import requests
import logging
import time

from bs4 import BeautifulSoup
from src import config
conf = config.configuration()


def get_tor_site_source(uri: str) -> dict:
    """
    Extract HTML source from a uri
    """
    timeout = {"source": "timeout", "title": "timeout"}
    try:

        if "http" not in uri:
            uri = f"http://{uri}"

        # using Polipo port for the socks proxt to TOR
        proxy = {"http": "socks5@127.0.0.1:8123", "https": "socks5@127.0.0.1:8123"}
        headers = {"user-agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"}

        if conf.use_proxy:
            r = requests.get(uri, headers=headers, proxies=proxy, timeout=10)
        else:
            r = requests.get(uri, headers=headers, timeout=10)

        soup = BeautifulSoup(r.text, "html.parser")

        try:
            title = soup.find("title").text
        except Exception as e:
            title = None

        return {"source": str(soup).lower(), "title": title}

    except requests.exceptions.ConnectionError as e:
        logging.error(f"Tor Web Request ConnectionError:{e}")
        return timeout
    except requests.exceptions.ConnectTimeout as e:
        logging.error(f"Tor Web Request ConnectionTimeout:{e}")
        return timeout
    except requests.exceptions.HTTPError as e:
        logging.error(f"Tor Web Request HTTPError:{e}")
        return timeout
    except Exception as e:
        logging.error(f"Tor Web Request ERROR:{e}:URI={uri}")
        return timeout


def is_tor_established() -> bool:
    """
    Determine if we are connected to tor
    """
    try:

        proxy = {"http": "socks5@127.0.0.1:8123", "https": "socks5@127.0.0.1:8123"}
        uri = "https://check.torproject.org/"
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0"
        }

        if conf.use_proxy:
            r = requests.get(uri, headers=headers, proxies=proxy, timeout=10)
        else:
            r = requests.get(uri, headers=headers, timeout=10)

        html = r.text
        if "congratulations" in html.lower():
            return True
        return False

    except Exception as e:
        logging.error(f"is_tor_established() ERROR:{e}")
        return False


def check_tor_connection() -> None:
    """
    Check if we have a connection to TOR and if not, wait 30 seconds
    on 15 interations until we exit if there is no connection.
    """
    try:
        con_attempts = 0

        while not is_tor_established():
            logging.error(f"Not connected to TOR, sleeping for 30 seconds")
            print("[!] NOT Connected to TOR. Please Re-connect.")
            time.sleep(30)
            con_attempts += 1

            if con_attempts >= 15:
                print("[!] 15 Attempts to Re-Connected Failed. Exiting.")
                exit(0)
        print("\n[i] TOR Connection Confirmed")

    except Exception as e:
        logging.error(f"While checking the TOR connection, an error occured:{e}")
        exit(1)

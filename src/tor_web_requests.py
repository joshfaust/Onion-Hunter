import requests
import logging

from bs4 import BeautifulSoup


def get_tor_site_source(uri: str) -> dict:
    """
    Extract the index.html source from the web page.
    """
    timeout = {"source": "timeout", "title": "timeout"}
    try:

        if "http" not in url:
            url = f"http://{url}"

        # using Polipo port for the socks proxt to TOR
        proxy = {"http":"socks5@127.0.0.1:8123","https":"socks5@127.0.0.1:8123"}
        headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0'}
        r = requests.get(url, headers=headers, proxies=proxy, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        try:
            title = soup.find('title').text
        except Exception as e:
            title = None

        final = {"source": str(soup).lower(), "title": title}
        return final

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
        logging.error(f"Tor Web Request ERROR:{e}")
        return timeout     


    def is_tor_established() -> bool:
        """
        Determine if we are connected to tor
        """
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

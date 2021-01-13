import praw
import logging
from tqdm import tqdm

from src import utilities as util
from src import onion_analysis as onion 
from src import config

CONFIG = config.configuration()

def reddit_login() -> praw.Reddit:
    """
    Ontain a seesion from reddit.
    """
    try:
        r = praw.Reddit(username=CONFIG.r_username,
                        password=CONFIG.r_password,
                        client_id=CONFIG.r_client_id,
                        client_secret=CONFIG.r_client_secret,
                        user_agent=CONFIG.r_user_agent)

        username = r.user.me()

        if (username is None):
            raise praw.exceptions.ClientException("Failed to Login. Please Check Configuration Settings.")

        print(f"[i] Logged into Reddit as: {r.user.me()}")
        return r

    except praw.exceptions.ClientException as e:
        logging.error(f"Praw_ClientException:{e}")
    except praw.exceptions.PRAWException as e:
        logging.error(f"PrawException:{e}")
    except praw.exceptions.APIException as e:
        logging.error(f"Praw_APIException:{e}")


def redditScraper():
    """
    Enumerates each subreddit defined in the config
    and scrapes from onion addresses. 
    """
    r = reddit_login()
    for sub in CONFIG.sub_reddits:

        try:
            subreddit = r.subreddit(sub)
            print(f"\n[+] Analyzing {subreddit.display_name} Subreddit.")

            for submission in subreddit.hot(limit=75):
                sub_content = submission.selftext
                sub_link = submission.url
                sub_links = onion.find_all_onion_addresses(sub_content)
                domain_source = str(sub_link).strip()

                # Check the top 15 comments in the Subreddit as well.
                for comment in submission.comments.list()[:10]:
                    addresses = onion.find_all_onion_addresses(comment.body)
                    if (len(addresses) > 0):
                        for i, item in enumerate(addresses) :
                            sub_links.append(addresses[i])

                # If there are onions found, continue
                if len(sub_links) > 0:
                    pbar = tqdm(total=len(sub_links), desc=f"Analyzing {len(sub_links)} Onion Domains")
                    for domain in sub_links:
                        onion.analyze_onion_address(domain_source, domain)
                        pbar.update(1)

        except praw.exceptions.ClientException as e:
            logging.error(f"Praw_ClientException:{e}")
            continue
        except praw.exceptions.PRAWException as e:
            logging.error(f"PrawException:{e}")
            continue
        except praw.exceptions.APIException as e:
            logging.error(f"Praw_APIException:{e}")
            continue
        except AttributeError as e:
            logging.error(f"AttributeError:{e}")
            continue
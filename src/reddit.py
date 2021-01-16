import praw
import logging
from tqdm import tqdm

from src import utilities as util
from src import onion_analysis as onion
from src import onion_utilities as onion_utils
from src import config

CONFIG = config.configuration()


def reddit_login() -> praw.Reddit:
    """
    Ontain a seesion from reddit.
    """
    try:
        r = praw.Reddit(
            username=CONFIG.r_username,
            password=CONFIG.r_password,
            client_id=CONFIG.r_client_id,
            client_secret=CONFIG.r_client_secret,
            user_agent=CONFIG.r_user_agent,
        )

        username = r.user.me()

        if username is None:
            raise praw.exceptions.ClientException("Reddit Login Failed. Check Configuration Settings")

        return r

    except praw.exceptions.ClientException as e:
        logging.error(f"Praw_ClientException:{e}")
    except praw.exceptions.PRAWException as e:
        logging.error(f"PrawException:{e}")
    except praw.exceptions.APIException as e:
        logging.error(f"Praw_APIException:{e}")


def redditScraper() -> None:
    """
    Enumerates each subreddit defined in the config
    and scrapes from onion addresses.
    """
    r = reddit_login()
    onion_addresses = []

    subreddit_pbar = tqdm(
        total=len(CONFIG.sub_reddits), desc=f"Searching subreddits for Onions"
    )
    for sub in CONFIG.sub_reddits:
        try:
            onion_holder = []
            subreddit = r.subreddit(sub)

            for submission in subreddit.hot(limit=20):
                sub_content = submission.selftext
                sub_link = submission.url
                onion_addresses = onion_addresses + onion_utils.find_all_onion_addresses(
                    sub_content
                )
                domain_source = str(sub_link).strip()

                # Check the top 15 comments in the Subreddit as well.
                for comment in submission.comments.list()[:10]:
                    addresses = onion_utils.find_all_onion_addresses(comment.body)
                    if len(addresses) > 0:
                        for i, item in enumerate(addresses):
                            onion_addresses.append(addresses[i])
            subreddit_pbar.update(1)

        except praw.exceptions.ClientException as e:
            logging.error(f"Praw_ClientException:{e}")
            subreddit_pbar.update(1)
            continue
        except praw.exceptions.PRAWException as e:
            logging.error(f"PrawException:{e}")
            subreddit_pbar.update(1)
            continue
        except praw.exceptions.APIException as e:
            logging.error(f"Praw_APIException:{e}")
            subreddit_pbar.update(1)
            continue
        except AttributeError as e:
            logging.error(f"AttributeError:{e}")
            subreddit_pbar.update(1)
            continue

    subreddit_pbar.close()
    if len(onion_addresses) > 0:
        pbar = tqdm(
            total=len(onion_addresses),
            desc=f"Analyzing {len(onion_addresses)} Reddit Onions",
        )
        for domain in onion_addresses:
            onion.analyze_onion_address(domain_source, domain)
            pbar.update(1)
        pbar.close()

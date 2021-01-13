import base64
import datetime
import sqlite3
from bs4 import BeautifulSoup
from tqdm import tqdm

from src import utilities as util
from src import onion_analysis as onion


"""
CREATE TABLE ONIONS
(ID INTEGER PRIMARY KEY AUTOINCREMENT,
DATE_FOUND TEXT NOT NULL,
DOMAIN_SOURCE TEXT NOT NULL,
URI TEXT NOT NULL,
URI_TITLE TEXT,
DOMAIN_HASH TEXT NOT NULL,
KEYWORD_MATCHES TEXT,
KEYWORD_MATCHES_SUM INT,
INDEX_SOURCE TEXT NOT NULL);

CREATE TABLE FRESH_ONION_SOURCES
(ID INTEGER PRIMARY KEY AUTOINCREMENT,
URI TEXT NOT NULL,
DOMAIN_HASH TEXT NOT NULL,
FOREIGN KEY (DOMAIN_HASH) REFERENCES ONIONS (DOMAIN_HASH));

CREATE TABLE SEEN_ONIONS
(ID INTEGER PRIMARY KEY AUTOINCREMENT,
DATE_FOUND TEXT NOT NULL,
URI TEXT NOT NULL,
DOMAIN_HASH TEXT NOT NULL,
FOREIGN KEY (DOMAIN_HASH) REFERENCES ONIONS (DOMAIN_HASH));
"""


# ---------------------------------------|
# Database Manager Class                 |
#                                        |
# Author: @jfaust0                       |
#                                        |
# Description: Handles all of the DB     |
# communication.                         |
# ---------------------------------------|

# Global
databaseFile = "onion.db"
conn = sqlite3.connect(databaseFile)
cur = conn.cursor()

# Deletes all data from the DB and resets the tables index values
def deleteAll():
    try:
        cmd0 = "delete from sqlite_sequence"
        cmd1 = "delete from FRESH_ONION_SOURCES"
        cmd2 = "delete from KNOWN_ONIONS"
        cmd3 = "delete from ONIONS"
        cur.execute(cmd0)
        conn.commit()
        cur.execute(cmd1)
        conn.commit()
        cur.execute(cmd2)
        conn.commit()
        cur.execute(cmd3)
        conn.commit()
        print("[i] All Data has been deleted from all tables.")
    except Exception as e:
        print(e)
        exit(0)


# Insert into the ONIONS table
def onionsInsert(DS, URI, UT, DH, KM, KMS, IS):
    try:

        cmd = """INSERT INTO ONIONS (DATE_FOUND, DOMAIN_SOURCE, URI, URI_TITLE, DOMAIN_HASH, KEYWORD_MATCHES, KEYWORD_MATCHES_SUM, INDEX_SOURCE) VALUES(?,?,?,?,?,?,?,?)"""
        timestamp = datetime.datetime.now()
        source_code = base64.encodebytes(str(IS).encode("utf-8"))
        data = (
            str(timestamp),
            str(DS),
            str(URI),
            str(UT),
            str(DH),
            str(KM),
            str(KMS),
            source_code,
        )
        conn.execute(cmd, data)
        conn.commit()

    except Exception as e:
        print(f"[!] Onions ERROR: {e}")


# Insert into the ONIONS table
def seen_onions_insert(domain: str, domain_hash: str) -> None:
    try:

        cmd = """INSERT INTO SEEN_ONIONS (DATE_FOUND, URI, DOMAIN_HASH) VALUES(?,?,?)"""
        timestamp = datetime.datetime.now()
        data = (str(timestamp), domain, domain_hash)
        conn.execute(cmd, data)
        conn.commit()

    except Exception as e:
        logging.error(f"seen_onions_insert() ERROR:{e}")
        print(f"[!] Onions ERROR: {e}")


# Insert into the FRESH ONIONS SOURCES table
def freshInsert(URI, DH):
    try:
        cmd = "INSERT INTO FRESH_ONION_SOURCES (URI, DOMAIN_HASH)  VALUES (?,?)"
        conn.execute(
            cmd,
            (
                str(URI),
                str(DH),
            ),
        )
        conn.commit()

    except Exception as e:
        print(f"[!] Fresh Insert ERROR: {e}")


# Insert into the KNOWN_ONIONS  table
def knownOnionsInsert(DH, RE):
    try:
        cmd = (
            "INSERT INTO KNOWN_ONIONS (DOMAIN_HASH, DATE_REPORTED, REPORTED) "
            "VALUES (?,?,?,)"
        )
        timestamp = datetime.datetime.now()
        conn.execute(
            cmd,
            (
                str(DH),
                str(timestamp),
                str(RE),
            ),
        )
        conn.commit()

    except Exception as e:
        print(f"[!] Known Insert ERROR: {e}")


# Pull all of the Fresh Onion Domains from the DB
## Returns: List Object
def getFreshOnionDomains():
    try:
        cmd = "SELECT URI FROM FRESH_ONION_SOURCES"
        cur.execute(cmd)
        data = cur.fetchall()
        return data
    except Exception as e:
        print(f"[!] Get Fresh ERROR: {e}")


# Checks if a Domain alread exists within the ONIONS table
## Returns: Boolean
def is_duplicate_onion(n_hash: str) -> bool:
    try:
        cmd1 = "SELECT count(DOMAIN_HASH) FROM ONIONS WHERE DOMAIN_HASH =?"
        cur.execute(cmd1, (n_hash,))
        onions_data = cur.fetchone()
        onions_data = str(onions_data).split(",")[0].replace("(", "")
        onions_data = int(onions_data)

        cmd2 = "SELECT count(DOMAIN_HASH) FROM SEEN_ONIONS WHERE DOMAIN_HASH =?"
        cur.execute(cmd2, (n_hash,))
        seen_onions_data = cur.fetchone()
        seen_onions_data = str(seen_onions_data).split(",")[0].replace("(", "")
        seen_onions_data = int(seen_onions_data)

        data = onions_data + seen_onions_data
        if data <= 0:
            return False  # Does not exists in database
        return True  # Exists in databases
    except Exception as e:
        print(f"[!] Check Duplication ERROR: {e}")


# Simply removes any onions that have the following attributes:
# - Has less than 50 onions on a single GET request
def cleanupFreshOnions():
    try:
        print("[i] Cleaning Up FRESH_ONIONS Table")
        deleted_index = 0

        # Get all of the hashes for the
        cmd0 = "SELECT DOMAIN_HASH FROM FRESH_ONION_SOURCES"
        cur.execute(cmd0)
        hash_list = cur.fetchall()

        pbar = tqdm(total=len(hash_list))
        for n_hash in hash_list:
            n_hash = str(n_hash).split("'")[1]

            cmd1 = "SELECT URI FROM FRESH_ONION_SOURCES WHERE DOMAIN_HASH =?"
            cur.execute(cmd1, (n_hash,))
            uri = cur.fetchone()

            # Pull the source code from the ONIONS table
            cmd2 = f"SELECT INDEX_SOURCE FROM ONIONS WHERE DOMAIN_HASH =?"
            cur.execute(cmd2, (n_hash,))
            source = str(cur.fetchone()).split("'")[1].replace("\\n", "")
            decoded_source = base64.decodebytes(source.encode("utf-8"))

            onion_addresses = onion.find_all_onion_addresses(str(decoded_source))

            if (
                len(onion_addresses) < 50
                or "facebook" in str(uri).lower()
                or "nytimes" in str(uri).lower()
            ):
                cmd2 = f"DELETE FROM FRESH_ONION_SOURCES WHERE DOMAIN_HASH =?"
                conn.execute(cmd2, (n_hash,))
                conn.commit()
                deleted_index += 1
            pbar.update(1)
        pbar.close()

        print(f"\t[i] Deleted {deleted_index} Fresh Onions Sources")

    except Exception as e:
        print(f"[!] Cleanup ERROR: {e}")


# Simply removes any onions that have the following attributes:
# - Has less than 50 onions on a single GET request
def cleanupOnions():
    try:
        print("[i] Cleaning Up ONIONS Table")
        deleted_index = 0

        # Get all of the hashes for all domains and read into a list
        cmd0 = "SELECT DOMAIN_HASH FROM ONIONS"
        cur.execute(cmd0)
        hash_list = cur.fetchall()
        hash_list_length = len(hash_list)

        # Delete all onions associated with Facebook, NYTimes
        pbar = tqdm(total=hash_list_length)
        for n_hash in hash_list:
            n_hash = str(n_hash).split("'")[1]

            cmd1 = f"SELECT URI FROM ONIONS WHERE DOMAIN_HASH =?"
            cur.execute(cmd1, (n_hash,))
            uri = cur.fetchone()

            if "facebook" in str(uri).lower() or "nytimes" in str(uri).lower():
                cmd2 = f"DELETE FROM ONIONS WHERE DOMAIN_HASH =?"
                conn.execute(cmd2, (n_hash,))
                conn.commit()
                deleted_index += 1

            pbar.update(1)
        pbar.close()

        # Delete all onions where we received a timeout
        count = f'SELECT COUNT(ID) FROM ONIONS WHERE KEYWORD_MATCHES = "timeout"'
        conn.execute(count)
        count_list = cur.fetchone()
        if count_list is None:
            count_list = 0

        cmd2 = f'DELETE from ONIONS where KEYWORD_MATCHES == "timeout"'
        conn.execute(cmd2)
        conn.commit()

        # Database cleanup, optimization
        cmd3 = "vacuum"
        conn.execute(cmd3)
        conn.commit()

        print(
            f"[i] Database Cleanup Complete:\n\t[i] Deleted {deleted_index} Garbage Onions"
        )
        print(f"\t[i] Deleted {count_list} onions that had no data (timeouts)")

    except Exception as e:
        print(f"[!] Cleanup ERROR: {e}")


# Added a new column in the ONIONS table called title. This function goes through all the source code within
## the ONIONS tables and updates the ONION table with the found site Title.
def addTitlesFromSource():
    try:

        # Get all of the hashes for all domains and read into a list
        cmd0 = "SELECT DOMAIN_HASH FROM ONIONS"
        cur.execute(cmd0)
        hash_list = cur.fetchall()
        hash_list_length = len(hash_list)

        pbar = tqdm(total=hash_list_length)
        for n_hash in hash_list:
            n_hash = str(n_hash).split("'")[1]

            # For each n_hash, pull it's HTML Source code
            get = f"SELECT INDEX_SOURCE FROM ONIONS WHERE DOMAIN_HASH =?"
            cur.execute(get, (n_hash,))
            source = str(cur.fetchone()).split("'")[1].replace("\\n", "")
            decoded_source = base64.decodebytes(source.encode("utf-8"))

            # Have BS4 find the title and put it into plaintext
            soup = BeautifulSoup(decoded_source, "html.parser")
            try:
                title = soup.find("title").text
            except Exception as e:
                title = None

            # Add it to the Onions table
            cmd0 = f"UPDATE ONIONS SET URI_TITLE = ? WHERE DOMAIN_HASH = ?"
            data = (title, n_hash)
            conn.execute(cmd0, data)
            conn.commit()

            pbar.update(1)

    except Exception as e:
        print(e)

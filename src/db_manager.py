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

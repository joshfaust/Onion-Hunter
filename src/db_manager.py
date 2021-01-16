import base64
import datetime
import sqlite3
import logging
from bs4 import BeautifulSoup
from tqdm import tqdm

from src import utilities as util
from src import onion_analysis as onion
from src import config
conf = config.configuration()

#GLOBAL
databaseFile = conf.db_name
conn = sqlite3.connect(databaseFile)
cur = conn.cursor()

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

def delete_all_db_data() -> None:
    """
    Deletes all data from the DB and resets the tables index values
    """
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
        logging.error(f"delete_all_db_data() ERROR:{e}")


def onions_insert(DS: str, URI: str, UT: str, DH: str, KM: str, KMS: str, IS: str) -> None:
    """
    Insert a new row into the ONIONS table
    """
    try:

        cmd = """INSERT INTO ONIONS (DATE_FOUND, DOMAIN_SOURCE, URI, URI_TITLE, DOMAIN_HASH, KEYWORD_MATCHES, KEYWORD_MATCHES_SUM, INDEX_SOURCE) VALUES(?,?,?,?,?,?,?,?)"""
        timestamp = datetime.datetime.now()
        source_code = base64.encodebytes(str(IS).encode("utf-8"))
        if conf.save_html_source_to_db:
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
        else:
            data = (
                str(timestamp),
                str(DS),
                str(URI),
                str(UT),
                str(DH),
                str(KM),
                str(KMS),
                "",
            )

        conn.execute(cmd, data)
        conn.commit()

    except Exception as e:
        logging.error(f"onions_insert() ERROR:{e}")


def seen_onions_insert(domain: str, domain_hash: str) -> None:
    """
    Insert a new row into the SEEN_ONIONS table
    """
    try:

        cmd = """INSERT INTO SEEN_ONIONS (DATE_FOUND, URI, DOMAIN_HASH) VALUES(?,?,?)"""
        timestamp = datetime.datetime.now()
        data = (str(timestamp), domain, domain_hash)
        conn.execute(cmd, data)
        conn.commit()

    except Exception as e:
        logging.error(f"seen_onions_insert() ERROR:{e}")


def fresh_onions_insert(URI: str, DH: str) -> None:
    """
    Insert a new row into the FRESH ONIONS SOURCES table
    """
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
        logging.error(f"fresh_onions_insert() ERROR:{e}")


def get_fresh_onion_domains() -> list:
    """
    Get a list of all the domains from FRESH_ONIONS_SOURCES
    """
    try:
        cmd = "SELECT URI FROM FRESH_ONION_SOURCES"
        cur.execute(cmd)
        data = cur.fetchall()
        return data
    except Exception as e:
        logging.error(f"get_fresh_onion_domains() ERROR:{e}")


def is_duplicate_onion(n_hash: str) -> bool:
    """
    Checks if a Domain alread exists within the ONIONS or 
    the SEEM_ONIONS table to avoid duplication
    """
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
        logging.error(f"is_duplicate_onion() ERROR:{e}")


def create_new_database() -> None:
    """
    Creates a brand new onions.db
    """
    try:
        table1 = """CREATE TABLE ONIONS
    (ID INTEGER PRIMARY KEY AUTOINCREMENT,
    DATE_FOUND TEXT NOT NULL,
    DOMAIN_SOURCE TEXT NOT NULL,
    URI TEXT NOT NULL,
    URI_TITLE TEXT,
    DOMAIN_HASH TEXT NOT NULL,
    KEYWORD_MATCHES TEXT,
    KEYWORD_MATCHES_SUM INT,
    INDEX_SOURCE TEXT NOT NULL);"""
        table2 = """CREATE TABLE FRESH_ONION_SOURCES
    (ID INTEGER PRIMARY KEY AUTOINCREMENT,
    URI TEXT NOT NULL,
    DOMAIN_HASH TEXT NOT NULL,
    FOREIGN KEY (DOMAIN_HASH) REFERENCES ONIONS (DOMAIN_HASH));"""
        table3 = """CREATE TABLE SEEN_ONIONS
    (ID INTEGER PRIMARY KEY AUTOINCREMENT,
    DATE_FOUND TEXT NOT NULL,
    URI TEXT NOT NULL,
    DOMAIN_HASH TEXT NOT NULL,
    FOREIGN KEY (DOMAIN_HASH) REFERENCES ONIONS (DOMAIN_HASH));"""
        cur.execute(table1)
        conn.commit()
        cur.execute(table2)
        conn.commit()
        cur.execute(table3)
        conn.commit()
    except Exception as e:
        logging.error(f"create_new_database() ERROR:{e}")


def dedup_fresh_onion_sources():
    print("[i] Cleaning Up FRESH_ONIONS Table")
    cleaned_hashes = set()

    # Get all of the hashes for the
    cmd0 = "SELECT URI FROM FRESH_ONION_SOURCES"
    cur.execute(cmd0)
    uri_list = cur.fetchall()

    # Delete the table's data:
    cmd1 = "DELETE FROM FRESH_ONION_SOURCES"
    cur.execute(cmd1)
    conn.commit()

    # Reset the PK index:
    cmd2 = "delete from sqlite_sequence where name = \"FRESH_ONION_SOURCES\""
    cur.execute(cmd2)
    conn.commit()

    # Pull base domains from onion and re-populate the DB
    pbar = tqdm(total=len(uri_list))
    for uri in uri_list:
        uri = str(uri).split("'")[1]
        cleaned_uri = onion.get_onion_base_address(uri)
        cleaned_hash = util.get_sha256(uri)

        if cleaned_hash not in cleaned_hashes:
            cmd = "INSERT INTO FRESH_ONION_SOURCES (URI, DOMAIN_HASH)  VALUES (?,?)"
            conn.execute(
            cmd,
            (
                str(cleaned_uri),
                str(cleaned_hash),
            ),
            )
            conn.commit()
            cleaned_hashes.add(cleaned_hash)

        pbar.update(1)


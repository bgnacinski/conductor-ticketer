from loguru import logger
from Outbox import Outbox
from Inbox import Inbox
from Gate import Gate
import Repositories
import aiosqlite
import datetime
import asyncio
import os
import sys

LOG_LEVEL = os.getenv("LOG_LEVEL") or "INFO"
LOG_FILE = os.getenv("LOG_FILE") or "server.log"

# API-related variables
API_URL = os.getenv("API_URL") or "http://localhost/api/"
API_URL = API_URL + "/" if not API_URL.endswith("/") else API_URL
API_KEY = os.getenv("API_KEY") or ""
BULK_PUSH = str(os.getenv("BULK_PUSH")).lower() in ("true", "yes")
BATCH_SIZE = int(os.getenv("BATCH_SIZE") or 500)
API_PULL_INTERVAL = int(os.getenv("API_PULL_INTERVAL") or 86400)
INCREMENTAL_BAN_PULL = str(os.getenv("INCREMENTAL_BAN_PULL")).lower() in ("true", "yes")
API_PUSH_INTERVAL = int(os.getenv("API_PUSH_INTERVAL") or 1800)

# gate-related variables
BIND_ADDRESS = os.getenv("BIND_ADDRESS") or ""
BIND_PORT = int(os.getenv("BIND_PORT") or 2137)
GATE_TYPE = os.getenv("GATE_TYPE") or "exit"
NONCE_SIZE = int(os.getenv("NONCE_SIZE") or 16)

# general purpose variables
DB_FILE = os.getenv("DB_FILE") or "outbox.db"
CA_PUBKEY_FILE = os.getenv("CA_PUBKEY_FILE") or "crypto/ca_key.pub"

def init_logger():
    logger.remove()

    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level=LOG_LEVEL,
    )

    logger.add(
        LOG_FILE,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=LOG_LEVEL,
        rotation="10 MB",
        retention="10 days",
        compression="zip",
        encoding="utf-8"
    )

async def prepare_db(db_file:str) -> aiosqlite.Connection:
    logger.info("Preparing DB...")

    try:
        conn = await aiosqlite.connect(db_file)
        await conn.execute("""
                    CREATE TABLE IF NOT EXISTS "outbox"
                    (
                         id                 TEXT PRIMARY KEY,
                         client_fingerprint TEXT NOT NULL,
                         action_type        TEXT NOT NULL CHECK (action_type IN ('entry', 'exit')),
                         created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
                         status             TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'FAILED', 'SENT', 'VALERR')) DEFAULT 'PENDING',
                         next_retry_at      DATETIME,
                         error_message      TEXT
                    )""")
        await conn.execute("""
                    CREATE TABLE IF NOT EXISTS "bans"
                    (
                        client_fingerprint BLOB not null constraint bans_pk primary key,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )""")

        await conn.execute("""
                    CREATE TABLE IF NOT EXISTS "last_performed_at"
                    (
                        action_name TEXT NOT NULL,
                        performed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )        
        """)
        await conn.commit()

        # see if any actions have been performed
        cur = await conn.execute("SELECT COUNT(*) FROM last_performed_at")
        num_rows = await cur.fetchone()
        await cur.close()

        if num_rows[0] == 0:
            await conn.execute("DELETE FROM last_performed_at WHERE 1")
            await conn.execute("INSERT INTO last_performed_at(action_type, performed_at) VALUES ('ban_sync', ?)", (datetime.datetime.fromtimestamp(0).isoformat(),))

        await conn.commit()

        await conn.execute("PRAGMA journal_mode = WAL;")
        await conn.execute("PRAGMA synchronous = FULL;")
        await conn.execute("PRAGMA wal_checkpoint(FULL);")

    except aiosqlite.Error as e:
        logger.exception(f"Failed to prepare database ({db_file}): {e}")
        raise

    logger.info("DB prepared successfully")

    return conn

async def api_pull(inbox: Inbox):
    logger.info("Retrieving CA's public key from API...")
    await inbox.fetch_pubkey()

    # get bans
    logger.info("Retrieving ban list from API...")
    await inbox.fetch_bans()

async def gate_handler(inbox: Inbox, outbox: Outbox, log_repository: Repositories.LogRepository, ban_repository: Repositories.BanRepository):
    gate = Gate(GATE_TYPE, log_repository, ban_repository, NONCE_SIZE, CA_PUBKEY_FILE)
    api_push_task = asyncio.create_task(api_push_loop(outbox))
    api_pull_task = asyncio.create_task(api_pull_loop(inbox))

    try:
        server = await asyncio.start_server(gate.client_handler, BIND_ADDRESS, BIND_PORT)

        logger.info("Waiting for clients...")
        await server.serve_forever()

    finally:
        api_push_task.cancel()
        api_pull_task.cancel()
        log_repository.close()
        ban_repository.close()

async def api_push_loop(outbox: Outbox):
    while True:
        logger.debug(f"Pushing data...")
        await outbox.push(BULK_PUSH)
        logger.debug(f"Next push cycle in {API_PUSH_INTERVAL} seconds")
        await asyncio.sleep(API_PUSH_INTERVAL)

async def api_pull_loop(inbox: Inbox):
    while True:
        logger.debug(f"Next pull cycle in {API_PULL_INTERVAL} seconds")
        await asyncio.sleep(API_PULL_INTERVAL)
        logger.debug(f"Pulling data...")
        await api_pull(inbox)

async def setup():
    db = await prepare_db(DB_FILE)
    log_repo = Repositories.LogRepository(db)
    await log_repo.cleanup()
    ban_repo = Repositories.BanRepository(db)
    last_perf_repo = Repositories.LastPerformedRepository(db)

    ib = Inbox(API_URL, API_KEY, ban_repo, CA_PUBKEY_FILE, last_perf_repo, INCREMENTAL_BAN_PULL)
    ob = Outbox(API_URL, API_KEY, log_repo, BATCH_SIZE)

    await api_pull(ib)

    return db, ib, ob, log_repo, ban_repo

async def launcher():
    init_logger()

    db, ib, ob, log_repo, ban_repo = await setup()
    await gate_handler(ib, ob, log_repo, ban_repo)

if __name__ == "__main__":
    asyncio.run(launcher())

import Repositories
from Gate import Gate
from Outbox import Outbox
from Inbox import Inbox
import aiosqlite
import asyncio
import os

# API-related variables
API_URL = os.getenv("API_URL") or "http://localhost/api/"
API_URL = API_URL + "/" if API_URL.endswith("/") else API_URL
API_KEY = os.getenv("API_KEY") or ""
BULK_PUSH = str(os.getenv("BULK_PUSH")).lower() in ("true", "yes")
API_PULL_INTERVAL = int(os.getenv("API_PULL_INTERVAL") or 86400)
API_PUSH_INTERVAL = int(os.getenv("API_PUSH_INTERVAL") or 1800)

# gate-related variables
BIND_ADDRESS = os.getenv("BIND_ADDRESS") or ""
BIND_PORT = int(os.getenv("BIND_PORT") or 2137)
GATE_TYPE = os.getenv("GATE_TYPE") or "exit"
NONCE_SIZE = int(os.getenv("NONCE_SIZE") or 16)

# general purpose variables
DB_FILE = os.getenv("DB_FILE") or "outbox.db"
CA_PUBKEY_FILE = os.getenv("CA_PUBKEY_FILE") or "crypto/ca_key.pub"

async def prepare_dbs(db_file:str) -> aiosqlite.Connection:
    print("[*] Preparing DBs...", end=" ")

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
                        client_fingerprint BLOB not null
                        constraint bans_pk primary key
                    )""")

    await conn.commit()

    await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA synchronous = FULL;")
    await conn.execute("PRAGMA wal_checkpoint(FULL);")

    print("done!")

    return conn

async def api_pull(inbox: Inbox):
    print("[*] Retrieving CA's public key from API...", end=" ")
    pubkey = await inbox.fetch_pubkey()

    # get bans
    print("[*] Retrieving ban list from API...", end=" ")
    bans = await inbox.fetch_bans()

async def gate_handler(inbox: Inbox, outbox: Outbox, log_repository: Repositories.LogRepository, ban_repository: Repositories.BanRepository):
    gate = Gate(GATE_TYPE, log_repository, ban_repository, NONCE_SIZE, CA_PUBKEY_FILE)
    api_push_task = asyncio.create_task(api_push_loop(outbox))
    api_pull_task = asyncio.create_task(api_pull_loop(inbox))

    try:
        server = await asyncio.start_server(gate.client_handler, BIND_ADDRESS, BIND_PORT)

        print("[*] Gate Handler | Waiting for clients...")
        await server.serve_forever()

    finally:
        api_push_task.cancel()
        api_pull_task.cancel()
        log_repository.close()
        ban_repository.close()

async def api_push_loop(outbox: Outbox):
    while True:
        await outbox.push(BULK_PUSH)
        await asyncio.sleep(API_PUSH_INTERVAL)

async def api_pull_loop(inbox: Inbox):
    while True:
        await asyncio.sleep(API_PULL_INTERVAL)
        await api_pull(inbox)

async def setup():
    db = await prepare_dbs(DB_FILE)
    log_repo = Repositories.LogRepository(db)
    await log_repo.cleanup()
    ban_repo = Repositories.BanRepository(db)

    ib = Inbox(API_URL, API_KEY, ban_repo, CA_PUBKEY_FILE)
    ob = Outbox(API_URL, API_KEY, log_repo)

    await api_pull(ib)

    return db, ib, ob, log_repo, ban_repo

async def launcher():
    db, ib, ob, log_repo, ban_repo = await setup()
    await gate_handler(ib, ob, log_repo, ban_repo)

if __name__ == "__main__":
    asyncio.run(launcher())
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from math import ceil
import aiosqlite
import hashlib
import random


class BanRepository:
    _db: aiosqlite.Connection
    _batch_size: int = 999

    def __init__(self, db: aiosqlite.Connection, batch_size: int = 999):
        self._db = db
        self._batch_size = batch_size

    async def is_banned(self, client_fingerprint: str) -> bool:
        try:
            cursor = await self._db.execute(
                "SELECT client_fingerprint FROM bans WHERE client_fingerprint = ?",
                (client_fingerprint,),
            )

            res = await cursor.fetchone()
            await cursor.close()

            if res: # response not empty -> client banned
                return True

        except aiosqlite.Error as e:
            print(f"[!] DB Error: {e}")

        # not banned by default
        return False

    async def ban_bulk(self, client_fingerprints: list) -> bool:
        try:
            # splitting data into batches
            no_batches = int(ceil(len(client_fingerprints) / self._batch_size))
            for i in range(0, no_batches):
                batch_fingerprints = client_fingerprints[self._batch_size * i:self._batch_size * (i + 1)]
                batch_placeholders = ",".join("(?)" * len(batch_fingerprints))
                await self._db.execute(f"INSERT INTO bans (client_fingerprint) VALUES {batch_placeholders}",
                                       (*batch_fingerprints,))
                await self._db.commit()

            return True

        except aiosqlite.IntegrityError:
            print("[!] Duplicate client fingerprint, saving may have not been performed!")

        except aiosqlite.OperationalError:
            print("[!] Operational error occurred, saving may have not been performed!")

        except aiosqlite.Error as e:
            print(f"[!] SQLite error: {e}, saving may have not been performed!")

        return False

    async def clear_bans(self) -> bool:
        try:
            await self._db.execute("DELETE FROM bans")
            await self._db.commit()

            return True

        except aiosqlite.Error as e:
            print(f"[!] DB error: {e}, clear may have not been performed!")

        return False

    def close(self):
        self._db.close()


class LogRepository:
    _db: aiosqlite.Connection
    _retry_delay_base: int = 5
    _retry_delay_cap: int = 900

    def __init__(self, db: aiosqlite.Connection, retry_delay_base: int = 5, retry_delay_cap: int = 900):
        self._retry_delay_base = retry_delay_base
        self._retry_delay_cap = retry_delay_cap
        self._db = db

    async def prepare_api_push(self) -> list | None:
        """
        Status changes:
         - PROCESSING -> PENDING
         - (FAILED AND next_retry_at <= CURRENT_TIMESTAMP) -> PENDING
         """
        data_to_push = await self._db.execute_fetchall("""
                                                       UPDATE outbox
                                                       SET status = 'PROCESSING'
                                                       WHERE (status = 'PENDING')
                                                          OR (status = 'FAILED' AND
                                                              (next_retry_at IS NULL OR next_retry_at <= CURRENT_TIMESTAMP))
                                                       RETURNING id, client_fingerprint, action_type, created_at""")

        if data_to_push:
            return list(data_to_push)

        return None

    async def append_log(self, client_pubkey: bytes, gate_type: str) -> bool:
        fingerprint = hashlib.sha256(client_pubkey).hexdigest()
        action_uuid = str(uuid4())
        action_type = gate_type

        try:
            await self._db.execute("INSERT INTO outbox(id, client_fingerprint, action_type) VALUES (?, ?, ?)",
                                   (action_uuid, fingerprint, action_type))
            await self._db.commit()
            return True

        except aiosqlite.Error as e:
            print(f"DB error: {e}, data may have not been saved!")
            return False

    async def retard_sync(self, ids: list[int]) -> bool:
        def next_retry(base: float = 5, cap: float = 900) -> str:
            delay = random.uniform(base, cap)
            return (datetime.now(timezone.utc) + timedelta(minutes=delay)).strftime("%Y-%m-%d %H:%M:%S")

        placeholders = ",".join("?" * len(ids))

        try:
            await self._db.execute(f"UPDATE outbox SET next_retry_at = ?, status='FAILED' WHERE id IN ({placeholders})",
                                   (next_retry(self._retry_delay_base, self._retry_delay_cap), *ids))
            await self._db.commit()

            return True

        except aiosqlite.Error as e:
            print(f"[!] DB error during sync retardation: {e}")

        return False

    async def update_status(self, batch_ids: list, status: str = "PENDING") -> bool:
        try:
            placeholders = ",".join("?" * len(batch_ids))
            await self._db.execute(f"UPDATE outbox SET status=? WHERE id IN ({placeholders})", (status, *batch_ids))
            await self._db.commit()

            return True

        except aiosqlite.Error as e:
            print(f"[!] DB Error: {e}")

        return False

    async def cleanup(self):
        try:
            await self._db.execute("UPDATE outbox SET status='PENDING' WHERE status='PROCESSING'")
            await self._db.execute("DELETE FROM outbox WHERE status='SENT'")
            await self._db.commit()

        except aiosqlite.Error as e:
            print(f"[!] DB Error: {e}")

    def close(self):
        self._db.close()

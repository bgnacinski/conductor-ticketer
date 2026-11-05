from datetime import datetime, timedelta, timezone
from math import ceil
import aiosqlite
import random
import hashlib
import httpx
import uuid
import os

class Outbox:
    db: aiosqlite.Connection
    batch_size = int(os.getenv("BATCH_SIZE") or 500)
     
    def __init__(self, db: aiosqlite.Connection):
        self.db = db
        self.db.row_factory = aiosqlite.Row

    @classmethod
    async def create(cls) -> "Outbox":
        db_file = os.getenv("DB_FILE") or "db/outbox.db"

        try:
            conn = await aiosqlite.connect(db_file)

            await conn.execute("PRAGMA journal_mode = WAL;")
            await conn.execute("PRAGMA synchronous = FULL;")
            await conn.execute("PRAGMA wal_checkpoint(FULL);")

            return cls(db=conn)

        except aiosqlite.OperationalError:
            print(f"[!] Cannot open database from: {db_file}")
            raise
        
    @staticmethod
    async def cleanup() -> None:
        db_file = os.getenv("DB_FILE") or "db/outbox.db"
        
        try:
            conn = await aiosqlite.connect(db_file)
        
            await conn.execute("UPDATE outbox SET status='PENDING' WHERE status='PROCESSING'")
            await conn.execute("DELETE FROM outbox WHERE status='SENT'")
            await conn.commit()
            
            await conn.close()
            
        except aiosqlite.OperationalError:
            print(f"[!] Cannot open database from: {db_file}")
            raise
        
    async def log(self, client_id:bytes):
        """Logs the entry, preparing it for further exchange with the API

        Args:
            client_id (bytes): Serialized client public key
        """
        fingerprint = hashlib.sha256(client_id).hexdigest()
        action_uuid = str(uuid.uuid4())
        action_type = os.getenv("GATE_TYPE") or "exit" # if gate is an exit type by default - by default client wont get chareged
        
        await self.db.execute("INSERT INTO outbox(id, client_fingerprint, action_type) VALUES (?, ?, ?)",
            (action_uuid, fingerprint, action_type))
        
        await self.db.commit()
        
    def _next_retry(self, base: float = 5, cap: float = 900) -> str:
        delay = random.uniform(0, min(base * 2, cap))
        return (datetime.now(timezone.utc) + timedelta(seconds=delay)).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def get_pubkey():
        url = (os.getenv("API_URL") or "http://localhost/api/") + "pubkey"
        api_key = os.getenv("API_KEY") or ""

        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        res = httpx.get(url, headers=headers)
        res_data = res.json()

        if res.is_success:
            return res_data["data"]

        else:
            return None

    @staticmethod
    def get_bans():
        url = (os.getenv("API_URL") or "http://localhost/api/") + "bans"
        api_key = os.getenv("API_KEY") or ""

        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        res = httpx.get(url, headers=headers, params={"output_type": "list"})
        res_data = res.json()
        
        if res.is_success and res_data["status"] == "success":
            return res_data["data"]

        elif res.is_success and res_data["status"] == "nodata":
            return []

        else:
            return None
        
    async def check_client(self, client_id: bytes) -> bool:
        client_fingerprint = hashlib.sha256(client_id).hexdigest()

        cursor = await self.db.execute(
            "SELECT client_fingerprint FROM bans WHERE client_fingerprint = ?",
            (client_fingerprint,),
        )

        if await cursor.fetchone():
            await cursor.close()
            return False
        
        else:
            await cursor.close()
            return True

    async def push(self, bulk:bool=True):
        url = (os.getenv("API_URL") or "http://localhost/api/") + "log"
        api_key = os.getenv("API_KEY") or ""
        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        req_schema = {
            "bulk": bulk,
            "data": []
        }
        
        data_to_send = await self.db.execute_fetchall("""UPDATE outbox SET status = 'PROCESSING'
                WHERE (status = 'PENDING')
                OR (status = 'FAILED' AND (next_retry_at IS NULL OR next_retry_at <= CURRENT_TIMESTAMP))
                RETURNING id, client_fingerprint, action_type, created_at""")
        
        await self.db.commit()
        
        if not data_to_send:
            return
        
        ids_to_send = []
        for row in data_to_send:
            ids_to_send.append(row[0])
        
        data_to_send = tuple(data_to_send)
        unsent = set(ids_to_send)
        
        try:
            if bulk: # sending data in bulk - tries to send all of the elements at once
                no_batches = int(ceil(len(data_to_send) / self.batch_size))
                
                for i in range(1, no_batches+1):
                    batch_data = data_to_send[self.batch_size * (i-1) : self.batch_size * i]
                    batch_ids = ids_to_send[self.batch_size * (i-1) : self.batch_size * i]
                    placeholders = ",".join("?" * len(batch_ids))
                        
                    req_schema["data"] = [dict(r) for r in batch_data]
                    
                    async with httpx.AsyncClient() as client:
                        try:
                            res = await client.post(url, headers=headers, json=req_schema)
                            
                        except httpx.TransportError:
                            print("[!] Exchanger | Unable to connect to the API - aborting")
                            await self.db.execute(f"UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id IN ({placeholders})", ("CONN_ERR", self._next_retry(), *batch_ids))
                            await self.db.commit()
                            
                            unsent.difference_update(batch_ids)
                            
                            return
                                            
                        response = res.json()
                        
                        if res.status_code in (200, 201):
                            await self.db.execute(f"UPDATE outbox SET status='SENT' WHERE id IN ({placeholders})", (*batch_ids,))
                            await self.db.commit()
                            print(f"[*] Exchanger | Successful API push of {len(batch_ids)}/{len(ids_to_send)} elements")
                            unsent.difference_update(batch_ids)
                            
                        elif res.status_code == 207:
                            created = response["created"]
                            duplicates = response["duplicates"]
                            failed = response["failed"]
                            
                            saved_ids = created + duplicates
                            if len(saved_ids) > 0:
                                saved_placeholders = ",".join("?" * len(saved_ids))
                                await self.db.execute(f"UPDATE outbox SET status='SENT' WHERE id IN ({saved_placeholders})", (*saved_ids,))
                                      
                            if len(failed) > 0:
                                fail_placeholders = ",".join("?" * len(failed))
                                await self.db.execute(f"UPDATE outbox SET status='VALERR' WHERE id IN ({fail_placeholders})", (*failed,))
                            
                            await self.db.commit()
                            
                            unsent.difference_update(duplicates, created, failed)
                            
                            print(f"[*] Exchanger | Multi-Status response received. Created elements: {len(created)}, duplicate elements: {len(duplicates)}, failed elements: {len(failed)}")
                            
                    
                        elif res.status_code // 100 == 5:
                            print("[!] Exchanger | API Server HTTP error: ", res.status_code, ". Unable to push data")
                            await self.db.execute(f"UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id IN ({placeholders})", (res.status_code, self._next_retry(), *batch_ids))
                            await self.db.commit()
                            
                            unsent.difference_update(batch_ids)
                            
                            return
                
                        elif res.status_code // 100 == 4:                                                   
                            if res.status_code in (401, 403):
                                print("[!] Exchanger | Authentication failure - unable to push data. HTTP ", res.status_code)
                                await self.db.execute(f"UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id IN ({placeholders})", (res.status_code, self._next_retry(), *batch_ids))
                                await self.db.commit()
                                
                                unsent.difference_update(batch_ids)
                                
                                return
                            
                            elif res.status_code == 409:
                                duplicates = response["duplicates"]
                                dup_placeholders = ", ".join("?" * len(duplicates))
                                
                                print(f"[*] Exchanger | Marking {len(duplicates)} duplicate elements as SENT")
                            
                                await self.db.execute(f"UPDATE outbox SET status='SENT' WHERE id IN ({dup_placeholders})", (*duplicates,))
                                await self.db.commit()
                            
                                unsent.difference_update(duplicates)
                                
                            elif res.status_code == 422:
                                failed_ids = response["failed"]
                                
                                fail_placeholders = ", ".join("?" * len(failed_ids))
                                
                                print(f"[!] Exchanger | HTTP 422 - Permanently removing {len(failed_ids)} from queue due to validation errors.")
                                await self.db.execute(f"UPDATE outbox SET status='VALERR' WHERE id IN ({fail_placeholders})", (*failed_ids, ))
                                await self.db.commit()
                                
                                unsent.difference_update(failed_ids)
                
                            elif res.status_code == 429:
                                print("[!] Exchanger | HTTP 429 - API server is probably overloaded. Aborting data push")
                                await self.db.execute(f"UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id IN ({placeholders})", (res.status_code, self._next_retry(), *batch_ids))
                                await self.db.commit()
                                
                                unsent.difference_update(batch_ids)
                                
                                return
                    
                            else:
                                print(f"[!] Exchanger | HTTP {res.status_code} error")
                                await self.db.execute(f"UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id IN ({placeholders})", (res.status_code, self._next_retry(), *batch_ids))
                                await self.db.commit()
                                
                                unsent.difference_update(batch_ids)
                
            else:
                async with httpx.AsyncClient() as client:
                    for row in data_to_send:
                        req_schema["data"] = dict(row)
                    
                        try:
                            res = await client.post(url, headers=headers, json=req_schema)
                            
                        except httpx.TransportError:
                            print("[!] Exchanger | Unable to connect to the API - aborting")
                            await self.db.execute(f"UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id = ?", ("CONN_ERR", self._next_retry(), row[0]))
                            await self.db.commit()
                            unsent.discard(row[0])
                            
                            return
                        
                        if res.is_success:
                            row_id = row[0]
                            
                            await self.db.execute("UPDATE outbox SET status='SENT' WHERE id = ?", (row_id,))
                            await self.db.commit()
                            
                            unsent.discard(row_id)
                            
                            print(f"[*] Exchanger | Successful API push of element {row_id}")
                        
                        elif res.status_code // 100 == 5:
                            print("[!] Exchanger | API Server HTTP error: ", res.status_code, ". Unable to push data")
                            await self.db.execute("UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id=?", (res.status_code, self._next_retry(), row[0]))
                            await self.db.commit()
                            unsent.discard(row[0])
                            
                            return
                            
                        elif res.status_code // 100 == 4:
                            if res.status_code in (401, 403):
                                print("[!] Exchanger | Authentication failure - unable to push data. HTTP ", res.status_code)
                                await self.db.execute("UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id=?", (res.status_code, self._next_retry(), row[0],))
                                await self.db.commit()
                                
                                unsent.discard(row[0])
                                
                                return
                                
                            elif res.status_code == 429:
                                print("[!] Exchanger | HTTP 429 - API server is probably overloaded. Aborting data push")
                                await self.db.execute("UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id=?", (res.status_code, self._next_retry(), row[0],))
                                await self.db.commit()
                                
                                unsent.discard(row[0])
                                return
                            
                            else:
                                print(f"[!] Exchanger | HTTP {res.status_code} error")
                                await self.db.execute("UPDATE outbox SET status='FAILED', error_message=?, next_retry_at=? WHERE id=?", (res.status_code, self._next_retry(), row[0],))
                                await self.db.commit()
                                
                                unsent.discard(row[0])
                            
        finally:
            if unsent:
                ids = list(unsent)
                placeholders = ",".join("?" * len(ids))
                await self.db.execute(f"UPDATE outbox SET status='PENDING' WHERE id in ({placeholders})", ids)
                await self.db.commit()
                    
    async def close(self):
        await self.db.close()
from math import ceil
import Repositories
import httpx
import os

class Outbox:
    _log_repository: Repositories.LogRepository
    _base_url: str
    _api_key: str
    batch_size: int
     
    def __init__(self, base_url:str, api_key:str, log_repository: Repositories.LogRepository, batch_size: int = 500):
        self._base_url = base_url
        self._api_key = api_key

        self._log_repository = log_repository
        self.batch_size = batch_size

    def _map_log_to_json(self, data:tuple) -> list:
        res = []
        for row in data:
            json_fragment = {
                "id": row[0],
                "client_fingerprint": row[1],
                "action_type": row[2],
                "created_at": row[3]
            }

            res.append(json_fragment)

        return res

    async def push(self, bulk:bool=True):
        url = self._base_url + "log"
        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json"
        }
        req_schema = {
            "bulk": bulk,
            "data": []
        }
        
        data_to_send = await self._log_repository.prepare_api_push()
        if not data_to_send:
            return

        ids_to_send = []
        for row in data_to_send:
            ids_to_send.append(row[0])
        
        data_to_send = tuple(data_to_send)
        unsent = set(ids_to_send)

        async with httpx.AsyncClient() as client:
            try:
                if bulk: # sending data in bulk - tries to send all of the elements at once
                    no_batches = int(ceil(len(data_to_send) / self.batch_size))

                    for i in range(0, no_batches):
                        batch_data = data_to_send[self.batch_size * i : self.batch_size * (i+1)]
                        batch_ids = ids_to_send[self.batch_size * i : self.batch_size * (i+1)]

                        req_schema["data"] = self._map_log_to_json(batch_data)
                    
                        print("sending request")
                        try:
                            res = await client.post(url, headers=headers, json=req_schema)
                            
                        except httpx.TransportError:
                            print("[!] Exchanger | Unable to connect to the API - aborting")
                            await self._log_repository.update_status(batch_ids, "FAILED")
                            unsent.difference_update(batch_ids)
                            
                            return
                                            
                        response = res.json()
                        
                        if res.status_code in (200, 201):
                            result = await self._log_repository.update_status(batch_ids, "SENT")
                            if not result:
                                print("[!] Due to errors, database state may not reflect changes made by API push")
                            print(f"[*] Exchanger | Successful API push of {len(batch_ids)}/{len(ids_to_send)} elements")
                            unsent.difference_update(batch_ids)
                            
                        elif res.status_code == 207:
                            created = response["created"]
                            duplicates = response["duplicates"]
                            failed = response["failed"]
                            
                            saved_ids = created + duplicates
                            if len(saved_ids) > 0:
                                result = await self._log_repository.update_status(saved_ids, "SENT")
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")

                            if len(failed) > 0:
                                result = await self._log_repository.update_status(failed, "VALERR")
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")

                            unsent.difference_update(duplicates, created, failed)
                            
                            print(f"[*] Exchanger | Multi-Status response received. Created elements: {len(created)}, duplicate elements: {len(duplicates)}, failed elements: {len(failed)}")
                            
                    
                        elif res.status_code // 100 == 5:
                            print("[!] Exchanger | API Server HTTP error: ", res.status_code, ". Unable to push data")
                            result = await self._log_repository.retard_sync(batch_ids)
                            if not result:
                                print("[!] Due to errors, database state may not reflect changes requested by the API response")

                            unsent.difference_update(batch_ids)
                            
                            return
                
                        elif res.status_code // 100 == 4:                                                   
                            if res.status_code in (401, 403):
                                print("[!] Exchanger | Authentication failure - unable to push data. HTTP ", res.status_code)

                                result = await self._log_repository.retard_sync(batch_ids)
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")

                                unsent.difference_update(batch_ids)

                                return
                            
                            elif res.status_code == 409:
                                duplicates = response["duplicates"]

                                print(f"[*] Exchanger | Marking {len(duplicates)} duplicate elements as SENT")

                                result = await self._log_repository.update_status(duplicates, "SENT")
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")

                                unsent.difference_update(duplicates)
                                
                            elif res.status_code == 422:
                                failed_ids = response["failed"]

                                print(f"[!] Exchanger | HTTP 422 - Permanently removing {len(failed_ids)} from queue due to validation errors.")
                                result = await self._log_repository.update_status(failed_ids, "VALERR")
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")

                                unsent.difference_update(failed_ids)
                
                            elif res.status_code == 429:
                                print("[!] Exchanger | HTTP 429 - API server is probably overloaded. Aborting data push")
                                result = await self._log_repository.retard_sync(batch_ids)
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")
                                
                                unsent.difference_update(batch_ids)
                                
                                return
                    
                            else:
                                print(f"[!] Exchanger | HTTP {res.status_code} error")
                                result = await self._log_repository.retard_sync(batch_ids)
                                if not result:
                                    print("[!] Due to errors, database state may not reflect changes requested by the API response")
                                
                                unsent.difference_update(batch_ids)
                
                else:
                    for row in data_to_send:
                        req_schema["data"] = list(row)
                        row_id = row[0]
                    
                        try:
                            res = await client.post(url, headers=headers, json=req_schema)
                            
                        except httpx.TransportError:
                            print("[!] Exchanger | Unable to connect to the API - aborting")
                            result = await self._log_repository.retard_sync([row_id])
                            if not result:
                                print("[!] Due to errors, database state may not reflect changes requested by the API response")

                            unsent.discard(row_id)
                            
                            return
                        
                        if res.is_success:
                            result = await self._log_repository.update_status([row_id], "SENT")
                            if not result:
                                print("[!] Due to errors, database state may not reflect changes requested by the API response")

                            unsent.discard(row_id)
                            
                            print(f"[*] Exchanger | Successful API push of element {row_id}")
                        
                        elif res.status_code // 100 == 5:
                            print("[!] Exchanger | API Server HTTP error: ", res.status_code, ". Unable to push data")

                            result = await self._log_repository.update_status([row_id], "FAILED")
                            if not result:
                                print("[!] Due to errors, database state may not reflect changes requested by the API response")

                            unsent.discard(row_id)
                            return
                            
                        elif res.status_code // 100 == 4:
                            result = await self._log_repository.update_status([row_id], "FAILED")
                            if not result:
                                print(
                                    "[!] Due to errors, database state may not reflect changes requested by the API response")

                            unsent.discard(row_id)

                            if res.status_code in (401, 403):
                                print("[!] Exchanger | Authentication failure - unable to push data. HTTP ", res.status_code)

                                return
                                
                            elif res.status_code == 429:
                                print("[!] Exchanger | HTTP 429 - API server is probably overloaded. Aborting data push")
                                return
                            
                            else:
                                print(f"[!] Exchanger | HTTP {res.status_code} error")

            finally:
                if unsent:
                    ids = list(unsent)
                    result = await self._log_repository.update_status(ids, "PENDING")

                    if not result:
                        print("[!] Outbox table is left in an unstable state!")

        await self._log_repository.cleanup()
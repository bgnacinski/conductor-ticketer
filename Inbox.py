import Repositories
import httpx
import os

class Inbox:
    _ban_repository: Repositories.BanRepository
    _base_url: str
    _api_key: str

    def __init__(self, ban_repository: Repositories.BanRepository, base_url: str, api_key: str):
        self._ban_repository = ban_repository
        self._base_url = base_url
        self._api_key = api_key

    async def fetch_pubkey(self):
        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json"
        }

        url = self._base_url + "pubkey"

        async with httpx.AsyncClient(headers=headers) as client:
            res = await client.get(url, headers=headers)
            res_data = res.json()

            if res.is_success:
                return res_data["data"]

            else:
                return None

    async def fetch_bans(self):
        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json"
        }
        url = self._base_url + "bans"

        async with httpx.AsyncClient(headers=headers) as client:
            res = await client.get(url, headers=headers, params={"output_type": "list"})
            res_data = res.json()

            if res.is_success and res_data["status"] == "success":
                return res_data["data"]

            elif res.is_success and res_data["status"] == "nodata":
                return []

            else:
                return None


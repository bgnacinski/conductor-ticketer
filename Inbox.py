from cryptography.hazmat.primitives import serialization
from Repositories import BanRepository
import base64
import httpx
import os
from loguru import logger

class Inbox:
    _ban_repository: BanRepository
    _base_url: str
    _api_key: str
    _ca_public_key_file: str

    def __init__(self, base_url: str, api_key: str, ban_repository: BanRepository, ca_public_key_file: str):
        self._base_url = base_url
        self._api_key = api_key
        self._ban_repository = ban_repository
        self._ca_public_key_file = ca_public_key_file

    async def fetch_pubkey(self) -> None:
        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json"
        }

        url = self._base_url + "pubkey"

        valid_pubkey = False

        try:
            async with httpx.AsyncClient(headers=headers) as client:
                res = await client.get(url)
                res_data = res.json()

                if res.is_success:
                    try:
                        pubkey = base64.b64decode(res_data["data"])
                        # if it fails -> pubkey not valid
                        serialization.load_ssh_public_key(pubkey)

                        with open(self._ca_public_key_file, "wb") as file:
                            file.write(pubkey)
                            file.close()

                        valid_pubkey = True
                        logger.info("CA public key retrieved and saved successfully")

                    except Exception as e:
                        valid_pubkey = False
                        logger.warning(f"Cannot save the retrieved key due to errors: {e}. Trying to use existing key...")

        except Exception as e:
            logger.error(f"An error during API querying occurred: {e}")

        if not valid_pubkey:
            with open(self._ca_public_key_file, "rb") as file:
                pubkey_raw = file.read()
                try:
                    serialization.load_ssh_public_key(pubkey_raw)
                    logger.warning("Unable to retrieve public key from API, using the old one.")

                except Exception as e:
                    logger.critical("Unable to load any public key due to errors. Quitting...")
                    raise e

    async def fetch_bans(self) -> None:
        headers = {
            "User-Agent": os.getenv("User-Agent") or "Ticketer/unknown",
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json"
        }
        url = self._base_url + "bans"

        try:
            async with httpx.AsyncClient(headers=headers) as client:
                res = await client.get(url, params={"output_type": "list"})
                res_data = res.json()

                if res.is_success:
                    await self._ban_repository.clear_bans()

                    if res_data["status"] == "success":
                        await self._ban_repository.ban_bulk(res_data["data"])

                    logger.info("Ban list retrieved and updated successfully")

                else:
                    logger.warning("Failed to retrieve ban list from API")

        except Exception as e:
            logger.error(f"An error occurred while fetching bans: {e}")

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from Repositories import BanRepository, LogRepository
from Outbox import Outbox
import hashlib
import time
import asyncio
import os

class Client:
    _cert: serialization.SSHCertificate
    _ca_pubkey: serialization.SSHPublicKeyTypes
    public_key: serialization.SSHCertPublicKeyTypes
    public_key_raw: bytes
    fingerprint: str

    MIN_RSA_KEY_SIZE = 2048
    MIN_ECDSA_KEY_SIZE = 256

    def __init__(self, ca_public_key:serialization.SSHPublicKeyTypes, cert_raw:bytes):
        cert_to_be = serialization.load_ssh_public_identity(cert_raw.strip())
        if not isinstance(cert_to_be, serialization.SSHCertificate):
            raise TypeError("Certificate must be of type SSHCertificate")

        self._cert = cert_to_be
        self._ca_pubkey = ca_public_key

        self.public_key = cert_to_be.public_key()
        self.public_key_raw = serialization.ssh.serialize_ssh_public_key(self.public_key)
        self.fingerprint = self._fingerprint()

    def _fingerprint(self):
        return hashlib.sha256(self.public_key_raw).hexdigest()

    def is_cert_valid(self) -> bool:
        """Used to determine if the certificate is valid.
        It checks if the signature key matches CA public key and certificate expiration date"""
        try:
            self._cert.verify_cert_signature()

            if self._cert.signature_key() != self._ca_pubkey:
                print("[!] Client Handler | Invalid certificate - not signed by CA!")
                return False

            if self._cert.valid_after <= time.time() <= self._cert.valid_before:
                print("[*] Client Handler | Valid certificate")

                return True

            else:
                print(f"[!] Client Handler | Certificate expired (valid between {self._cert.valid_after}-{self._cert.valid_before})!")
                return False

        except InvalidSignature:
            print("[!] Client Handler | Invalid certificate - wrong signature")
            return False
        except Exception as e:
            print(f"[!] Client Handler | Certificate verification error: {e!r}")
            return False

    def is_key_algo_secure(self) -> bool:
        """
        Used to detect weak key algorithms
        """
        if isinstance(self.public_key, ed25519.Ed25519PublicKey):
            return True

        elif isinstance(self.public_key, ec.EllipticCurvePublicKey) and self.public_key.key_size >= self.MIN_ECDSA_KEY_SIZE:
            return True

        elif isinstance(self.public_key, rsa.RSAPublicKey) and self.public_key.key_size >= self.MIN_RSA_KEY_SIZE:
            return True

        return False

    def verify_signature(self, nonce: bytes, response: bytes) -> bool:
        """Verify the signature against the CAs public key"""
        # move key checking logic into is_key_algo_secure - it seems redundant as is
        try:
            if isinstance(self.public_key, ed25519.Ed25519PublicKey):
                self.public_key.verify(response, nonce)
                return True

            elif isinstance(self.public_key, ec.EllipticCurvePublicKey):
                if self.public_key.key_size <= 256:
                    hash_algo = hashes.SHA256()
                elif self.public_key.key_size <= 384:
                    hash_algo = hashes.SHA384()
                else:
                    hash_algo = hashes.SHA512()

                self.public_key.verify(response, nonce, ec.ECDSA(hash_algo))
                return True

            elif isinstance(self.public_key, rsa.RSAPublicKey) and self.public_key.key_size >= self.MIN_RSA_KEY_SIZE:
                try:
                    self.public_key.verify(
                        response,
                        nonce,
                        padding.PKCS1v15(),
                        hashes.SHA512()
                    )
                except InvalidSignature:
                    self.public_key.verify(
                        response,
                        nonce,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )

                return True

        except Exception as e:
            print(f"[!] Exception raised: {e}")

        return False

class Gate:
    nonce_size: int
    public_key: serialization.SSHPublicKeyTypes
    _outbox: Outbox
    _ban_repository: BanRepository
    _log_repository: LogRepository

    gate_type: str

    def __init__(self, gate_type:str, log_repository: LogRepository, ban_repository: BanRepository, nonce_size:int=16, ca_pubkey_file="crypto/ca_key.pub"):
        self.gate_type = gate_type
        if self.gate_type.lower() not in ["entry", "exit"]:
            self.gate_type = "exit"

        self.nonce_size = nonce_size
        self._ban_repository = ban_repository
        self._log_repository = log_repository

        with open(ca_pubkey_file, "rb") as f:
            self._ca_pubkey = serialization.load_ssh_public_key(f.read())

    async def client_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        print("[*] Client Handler | Client connected! Waiting for public key...", end=" ")
        client_cert_raw = await reader.read(1024)
        print(f"received public key (length: {len(client_cert_raw.strip())})")

        try:
            client = Client(self._ca_pubkey, client_cert_raw)
            if await self._ban_repository.is_banned(client.fingerprint):
                writer.write(b"FAIL")
                await writer.drain()
                print("[!] Client Handler | Client is banned!")
                return

            # check client pubkey
            if not client.is_cert_valid():
                print("[!] Client Handler | Certificate not valid!")
                raise InvalidSignature

            if not client.is_key_algo_secure():
                raise UnsupportedAlgorithm

            # send NONCE to client
            nonce = os.urandom(self.nonce_size)
            writer.write(nonce)
            await writer.drain()

            response = await reader.read(1024)

            if client.verify_signature(nonce, response):
                result = await self._log_repository.append_log(client.public_key_raw, self.gate_type)
                if not result:
                    print("[!] Log entry may have not been created.")

                print("[*] Client Handler | OK. Gate open")
                writer.write(b"OK")
                await writer.drain()

            else:
                raise InvalidSignature

        except (InvalidSignature, UnsupportedAlgorithm) as e:
            if isinstance(e, InvalidSignature):
                print(f"[!] Client Handler | Invalid signature")
            else:
                print(f"[!] Client Handler | Unsupported key algorithm or unsupported key length")

            writer.write(b"FAIL")
            await writer.drain()

        finally:
            writer.close()
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
from cryptography.exceptions import InvalidSignature
from Outbox import Outbox
from Inbox import Inbox
import time
import asyncio
import os

class Client:
    _cert: serialization.SSHCertificate
    _ca_pubkey: serialization.SSHPublicKeyTypes
    public_key: serialization.SSHCertPublicKeyTypes

    MIN_RSA_KEY_SIZE = 2048
    MIN_ECDSA_KEY_SIZE = 256

    def __init__(self, ca_public_key:serialization.SSHPublicKeyTypes, cert_raw:bytes):
        cert_to_be = serialization.load_ssh_public_identity(cert_raw.strip())
        if not isinstance(cert_to_be, serialization.SSHCertificate):
            raise TypeError("Certificate must be of type SSHCertificate")

        self._cert = cert_to_be
        self.public_key = cert_to_be.public_key()
        self._ca_pubkey = ca_public_key

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

    def __init__(self, nonce_size:int=16, ca_pubkey_file="crypto/ca_key.pub"):
        self.nonce_size = nonce_size
        with open(ca_pubkey_file, "rb") as f:
            self._ca_pubkey = serialization.load_ssh_public_key(f.read())

    async def client_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        print("[*] Client Handler | Client connected! Waiting for public key...", end=" ")
        client_cert_raw = await reader.readline()
        print(f"received public key (length: {len(client_cert_raw.strip())})")

        try:
            client = Client(self._ca_pubkey, client_cert_raw)

            # check client pubkey
            if not client.is_cert_valid():
                pass

            if not client.is_key_algo_secure():
                pass

            # send NONCE to client
            nonce = os.urandom(self.nonce_size)
            writer.write(nonce)
            await writer.drain()

            response = await reader.read(1024)

            if client.verify_signature(nonce, response):
                outbox = await Outbox.create()
                loaded_key = ssh.serialize_ssh_public_key(client.public_key)

                if await Inbox.check_client(loaded_key):
                    await outbox.log(loaded_key)

                    print("[*] Client Handler | OK. Gate open")
                    writer.write(b"OK")
                    await writer.drain()

                else:
                    print("[*] Client Handler | BANNED!")
                    writer.write(b"BANNED")
                    await writer.drain()

            else:
                raise InvalidSignature

        except InvalidSignature:
            print(f"[!] Client Handler | Invalid signature")
            writer.write(b"FAIL")
            await writer.drain()
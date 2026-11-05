from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
from cryptography.exceptions import InvalidSignature 
from Exchanger import Outbox
import aiosqlite
import base64
import asyncio
import time
import os

BULK_PUSH = str(os.getenv("BULK_PUSH")).lower() in ("true", "yes")
PUSH_INTERVAL = int(os.getenv("PUSH_INTERVAL") or 1800)
SETUP_INTERVAL = int(os.getenv("SETUP_INTERVAL")or 86400)
NONCE_SIZE = int(os.getenv("NONCE_SIZE") or 16)
MIN_RSA_KEY_SIZE = 2048
MIN_ECDSA_KEY_SIZE = 256
ALLOWED_KEY_TYPES = [
    rsa.RSAPublicKey,
    ed25519.Ed25519PublicKey,
    ec.EllipticCurvePublicKey
]
PUBKEY = ""

def is_key_algo_secure(pubkey: serialization.SSHCertPublicKeyTypes) -> bool:
    """
    Used to detect weak key algorithms
    """
    global ALLOWED_KEY_TYPES
    global MIN_RSA_KEY_SIZE
    global MIN_ECDSA_KEY_SIZE
    
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return True

    elif isinstance(pubkey, ec.EllipticCurvePublicKey) and pubkey.key_size >= MIN_ECDSA_KEY_SIZE:
        return True
    
    elif isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size >= MIN_RSA_KEY_SIZE:
        return True
        
    return False

def is_cert_valid(cert) -> bool:
    global PUBKEY
    
    if not isinstance(cert, ssh.SSHCertificate):
        print("[!] Client Handler | Received data is not a certificate")
        return False
    
    try:
        cert.verify_cert_signature()
        
        if cert.signature_key() != PUBKEY:
            print("[!] Client Handler | Invalid certificate - not signed by CA!")
            return False
        
        if cert.valid_after <= time.time() <= cert.valid_before:
            print("[*] Client Handler | Valid certificate")
 
            return True
        
        else:
            print(f"[!] Client Handler | Certificate expired (valid between {cert.valid_after}-{cert.valid_before})!")
            return False
    
    except InvalidSignature:
        print("[!] Client Handler | Invalid certificate - wrong signature")
        return False
    except Exception as e:
        print(f"[!] Client Handler | Certificate verification error: {e!r}")
        return False
    
def verify_signature(pubkey: serialization.SSHCertPublicKeyTypes, nonce:bytes, response: bytes) -> bool:
    try:
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(response, nonce)
            return True
        
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            if pubkey.key_size <= 256:
                hash_algo = hashes.SHA256()
            elif pubkey.key_size <= 384:
                hash_algo = hashes.SHA384()
            else:
                hash_algo = hashes.SHA512()
                
            pubkey.verify(response, nonce, ec.ECDSA(hash_algo))
            return True
            
        elif isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size >= MIN_RSA_KEY_SIZE:
            try:
                pubkey.verify(
                    response,
                    nonce,
                    padding.PKCS1v15(),
                    hashes.SHA512()
                )
            except InvalidSignature:
                pubkey.verify(
                    response,
                    nonce,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                
            return True
        
    except:
        return False
    
    return False
    
async def client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    print("[*] Client Handler | Client connected! Waiting for public key...", end=" ")
    client_cert_raw = await reader.readline()
    print(f"received public key (length: {len(client_cert_raw.strip())})")
    
    try:
        # serialize client certificate
        client_cert = serialization.load_ssh_public_identity(client_cert_raw.strip())
        
        if not isinstance(client_cert, serialization.SSHCertificate):
            writer.write(b"INVALID_CERT")
            await writer.drain()
            return
        
        client_pubkey = client_cert.public_key()
        
        # check certificate
        if not is_cert_valid(client_cert):
            writer.write(b"INVALID_CERT")
            await writer.drain()
            return
                
        # check key algo
        if not is_key_algo_secure(client_pubkey):
            writer.write(b"KEY_NOT_SECURE")
            await writer.drain()
            return
        
        nonce = os.urandom(NONCE_SIZE)
        
        writer.write(nonce)
        await writer.drain()
        
        response = await reader.read(1024)

        if verify_signature(client_pubkey, nonce, response):
            outbox = await Outbox.create()
            loaded_key = ssh.serialize_ssh_public_key(client_pubkey)
            
            if await outbox.check_client(loaded_key):
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
        
async def gate_handler():
    global PUBKEY
    with open("crypto/ca_key.pub", "rb") as f:
        PUBKEY = serialization.load_ssh_public_key(f.read())
        
    print("[*] Gate Handler | Starting...")

    await Outbox.cleanup()
    outbox = await Outbox.create()
    
    sync_task = asyncio.create_task(sync_with_api(outbox))
    setup_task = asyncio.create_task(setup_loop())
    
    try:
        server = await asyncio.start_server(client_handler, "localhost", 2137)    

        await server.serve_forever()
        print("[*] Gate Handler | Waiting for clients...")
        
    finally:
        sync_task.cancel()
        setup_task.cancel()
            
        await outbox.close()

async def sync_with_api(outbox: Outbox):
    print("[*] Exchanger | Starting...")
    while True:
        try:
            await outbox.push(BULK_PUSH)
            
        except Exception as e:
            print(f"[!] Exchanger | Exception during sync occurred: {e}")
            
        await asyncio.sleep(PUSH_INTERVAL)

async def prepare_dbs(db):
    print("[*] Preparing DBs...", end=" ")

    await db.execute("""
                     CREATE TABLE IF NOT EXISTS "outbox"
                     (
                         id                 TEXT PRIMARY KEY,
                         client_fingerprint TEXT NOT NULL,
                         action_type        TEXT NOT NULL CHECK (action_type IN ('entry', 'exit')),
                         created_at         DATETIME                                                                              DEFAULT CURRENT_TIMESTAMP,
                         status             TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'FAILED', 'SENT', 'VALERR')) DEFAULT 'PENDING',
                         next_retry_at      DATETIME,
                         error_message      TEXT
                     )""")
    await db.execute("""
                     CREATE TABLE IF NOT EXISTS "bans"
                     (
                         client_fingerprint BLOB not null
                             constraint bans_pk primary key
                     )""")

    await db.commit()

    print("done.")

async def setup():
    db_file = os.getenv("DB_FILE") or "outbox.db"
    pubkey_file = os.getenv("PUB_KEY") or "crypto/ca_key.pub"
    
    # setup tables
    db = await aiosqlite.connect(db_file)
    await prepare_dbs(db)

    # (try to) get pubkey from API, (try to) get ban list from API
    # get CA pubkey
    valid_pubkey = False

    print("[*] Retrieving CA's public key from API...", end=" ")
    pubkey = await Outbox.get_pubkey()
    if pubkey:
        try:
            # if it fails -> pubkey not valid
            serialization.load_ssh_public_key(base64.b64decode(pubkey))
            
            with open(pubkey_file, "wb") as file:
                file.write(base64.b64decode(pubkey))
                file.close()
                
            valid_pubkey = True   
            print("done!")
            
        except Exception as e:
            valid_pubkey = False
            print(f"[!] Cannot save the retrieved key due to errors: {e}. Trying to use existing key...", end=" ")
            
    if not valid_pubkey:
        with open(pubkey_file, "rb") as file:
            pubkey_raw = file.read()
            try:
                serialization.load_ssh_public_key(pubkey_raw)
                print("[!] Unable to retrieve public key from API, using the old one.")
            except Exception as e:
                print("[!] Unable to load any public key due to errors. Quitting...")
                raise e
            
    # get bans
    print("[*] Retrieving ban list from API...", end=" ")
    bans = await Outbox.get_bans()
    if bans:
        await db.execute("DELETE FROM bans")
        for ban in bans:
            await db.execute("INSERT INTO bans VALUES (?)", (ban,))

        await db.commit()
            
        print("done!")

    elif bans == []:
        print("No clients are banned - clearing the bans table...", end=" ")

        await db.execute("DELETE FROM bans")
        await db.commit()
            
        print("done!")
            
    else:
        print("Unable to retrieve banned clients - using the saved list.")

async def setup_loop():
    while True:
        await asyncio.sleep(SETUP_INTERVAL)

        await setup()

if __name__ == "__main__":
    asyncio.run(setup())
    asyncio.run(gate_handler())
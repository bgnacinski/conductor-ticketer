from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
from cryptography.exceptions import InvalidSignature 
from Exchanger import Outbox
import time
import asyncio
import os

BULK_PUSH = str(os.getenv("BULK_PUSH")).lower() in ("true", "yes")
PUSH_INTERVAL = int(str(os.getenv("PUSH_INTERVAL"))) or 1800
CHALL_SIZE = int(str(os.getenv("NONCE_SIZE"))) or 16
MIN_RSA_KEY_SIZE = 2048
MIN_ECDSA_KEY_SIZE = 256
ALLOWED_KEY_TYPES = [
    rsa.RSAPublicKey,
    ed25519.Ed25519PublicKey,
    ec.EllipticCurvePublicKey
]

with open("crypto/ca_key.pub", "rb") as f:
    PUBKEY = serialization.load_ssh_public_key(f.read())

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
        print("[!] Received data is not a certificate")
        return False
    
    try:
        cert.verify_cert_signature()
        
        if cert.signature_key() != PUBKEY:
            print("[!] Invalid certificate - not signed by us!")
            return False
        
        if cert.valid_after <= time.time() <= cert.valid_before:
            print("[*] Valid certificate")
 
            return True
        
        else:
            return False
    
    except InvalidSignature:
        print("[!] Invalid certificate - wrong signature")
        return False
    except Exception as e:
        print(f"[!] Certificate verification error: {e!r}")
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
    print("[*] Client connected! Waiting for public key...")
    client_cert_raw = await reader.readline()
    print("[*] Recieved public key, key length: ", len(client_cert_raw.strip()))
    
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
        
        nonce = os.urandom(CHALL_SIZE)
        
        writer.write(nonce)
        await writer.drain()
        
        response = await reader.read(1024)

        if verify_signature(client_pubkey, nonce, response):
            outbox = await Outbox.create()
            await outbox.log(ssh.serialize_ssh_public_key(client_pubkey))
            
            print("[*] OK. Gate open")
            writer.write(b"OK")
            await writer.drain()
            
        else:
            raise InvalidSignature
        
    except InvalidSignature:
        print(f"[!] Invalid signature")
        writer.write(b"FAIL")
        await writer.drain()
        
async def main(): 
    await Outbox.cleanup()
    outbox = await Outbox.create()
    
    sync_task = asyncio.create_task(sync_with_api(outbox))
    
    try:
        server = await asyncio.start_server(client_handler, "localhost", 2137)    

        await server.serve_forever()
        
    finally:
        sync_task.cancel()
            
        await outbox.close()
    
async def sync_with_api(outbox: Outbox):
    while True:
        try:
            await outbox.push(BULK_PUSH)
            
        except Exception as e:
            print(f"[!] Exception during sync occured: {e}")
            
        await asyncio.sleep(PUSH_INTERVAL)
    
asyncio.run(main())
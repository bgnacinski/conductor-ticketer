from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
from cryptography.exceptions import InvalidSignature 
import asyncio
import os

CHALL_SIZE = 16
MIN_RSA_KEY_SIZE = 2048
MIN_ECDSA_KEY_SIZE = 256
ALLOWED_KEY_TYPES = [
    rsa.RSAPublicKey,
    ed25519.Ed25519PublicKey,
    ec.EllipticCurvePublicKey
]

with open("crypto/ca_key.pub", "rb") as f:
    PUBKEY = serialization.load_ssh_public_key(f.read())

async def data_pusher():
    pass

def get_fingerprint(pubkey: serialization.SSHCertPublicKeyTypes) -> str:
    """
    Generate a SHA256 fingerprint from user's public key
    """
    return str(serialization.ssh_key_fingerprint(pubkey, hashes.SHA256()))

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
        print("[*] Valid certificate")
 
        return True
    
    except:
        print("[!] Invalid certificate")
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
    print(client_cert_raw)
    print("[*] Recieved public key, key length: ", len(client_cert_raw.strip()))
    
    try:
        # serialize client certificate
        client_cert = serialization.load_ssh_public_identity(client_cert_raw.strip())
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
            print("[*] OK. Gate open")
            writer.write(b"OK")
            await writer.drain()
            
        else:
            raise InvalidSignature
        
    except Exception as e:
        print(f"[!] Other error: {e}")
        writer.write(b"FAIL")
        await writer.drain()
        
async def main(): 
    server = await asyncio.start_server(client_handler, "localhost", 2137)    

    await server.serve_forever()

asyncio.run(main())
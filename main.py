from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
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

async def data_pusher():
    pass

def get_fingerprint(pubkey: serialization.SSHPublicKeyTypes) -> str:
    """
    Generate a SHA256 fingerprint from user's public key
    """
    return str(serialization.ssh_key_fingerprint(pubkey, hashes.SHA256()))

def is_key_algo_secure(pubkey: serialization.SSHPublicKeyTypes) -> bool:
    """
    Used to detect weak key algorithms
    """
    global ALLOWED_KEY_TYPES
    global MIN_RSA_KEY_SIZE
    global MIN_ECDSA_KEY_SIZE
    
    if type(pubkey) in ALLOWED_KEY_TYPES:
        if type(pubkey) == rsa.RSAPublicKey and pubkey.key_size < MIN_RSA_KEY_SIZE:
            return False
        
        elif type(pubkey) == ec.EllipticCurvePublicKey and pubkey.key_size < MIN_ECDSA_KEY_SIZE:
            return False
        
        else:
            return True
    
    else:
        return False
    
def verify_signature(pubkey: serialization.SSHPublicKeyTypes, response: bytes) -> bool:
    pass

async def client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    print("[*] Client connected! Waiting for public key...")
    client_pubkey_raw = await reader.readline()
    print("[*] Recieved public key, key length: ", len(client_pubkey_raw))
    
    try:
        # serialize client public key
        client_pubkey = serialization.load_ssh_public_key(client_pubkey_raw.strip())
        
        # check key algorithm
        if not is_key_algo_secure(client_pubkey):
            writer.write(b"")
        
        challenge = os.urandom(CHALL_SIZE)
        
        writer.write(challenge)
        await writer.drain()
        
        response = await reader.read(1024)

        if verify_signature(client_pubkey, response):
            print("[*] OK. Bramka otwarta")
            writer.write(b"OK")
            await writer.drain()
            
        else:
            raise InvalidSignature
        
    except InvalidSignature:
        print("[!] FAIL. Bramka zamknięta")
        writer.write(b"FAIL")
        await writer.drain()
        
async def main(): 
    server = await asyncio.start_server(client_handler, "localhost", 2137)    

    await server.serve_forever()

asyncio.run(main())
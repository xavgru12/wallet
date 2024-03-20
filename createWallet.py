import ecdsa
import codecs
import hashlib
import base58
from Crypto.Hash import RIPEMD160
import qrcode
import datetime

def generate_secp256k1_keypair():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.verifying_key
    private_key_bytes = private_key.to_string()
    public_key_bytes = public_key.to_string("compressed") # pyright: ignore
    private_key_hex = codecs.encode(private_key_bytes, 'hex').decode()
    public_key_hex = codecs.encode(public_key_bytes, 'hex').decode()
    return private_key_hex, public_key_hex

def pubkey_to_address(pubkey_hex):
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = RIPEMD160.new(sha256).digest()
    version = b'\x00'  # Use '\x00' for mainnet addresses
    payload = version + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    full_payload = payload + checksum

    address = base58.b58encode(full_payload).decode('utf-8')
    return address


private_key_hex, public_key_hex = generate_secp256k1_keypair()

print("Private Key (hex):", private_key_hex)
print("Public Key (hex, compressed 33 bytes):", public_key_hex)
address = pubkey_to_address(public_key_hex)
print(f"address: {address}")

img = qrcode.make(address)
timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
file_name = f"address-{timestamp}"
img.save(file_name)


with open (f"secrets-{timestamp}.txt", "w+") as f:
    f.write(f"private key: {private_key_hex}\n")

    f.write(f"public_key_hex: {public_key_hex}\n")

    f.write(f"address: {address}\n")

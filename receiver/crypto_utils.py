from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import unpad
import os

def generate_rsa_keys(private_key_path="receiver_private.pem", public_key_path="receiver_public.pem", key_size=2048):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("✅ RSA keys already exist. Skipping generation.")
        return

    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_key_path, "wb") as f:
        f.write(private_key)

    with open(public_key_path, "wb") as f:
        f.write(public_key)

    print("🔐 RSA key pair generated.")


def decrypt_rsa(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    """
    Decrypts data using the RSA private key with OAEP padding.
    """
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

def decrypt_aes_key_packet(encrypted_packet: bytes, private_key_path="receiver_private.pem") -> tuple[bytes, bytes]:
    """
    Decrypts the RSA_KEY packet sent by the sender. Returns (aes_key, nonce).
    Assumes the sender encrypted (aes_key + nonce) using receiver's public key.
    """
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    # RSA decryption
    decrypted_blob = decrypt_rsa(encrypted_packet, private_key)

    # Assuming AES key is 32 bytes (AES-256), nonce is 16 bytes
    aes_key = decrypted_blob[:32]
    nonce = decrypted_blob[32:48]
    return aes_key, nonce

def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts AES-encrypted data using the provided AES key and IV.
    Assumes AES in CBC mode and PKCS7 padding.
    """
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher_aes.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)

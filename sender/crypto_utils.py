import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from sender.state_manager import SenderState

def generate_aes_key_and_nonce(state: SenderState):
    """
    Generates a random AES key and nonce for secure encryption.
    """
    # NOTE: nonce (number used once) is a one-time-use value. 
    # It ensures that encrypting same data twice produces different ciphertexts, preventing replay and pattern attacks.

    state.aes_key = get_random_bytes(32)  # AES-256
    state.aes_nonce = get_random_bytes(16)
    print("🔐 AES key and nonce generated.")

def encrypt_aes_key_with_rsa(state: SenderState):
    """
    Encrypts the AES key and nonce using the receiver's RSA public key.
    """
    if not state.rsa_receiver_key:
        raise ValueError("Missing receiver RSA key")

    if not state.aes_key or not state.aes_nonce:
        raise ValueError("Missing AES key or nonce")
    
    combined = state.aes_key + state.aes_nonce  # 32 + 16 = 48 bytes
    cipher_rsa = PKCS1_OAEP.new(state.rsa_receiver_key)
    encrypted_key = cipher_rsa.encrypt(combined)

    #FOR DEBUGGING
    #print(f"[DEBUG] AES key length: {len(state.aes_key)}, nonce length: {len(state.aes_nonce)}")
    #print(f"[DEBUG] Combined length: {len(combined)}")
    #print(f"[DEBUG] Encrypted RSA payload length: {len(encrypted_key)}")  # Should be 256

    return encrypted_key

def encrypt_metadata(state: SenderState, ttl: int = 60):
    """
    Encrypts metadata (filename, filesize, TTL) using AES (EAX mode).
    Returns: nonce + ciphertext
    """
    metadata = {
        "filename": state.filename,
        "filesize": state.filesize,
        "ttl": ttl
    }
    cipher = AES.new(state.aes_key, AES.MODE_EAX, nonce=state.aes_nonce)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(metadata).encode())
    return state.aes_nonce + tag + ciphertext


def load_receiver_rsa_key(path: str) -> RSA.RsaKey:
    """
    Loads the receiver's RSA public key from file.
    """
    with open(path, 'rb') as f:
        key_data = f.read()
    rsa_key = RSA.import_key(key_data)
    print("🔑 Receiver RSA public key loaded.")
    return rsa_key

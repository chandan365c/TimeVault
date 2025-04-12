import os
from Cryptodome.Cipher import AES
from sender.constants import WINDOW_SIZE, TIMEOUT, CHUNK_SIZE

class SenderState:
    def __init__(self):
        self.state = "IDLE"
        self.receiver_addr = None

        # File details
        self.filename = None
        self.filesize = None
        self.file_chunks = []
        self.chunk_count = 0
        self.chunk_size = CHUNK_SIZE
        self.delete_after = 60

        # Cryptography
        self.rsa_receiver_key = None
        self.aes_key = None
        self.aes_nonce = None

        # Sliding window / ACKs
        self.window_size = WINDOW_SIZE
        self.timeout = TIMEOUT
        self.sent_chunks = {}               # seq_num -> last sent time
        self.acknowledged_chunks = set()
        self.last_sent_time = {}
        self.unacked_chunks = set()
        self.total_chunks = 0

        # Control flags
        self.ack_syn_received = False
        self.ack_aes_received = False
        self.ack_meta_received = False
        self.ack_fin_received = False
        self.transfer_complete = False

    def load_file(self, filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        self.filename = os.path.basename(filepath)
        self.filesize = os.path.getsize(filepath)
        self.file_chunks = []

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                self.file_chunks.append(chunk)

        self.chunk_count = len(self.file_chunks)
        print(f"📄 File loaded: {self.filename} ({self.filesize} bytes in {self.chunk_count} chunks)")

    def encrypt_chunk(self, chunk):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        return cipher.nonce + cipher.encrypt(chunk)

    def reset(self):
        print("♻️ Resetting sender state...")
        self.__init__()

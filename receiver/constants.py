from enum import IntEnum

class PacketType(IntEnum):
    SYN = 1
    ACK_SYN = 2
    RSA_KEY = 3
    AES_KEY = 4
    ACK_AES = 5
    META = 6
    ACK_META = 7
    DATA = 8    
    ACK = 9
    FIN = 10
    ACK_FIN = 11

    DISCOVER_RECEIVER = 100
    RECEIVER_HERE = 101

CHUNK_SIZE= 4096
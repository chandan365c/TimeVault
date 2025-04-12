from sender.constants import PacketType

def create_data_packet(seq_num, encrypted_chunk):
    """
    Constructs a DATA packet with a packet type, sequence number, and encrypted chunk.
    Packet format: [PacketType.DATA][4-byte seq_num][encrypted_chunk]
    """
    seq_bytes = seq_num.to_bytes(4, 'big')  # 4 bytes for sequence number
    return bytes([PacketType.DATA]) + seq_bytes + encrypted_chunk

def create_fin_packet():
    """
    Constructs a FIN packet to indicate end of file transfer.
    Packet format: [PacketType.FIN]
    """
    return bytes([PacketType.FIN])

import os
from threading import Timer

class ReceiverState:
    def __init__(self):
        self.reset()

    def reset(self):
        # Connection & protocol state
        self.sender_addr = None
        self.connected = False
        self.state = "IDLE"  # Possible states: IDLE, AWAITING_AES_KEY, AWAITING_META, RECEIVING_FILE, FILE_COMPLETE

        # Key management
        self.private_key_path = "receiver_private.pem"
        self.public_key_path = "receiver_public.pem"
        self.aes_key = None

        # Metadata
        self.filename = None
        self.filesize = 0
        self.ttl = 60  # default TTL in seconds
        self.expected_chunks = 0

        # File data tracking
        self.received_chunks = {}  # {chunk_index: data}
        self.last_ack_sent = -1  # For retransmission handling

        # Cleanup
        self._deletion_timer = None

    def schedule_file_deletion(self):
        """
        Starts a timer that will delete the received file after TTL expires.
        """
        if self.filename and self.ttl > 0:
            log_info(f"⏳ File '{self.filename}' will be deleted in {self.ttl} seconds.")
            self._deletion_timer = Timer(self.ttl, self._delete_file)
            self._deletion_timer.start()

    def _delete_file(self):
        """
        Deletes the file from disk after TTL and resets the state.
        """
        try:
            if os.path.exists(self.filename):
                os.remove(self.filename)
                log_info(f"🗑️ Auto-deleted file: {self.filename}")
            else:
                log_warn(f"File {self.filename} not found during deletion.")
        except Exception as e:
            log_error(f"❌ Error deleting file: {e}")
        finally:
            self.reset()

    def cancel_file_deletion(self):
        """
        Cancel auto-deletion if needed (e.g., transfer interrupted).
        """
        if self._deletion_timer:
            self._deletion_timer.cancel()
            self._deletion_timer = None

# Import logs only at the end to avoid circular import
from receiver.utils import log_info, log_warn, log_error

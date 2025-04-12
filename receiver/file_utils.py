import os
import time
import threading
from receiver.state_manager import ReceiverState
from receiver.utils import show_gui_popup

def sanitize_filename(filename: str) -> str:
    """
    Removes or replaces invalid characters from the filename.
    """
    return "".join(c if c.isalnum() or c in (" ", ".", "_") else "_" for c in filename)

def save_chunk_to_file(state: ReceiverState):
    """
    Assemble all received chunks in order and save the file to disk.
    """
    output_dir = "received_files"
    os.makedirs(output_dir, exist_ok=True)

    safe_filename = sanitize_filename(state.filename)
    file_path = os.path.join(output_dir, safe_filename)
    state.file_save_path = file_path  # Optional: store path for deletion timer

    with open(file_path, 'wb') as f:
        for i in range(state.expected_chunks):
            chunk = state.received_chunks.get(i, b'')
            f.write(chunk)

    print(f"💾 File saved successfully at: {file_path}")

    # Start auto-delete timer if TTL is specified
    if state.ttl and isinstance(state.ttl, int):
        show_gui_popup("NOTICE", f"🕐 File will auto-delete in {state.ttl} seconds.")
        threading.Thread(target=start_auto_delete_timer, args=(file_path, state.ttl), daemon=True).start()

def start_auto_delete_timer(path: str, ttl: int):
    """
    Waits for TTL seconds and then deletes the specified file.
    """
    time.sleep(ttl)
    try:
        if os.path.exists(path):
            os.remove(path)
            print(f"🗑️ File auto-deleted after {ttl} seconds: {path}")
            show_gui_popup("File Auto-Deleted", f"The file has been deleted after {ttl} seconds:\n{path}")
        else:
            print(f"⚠️ Auto-delete: File not found at {path}")
    except Exception as e:
        print(f"❌ Auto-delete failed: {e}")
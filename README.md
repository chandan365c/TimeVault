# TimeVault

 A lightweight custom secure file transfer protocol using AES-EAX for authenticated encryption and RSA for key exchange. Built support for auto-deletion timers, sliding window retransmission, and local peer discovery. Designed for LAN and WAN use, with modular architecture and GUI/CLI interface.

## Features

- **End-to-End Encryption:**
AES-256 in EAX mode ensures confidentiality and integrity, with RSA key exchange for secure AES delivery.

- **Reliable UDP File Transfer:**
A reliable file transfer system built on a custom UDP based protocol. Implements acknowledgements, chunk sequencing, and retransmission using a custom sliding window protocol.

- **Smart Receiver Discovery:**
Automatically finds active receivers on your local network via UDP broadcast.

- **Self-Destructing Files:**
Sender sets a TTL (time-to-live), and the file auto-deletes after the duration expires.

- **Designed for LAN & WAN:**
Works within local networks or over the internet with proper IP and port setup.

## 🛠 Setup

### Recommended (Virtual Environment)
```bash
python3 -m venv your_venv_name
source your_venv_name/bin/activate  #activates your venv
pip install -r requirements.txt
```

## Running the Project
```bash
# Recommended to activate your python venv before running these

# On the Receiver Machine
python3 main_receiver.py     

# On Sender Machine
python3 main_sender.py    


#NOTE: To run the pure GUI version, simply double click on the executable files inside the sender's and receiver's respective folders
 
```
**Note:** Make sure sender and receiver are on the same LAN or the receiver has a public IP / port forwarded for external transfers.


### **NOTE: Cryptodome package issue**

- The pycryptodome module can get saved as either "*Crypto*" or "*Cryptodome*". (In my system, it is saved as *Crypto* in the venv and *Cryptodome* outside the vnev)
- This can give rise to **module not found error**. Just changing all the imports in the files to the alternative can fix the issue. (An alternative can be to run it inside/outside the venv depending on your preference)


## Future Plans & Improvements

- **File transfers outside the local network:**
Implement NAT traversal or fallback relay server support.

- **Multi-file Transfer Support:**
Enable batch transfers and zip/archive options.


- **Transfer Statistics UI:**
Show transfer speed, estimated time, chunk retry count, etc.

- **User Authentication Layer:**
Add optional sender/receiver authentication and access control.

- **GUI with Drag & Drop:**
Cross-platform PyQt or Tkinter-based interface for easier use.

- **Package as CLI Tool:**
pip install timevault with command-line commands like timevault send --file xyz.

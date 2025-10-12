# UDBee

**UDBee** is a covert reverse shell tool that leverages UDP for encrypted command-and-control communication. It features hybrid encryption (RSA + AES), sophisticated message fragmentation, and covert channel techniques to evade network detection and analysis.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Directory Structure](#directory-structure)
- [Disclaimer](#disclaimer)

---

## Features

- **UDP-Based C2:** Uses UDP for stealthy, stateless communication between attacker and victim.
- **Hybrid Encryption:** Implements RSA and AES to ensure robust encryption of commands and responses.
- **Message Fragmentation:** Breaks messages into smaller fragments to avoid detection and packet analysis.
- **Covert Channel Techniques:** Mimics legitimate traffic and injects dummy packets to blend in.
- **Modular Design:** Separated attacker and victim logic for easy deployment and maintenance.

---

## How It Works

UDBee establishes an encrypted reverse shell session over UDP, obfuscating traffic through fragmentation and dummy packets. The attacker initiates a session, sends encrypted commands, and receives responses from the victim machine, all while blending traffic with legitimate-looking packets.

**Core Flow:**
1. **Key Exchange:** Attacker and victim securely exchange public keys using RSA.
2. **Session Establishment:** The attacker uses techniques (such as STUN) to discover the victim's network location.
3. **Encrypted Communication:** Commands and responses are encrypted with AES, keys wrapped in RSA.
4. **Fragmentation & Dummy Packets:** Data is split and interleaved with dummy packets to disguise the traffic.
5. **Covert Execution:** Shell commands are executed on the victim, results sent back covertly.

---

## Installation

### Requirements

- Python 3.7+
- [attacker/requirements.txt](attacker/requirements.txt) lists required packages:
  
  ```
  pip install -r attacker/requirements.txt
  ```

### Setup

1. **Clone the Repository**
   ```sh
   git clone https://github.com/MoMhaidat05/UDBee.git
   cd UDBee
   ```

2. **Install Dependencies**
   ```sh
   pip install -r attacker/requirements.txt
   ```

3. **Deploy Victim & Attacker Scripts**
   - Place the contents of the `attacker/` directory on the attacker's machine.
   - Place the executable file after making it using contents of the `victim/` directory on the victim's machine.

---

## Usage

### Attacker

- **Core Control**: `attacker/core.py` — main script to control sessions, send commands, and receive responses.
- **Encryption/Decryption**: Handled by `attacker/encryption.py` and `attacker/decryption.py`.
- **Fragmentation**: Managed by `attacker/message_fragmentation.py`.
- **Dummy Packets**: Sent via `attacker/dummy_packets.py` to mask traffic.
- **STUN/Discovery**: Use `attacker/stun.py` to assist in building a valid STUN message.

**Example**:
```sh
python attacker/core.py --ip <victim_ip> -delay <delay between messages> -jitter <jitter for delay obfuscation> --chunk-size <outbound chunk size (sent from your machine)> --received_chunks <maximum size for received chunks> -buffer <maximum number of chunks to be received>
```

### Victim

- Scripts in the `victim/` directory listen for UDP packets, decrypt commands, execute them, and send encrypted responses.

**Note:** For specific victim usage, refer to scripts in the `victim/` directory.

---

## Directory Structure

```
UDBee/
├── attacker/
│   ├── core.py
│   ├── encryption.py
│   ├── decryption.py
│   ├── message_fragmentation.py
│   ├── dummy_packets.py
│   ├── stun.py
│   ├── check_missing.py
│   └── requirements.txt
├── victim/
│   ├── core.py
│   ├── encryption.py
│   ├── decryption.py
│   ├── message_fragmentation.py
│   ├── add_to_statup.py
│   ├── stun.py
│   ├── check_missing.py
│   └── requirements.txt
└── .gitignore
```

---

## Disclaimer

This software is provided for educational and research purposes only. Unauthorized use of UDBee against networks or systems without explicit permission is illegal and unethical.

---

## Author

Developed by [MoMhaidat05](https://github.com/MoMhaidat05)

# 🔒 Secure P2P Messenger

A secure, real-time peer-to-peer instant messaging application built in Python. Messages are encrypted end-to-end using AES-256 before being sent over the network. Designed as a course project demonstrating applied cryptography concepts including key derivation, symmetric encryption, Diffie-Hellman key exchange, and automatic key rotation.

---

## Features

- **End-to-end encryption** — every message is encrypted with AES-256-CBC before it leaves your machine
- **Password-based key derivation** — the shared password is never used directly as a key; PBKDF2-HMAC-SHA256 derives a strong key from it
- **Diffie-Hellman key exchange** — optional passwordless mode where both peers negotiate a shared secret over an insecure channel
- **Random IV per message** — the same message always produces different ciphertext
- **Automatic key rotation** — the session key updates every 10 messages without any extra communication
- **Double encryption mode** — extra credit mode that encrypts with AES-CBC and AES-CFB independently, then XORs the results together
- **Live ciphertext display** — the GUI shows the raw ciphertext on every send and receive so you can verify encryption is working

---

## Requirements

- Python 3.8+
- [PyCryptodome](https://pycryptodome.readthedocs.io/)

Install the dependency with:

```bash
pip install pycryptodome
```

---

## How to Run

The app works as a two-peer system. One machine acts as the **Server** (listens for a connection) and the other acts as the **Client** (connects to the server).

**On the Server machine:**
1. Run `python messenger_gui.py`
2. Set Role to **Server**
3. Enter a port (default: `9999`)
4. Enter a shared password (or enable DH mode)
5. Click **Connect** — the app will wait for the client to join

**On the Client machine:**
1. Run `python messenger_gui.py`
2. Set Role to **Client**
3. Enter the server's IP address and the same port
4. Enter the same shared password (or enable DH mode)
5. Click **Connect**

Once both sides connect, you can start sending messages.

> **Testing locally:** Set the server IP to `127.0.0.1` and open two terminal windows on the same machine.

---

## Project Structure

```
├── messenger_gui.py   # Tkinter GUI — handles all user interaction
├── crypto_core.py     # All cryptographic logic (encryption, key derivation, DH, key rotation)
├── network.py         # TCP socket layer — connection setup, framing, and handshake
└── README.md
```

---

## How It Works

### Key Derivation
The shared password is never used as the encryption key directly. Instead, `PBKDF2-HMAC-SHA256` with 100,000 iterations stretches the password into a 256-bit AES key. Both peers independently run the same derivation using the salt exchanged at connection time, so they both arrive at the same key without ever sending it over the network.

### Encryption (Standard Mode)
Messages are encrypted with **AES-256-CBC**. A fresh 16-byte random IV is generated for every message, which ensures that sending the same message twice produces completely different ciphertext each time. The IV is sent alongside the ciphertext in the message envelope so the receiver can decrypt it.

### Encryption (Double Mode — Extra Credit)
In Double mode, the master key is split into two independent sub-keys. The plaintext is encrypted once with AES-256-CBC and once with AES-256-CFB. The two ciphertexts are then XOR'd together. An attacker would need to break both ciphers simultaneously to recover any information.

### Diffie-Hellman Key Exchange (Extra Credit)
If DH mode is enabled, no shared password is needed. Both peers exchange public keys using the 2048-bit MODP Group 14 prime from RFC 3526. They each compute the same shared secret independently and use it in place of a password for key derivation. The plaintext password is never involved.

### Key Rotation
Both peers track a message counter. Every 10 messages, the epoch counter increments and both sides re-derive a new key using the updated epoch mixed into the salt. Since both sides apply the same counter logic, they stay in sync automatically with no extra network traffic. You can also trigger a manual rotation at any time using the **Rotate Key Now** button. Rotating regularly limits how much ciphertext is encrypted under any single key.

### Network Layer
The two peers connect over a standard TCP socket. Messages are **length-prefixed** with a 4-byte header so the receiver knows exactly how many bytes to read per message. An application-level handshake runs first to exchange the salt (and DH public keys if applicable) before any chat messages flow.

---

## GUI Overview

| Element | Description |
|---|---|
| Role | Switch between Server (listen) and Client (connect) |
| Peer IP | The server's IP address — only needed when acting as Client |
| Port | TCP port both peers must agree on |
| Shared Password | The passphrase used to derive the encryption key |
| DH Key Exchange | Enables passwordless mode using Diffie-Hellman |
| Encryption Mode | Standard (AES-CBC) or Double (AES-CBC + AES-CFB XOR'd) |
| Epoch / Msgs | Live counter showing current key epoch and message count |
| Rotate Key Now | Manually forces a key rotation ahead of schedule |
| Key Fingerprint | First 16 hex characters of the current key — both peers should match |
| Chat window | Shows plaintext, ciphertext, timestamps, and rotation events |

---

## Security Notes

- The salt is exchanged in plaintext during the handshake — this is intentional and safe. The salt does not need to be secret; it just needs to be the same on both sides.
- DH mode does not authenticate the peers. A man-in-the-middle could intercept the public key exchange. For a production system, this would be addressed with certificates or a pre-authenticated channel.
- The double encryption XOR scheme is a course exercise. In production, authenticated encryption (AES-GCM) would be the standard choice.
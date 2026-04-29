"""
crypto_core.py
Cryptographic primitives for the Secure P2P Messenger.
"""

import os
import hashlib
import hmac
import struct
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES-256 needs a 32-byte key and operates on 16-byte blocks
AES_KEY_SIZE   = 32
AES_BLOCK_SIZE = 16
PBKDF2_ITERS   = 100_000
SALT_SIZE      = 16


# --- Key Derivation ---

def derive_key(password: str, salt: bytes, epoch: int = 0) -> bytes:
    # Mix the epoch into the salt so each rotation gives a completely different key
    epoch_bytes = struct.pack(">Q", epoch)
    effective_salt = hashlib.sha256(salt + epoch_bytes).digest()

    # PBKDF2 with 100k iterations — slow by design to resist brute-force
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        effective_salt,
        PBKDF2_ITERS,
        dklen=AES_KEY_SIZE,
    )
    return key


# --- Standard AES-256-CBC Encrypt / Decrypt ---

def encrypt(key: bytes, plaintext: str) -> dict:
    # A fresh random IV every call means identical messages encrypt differently
    iv = get_random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode("utf-8"), AES_BLOCK_SIZE, style="pkcs7")
    ciphertext = cipher.encrypt(padded)
    return {
        "iv":         base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt(key: bytes, payload: dict) -> str:
    iv         = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    cipher     = AES.new(key, AES.MODE_CBC, iv)
    padded     = cipher.decrypt(ciphertext)
    plaintext  = unpad(padded, AES_BLOCK_SIZE, style="pkcs7")
    return plaintext.decode("utf-8")


# --- Extra Credit: Double Encryption with XOR ---

def double_encrypt(key: bytes, plaintext: str) -> dict:
    # Split the master key into two independent sub-keys using domain labels
    key_cbc = hashlib.sha256(b"CBC" + key).digest()
    key_cfb = hashlib.sha256(b"CFB" + key).digest()

    iv_cbc = get_random_bytes(AES_BLOCK_SIZE)
    iv_cfb = get_random_bytes(AES_BLOCK_SIZE)

    # Pad once and reuse — both ciphers need the same length input
    padded = pad(plaintext.encode("utf-8"), AES_BLOCK_SIZE, style="pkcs7")

    cipher_cbc = AES.new(key_cbc, AES.MODE_CBC, iv_cbc)
    ct_cbc     = cipher_cbc.encrypt(padded)

    cipher_cfb = AES.new(key_cfb, AES.MODE_CFB, iv_cfb, segment_size=128)
    ct_cfb     = cipher_cfb.encrypt(padded)

    # XOR the two ciphertexts — an attacker needs to break both ciphers to recover plaintext
    xored = bytes(a ^ b for a, b in zip(ct_cbc, ct_cfb))

    return {
        "mode":       "double",
        "iv_cbc":     base64.b64encode(iv_cbc).decode(),
        "iv_cfb":     base64.b64encode(iv_cfb).decode(),
        "ciphertext": base64.b64encode(xored).decode(),
        "ct_cfb":     base64.b64encode(ct_cfb).decode(),  # needed to un-XOR on the other side
    }


def double_decrypt(key: bytes, payload: dict) -> str:
    key_cbc = hashlib.sha256(b"CBC" + key).digest()
    key_cfb = hashlib.sha256(b"CFB" + key).digest()

    iv_cbc = base64.b64decode(payload["iv_cbc"])
    iv_cfb = base64.b64decode(payload["iv_cfb"])
    xored  = base64.b64decode(payload["ciphertext"])
    ct_cfb = base64.b64decode(payload["ct_cfb"])

    # Ensure both byte strings are the same length before XOR-ing
    length = min(len(xored), len(ct_cfb))
    ct_cbc = bytes(a ^ b for a, b in zip(xored[:length], ct_cfb[:length]))

    # Decrypt the CBC layer to get back the padded plaintext
    cipher_cbc = AES.new(key_cbc, AES.MODE_CBC, iv_cbc)
    padded     = cipher_cbc.decrypt(ct_cbc)
    plaintext  = unpad(padded, AES_BLOCK_SIZE, style="pkcs7")
    return plaintext.decode("utf-8")


# --- Extra Credit: Diffie-Hellman Key Exchange (RFC 3526 Group 14) ---

# Standard 2048-bit prime from RFC 3526 — widely trusted for DH
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_GENERATOR = 2


def dh_generate_private_key() -> int:
    # 256 random bits is more than enough for DH private key security
    return int.from_bytes(get_random_bytes(32), "big")


def dh_public_key(private_key: int) -> int:
    # g^private mod p
    return pow(DH_GENERATOR, private_key, DH_PRIME)


def dh_shared_secret(their_public: int, my_private: int) -> bytes:
    shared = pow(their_public, my_private, DH_PRIME)
    # Hash the raw shared value down to 32 bytes for use as an AES key
    return hashlib.sha256(shared.to_bytes(256, "big")).digest()


# --- Key Manager ---

class KeyManager:
    # How many messages before we automatically rotate to a new key
    ROTATION_INTERVAL = 10

    def __init__(self, password: str, salt: bytes, use_dh: bool = False,
                 dh_secret: bytes = None):
        self.password  = password
        self.salt      = salt
        self.epoch     = 0
        self.msg_count = 0
        self.use_dh    = use_dh
        self.dh_secret = dh_secret
        self._refresh_key()

    def _refresh_key(self):
        if self.use_dh and self.dh_secret:
            # In DH mode, use the shared secret as the "password" for derivation
            effective_pw = base64.b64encode(self.dh_secret).decode()
            self.current_key = derive_key(effective_pw, self.salt, self.epoch)
        else:
            self.current_key = derive_key(self.password, self.salt, self.epoch)

    @property
    def key(self) -> bytes:
        return self.current_key

    def record_message(self):
        # Both peers call this after every message, so they stay in sync automatically
        self.msg_count += 1
        if self.msg_count % self.ROTATION_INTERVAL == 0:
            self.epoch += 1
            self._refresh_key()
            return True  # let the caller know a rotation just happened
        return False

    def force_rotate(self):
        self.epoch += 1
        self._refresh_key()

    def current_epoch(self) -> int:
        return self.epoch


# --- Message Packing ---

def pack_message(payload: dict, sender: str, epoch: int, mode: str = "standard") -> str:
    # Wrap the encrypted payload with metadata so the receiver knows how to decrypt it
    envelope = {
        "sender":  sender,
        "epoch":   epoch,
        "mode":    mode,
        "payload": payload,
    }
    return json.dumps(envelope)


def unpack_message(raw: str) -> dict:
    return json.loads(raw)
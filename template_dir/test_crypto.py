"""
test_crypto.py
==============
Unit tests for crypto_core.py.
Run with:  python test_crypto.py
"""

import unittest
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import (
    derive_key,
    encrypt, decrypt,
    double_encrypt, double_decrypt,
    KeyManager,
    pack_message, unpack_message,
    dh_generate_private_key, dh_public_key, dh_shared_secret,
)


class TestKeyDerivation(unittest.TestCase):

    def test_same_inputs_same_key(self):
        salt = os.urandom(16)
        k1 = derive_key("password123", salt, epoch=0)
        k2 = derive_key("password123", salt, epoch=0)
        self.assertEqual(k1, k2)

    def test_different_epoch_different_key(self):
        salt = os.urandom(16)
        k0 = derive_key("password123", salt, epoch=0)
        k1 = derive_key("password123", salt, epoch=1)
        self.assertNotEqual(k0, k1)

    def test_key_length_256_bits(self):
        key = derive_key("test", os.urandom(16))
        self.assertEqual(len(key), 32)

    def test_different_password_different_key(self):
        salt = os.urandom(16)
        k1 = derive_key("alice", salt)
        k2 = derive_key("bob",   salt)
        self.assertNotEqual(k1, k2)


class TestAESCBC(unittest.TestCase):

    def setUp(self):
        self.key = derive_key("testpass", os.urandom(16))

    def test_encrypt_decrypt_roundtrip(self):
        msg = "Hello, World!"
        payload = encrypt(self.key, msg)
        result  = decrypt(self.key, payload)
        self.assertEqual(result, msg)

    def test_same_message_different_ciphertext(self):
        msg  = "ok"
        ct1  = encrypt(self.key, msg)["ciphertext"]
        ct2  = encrypt(self.key, msg)["ciphertext"]
        self.assertNotEqual(ct1, ct2,
            "Same plaintext must produce different ciphertext (random IV)")

    def test_empty_message(self):
        payload = encrypt(self.key, "")
        result  = decrypt(self.key, payload)
        self.assertEqual(result, "")

    def test_unicode_message(self):
        msg     = "こんにちは 🔒"
        payload = encrypt(self.key, msg)
        result  = decrypt(self.key, payload)
        self.assertEqual(result, msg)

    def test_long_message(self):
        msg     = "A" * 10_000
        payload = encrypt(self.key, msg)
        result  = decrypt(self.key, payload)
        self.assertEqual(result, msg)

    def test_wrong_key_fails(self):
        key2    = derive_key("wrongpass", os.urandom(16))
        payload = encrypt(self.key, "secret")
        with self.assertRaises(Exception):
            decrypt(key2, payload)


class TestDoubleEncryption(unittest.TestCase):

    def setUp(self):
        self.key = derive_key("testpass", os.urandom(16))

    def test_roundtrip(self):
        msg     = "Double encryption test"
        payload = double_encrypt(self.key, msg)
        result  = double_decrypt(self.key, payload)
        self.assertEqual(result, msg)

    def test_different_from_standard(self):
        msg  = "same message"
        std  = encrypt(self.key, msg)["ciphertext"]
        dbl  = double_encrypt(self.key, msg)["ciphertext"]
        self.assertNotEqual(std, dbl)

    def test_random_iv_per_call(self):
        msg  = "ok"
        p1   = double_encrypt(self.key, msg)["ciphertext"]
        p2   = double_encrypt(self.key, msg)["ciphertext"]
        self.assertNotEqual(p1, p2)


class TestKeyManager(unittest.TestCase):

    def test_both_sides_same_key(self):
        salt = os.urandom(16)
        pw   = "shared_secret"
        km1  = KeyManager(pw, salt)
        km2  = KeyManager(pw, salt)
        self.assertEqual(km1.key, km2.key)

    def test_key_rotates_after_n_messages(self):
        salt    = os.urandom(16)
        km      = KeyManager("pw", salt)
        key_0   = km.key
        for _ in range(KeyManager.ROTATION_INTERVAL):
            km.record_message()
        self.assertNotEqual(key_0, km.key)

    def test_both_sides_rotate_in_sync(self):
        salt = os.urandom(16)
        pw   = "shared"
        km1  = KeyManager(pw, salt)
        km2  = KeyManager(pw, salt)
        n    = KeyManager.ROTATION_INTERVAL
        for _ in range(n):
            km1.record_message()
            km2.record_message()
        self.assertEqual(km1.key, km2.key)

    def test_force_rotate(self):
        salt  = os.urandom(16)
        km    = KeyManager("pw", salt)
        k0    = km.key
        km.force_rotate()
        self.assertNotEqual(k0, km.key)

    def test_epoch_increments(self):
        salt = os.urandom(16)
        km   = KeyManager("pw", salt)
        self.assertEqual(km.current_epoch(), 0)
        km.force_rotate()
        self.assertEqual(km.current_epoch(), 1)


class TestDHKeyExchange(unittest.TestCase):

    def test_shared_secret_matches(self):
        priv_a = dh_generate_private_key()
        priv_b = dh_generate_private_key()
        pub_a  = dh_public_key(priv_a)
        pub_b  = dh_public_key(priv_b)
        secret_a = dh_shared_secret(pub_b, priv_a)
        secret_b = dh_shared_secret(pub_a, priv_b)
        self.assertEqual(secret_a, secret_b)

    def test_different_keys_different_secrets(self):
        priv_a1 = dh_generate_private_key()
        priv_a2 = dh_generate_private_key()
        priv_b  = dh_generate_private_key()
        s1 = dh_shared_secret(dh_public_key(priv_b), priv_a1)
        s2 = dh_shared_secret(dh_public_key(priv_b), priv_a2)
        self.assertNotEqual(s1, s2)

    def test_dh_key_manager_sync(self):
        priv_a = dh_generate_private_key()
        priv_b = dh_generate_private_key()
        pub_a  = dh_public_key(priv_a)
        pub_b  = dh_public_key(priv_b)
        sec_a  = dh_shared_secret(pub_b, priv_a)
        sec_b  = dh_shared_secret(pub_a, priv_b)
        salt   = os.urandom(16)
        km_a   = KeyManager("", salt, use_dh=True, dh_secret=sec_a)
        km_b   = KeyManager("", salt, use_dh=True, dh_secret=sec_b)
        self.assertEqual(km_a.key, km_b.key)


class TestMessageSerialization(unittest.TestCase):

    def test_pack_unpack_roundtrip(self):
        payload = {"iv": "abc", "ciphertext": "xyz"}
        raw     = pack_message(payload, "Alice", epoch=2, mode="standard")
        env     = unpack_message(raw)
        self.assertEqual(env["sender"],  "Alice")
        self.assertEqual(env["epoch"],   2)
        self.assertEqual(env["mode"],    "standard")
        self.assertEqual(env["payload"], payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)

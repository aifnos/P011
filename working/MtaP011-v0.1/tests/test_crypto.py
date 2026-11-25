# -*- coding: utf-8 -*-
import base64
import binascii
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
from mta_crypto import ASCII_IV, CryptoError, OpenSslCrypto, P256_SPKI_PREFIX
from mta_protocol import P2pInfo


def host_openssl():
    selected = os.environ.get("MTA_TEST_OPENSSL")
    candidates = [selected] if selected else []
    if os.name == "nt":
        candidates += [r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe"]
    else:
        candidates += ["/usr/bin/openssl", "/bin/openssl"]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


class CryptoTests(unittest.TestCase):
    def setUp(self):
        executable = host_openssl()
        if executable is None:
            self.skipTest("HOST OpenSSL unavailable; no device crypto claim")
        self.base = tempfile.mkdtemp(prefix="mta-host-crypto-test-")
        try:
            self.crypto = OpenSslCrypto(executable, temp_root=self.base)
        except CryptoError:
            shutil.rmtree(self.base)
            self.skipTest("HOST OpenSSL EVP unavailable; no device crypto claim")

    def tearDown(self):
        if hasattr(self, "base") and os.path.isdir(self.base):
            shutil.rmtree(self.base)

    def test_p256_spki_and_private_cleanup(self):
        with self.crypto.generate_keypair() as keys:
            der = base64.b64decode(keys.public_key)
            self.assertEqual(len(der), 91)
            self.assertTrue(der.startswith(P256_SPKI_PREFIX))
            self.assertTrue(keys._native_key)
            self.assertEqual(os.listdir(self.base), [])
        self.assertTrue(keys.closed)
        self.assertIsNone(keys._native_key)
        self.assertEqual(os.listdir(self.base), [])
        with self.assertRaises(CryptoError):
            self.crypto.derive_shared(keys, keys.public_key)

    def test_ecdh_both_directions(self):
        with self.crypto.generate_keypair() as a, self.crypto.generate_keypair() as b:
            left = self.crypto.derive_shared(a, b.public_key)
            right = self.crypto.derive_shared(b, a.public_key)
            self.assertEqual(len(left), 32)
            self.assertEqual(left, right)
            self.assertEqual(os.listdir(self.base), [])
        self.assertEqual(os.listdir(self.base), [])

    def test_aes_fixed_ascii_iv_known_vector(self):
        # Public non-secret fixture independently computed with OpenSSL CLI;
        # no generated session secret is ever placed into argv.
        self.assertEqual(ASCII_IV, b"0102030405060708")
        plaintext = b"MTA known public test vector"
        fixture_key = bytes(bytearray(range(32)))
        encrypted = self.crypto.aes_ctr(plaintext, fixture_key)
        self.assertEqual(binascii.hexlify(encrypted).decode("ascii"), "7cbbf725e7c5a304dbc026598f48866d9b7eeabdd10704dc6b3dfe7e")
        self.assertEqual(self.crypto.aes_ctr(encrypted, fixture_key), plaintext)

    def test_binary_empty_multiblock(self):
        key = bytes(bytearray(range(32)))
        for data in (b"", b"\x00\xff" * 129, b"a" * 8192):
            self.assertEqual(self.crypto.aes_ctr(self.crypto.aes_ctr(data, key), key), data)
        for data, key in ((b"x" * 8193, b"k" * 32), (b"x", b"k" * 31), ("x", b"k" * 32)):
            with self.assertRaises(CryptoError):
                self.crypto.aes_ctr(data, key)

    def test_credential_exchange(self):
        plain = P2pInfo("DIRECT-笔", "abc12345", "02:00:00:00:00:01", 33331, sender_id="1234")
        with self.crypto.generate_keypair() as sender, self.crypto.generate_keypair() as receiver:
            encrypted = self.crypto.encrypt_credentials(plain, sender, receiver.public_key)
            self.assertNotEqual(encrypted.ssid, plain.ssid)
            self.assertEqual(encrypted.key, sender.public_key)
            restored = self.crypto.decrypt_credentials(encrypted, receiver)
            self.assertEqual(restored.to_dict(), plain.to_dict())

    def test_decryption_never_falls_back_to_plaintext(self):
        with self.crypto.generate_keypair() as keys:
            for peer in ("!", base64.b64encode(b"bad-key").decode("ascii"), base64.b64encode(b"\x00" * 91).decode("ascii")):
                with self.assertRaises(CryptoError):
                    self.crypto.derive_shared(keys, peer)
            with self.assertRaises(CryptoError):
                self.crypto.decrypt_credentials(P2pInfo("DIRECT-a", "12345678", "02:00:00:00:00:01", 5), keys)
        for bad in ("!", "", "A" * 600):
            with self.assertRaises(CryptoError):
                self.crypto.decrypt(bad, b"x" * 32)

    def test_cli_arguments_contain_no_raw_session_key(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("Session crypto must not spawn a CLI")) as spawn:
            with self.crypto.generate_keypair() as a, self.crypto.generate_keypair() as b:
                key = self.crypto.derive_shared(a, b.public_key)
                self.crypto.encrypt("credential", key)
                self.assertFalse(spawn.called)

    def test_private_cleanup_on_failure(self):
        real_free = self.crypto._lib.EC_KEY_free
        with mock.patch.object(self.crypto._lib, "EC_KEY_free", wraps=real_free) as free:
            with mock.patch.object(self.crypto, "_public_spki", side_effect=CryptoError("fixture failure")):
                with self.assertRaises(CryptoError):
                    self.crypto.generate_keypair()
            self.assertEqual(free.call_count, 1)
        self.assertEqual(os.listdir(self.base), [])

    def test_bad_configuration_is_explicit(self):
        for arguments in (("relative",), (self.crypto.executable, 0), (self.crypto.executable, 61)):
            with self.assertRaises(CryptoError):
                OpenSslCrypto(*arguments)
        with self.assertRaises(CryptoError):
            OpenSslCrypto(self.crypto.executable, crypto_library=os.path.join(self.base, "missing-library"))


if __name__ == "__main__":
    unittest.main()

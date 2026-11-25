# -*- coding: utf-8 -*-
"""MTA P-256/SPKI/ECDH and AES-256-CTR via installed OpenSSL.

P-256/SPKI/ECDH and AES use libcrypto via ctypes. Session EC private keys remain
native memory only: no private files, subprocesses, key argv, or logs. This also
works around the P011 firmware's stripped CLI lacking pkey -pubout. No
third-party Python package is required.

The fixed ASCII IV and absence of a KDF/authentication tag are wire-protocol
properties, not a recommendation for new cryptographic designs. Transport
peer validation is the caller's responsibility. Python cannot promise secure
erasure of every immutable secret copy; secrets must never be logged/archived.
"""
import base64
import binascii
import ctypes
import ctypes.util
import os
import threading

from mta_protocol import P2pInfo, ProtocolError

ASCII_IV = b"0102030405060708"
P256_SPKI_PREFIX = binascii.unhexlify("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
MAX_CREDENTIAL_BYTES = 256


class CryptoError(RuntimeError):
    pass


def _public_der(text):
    if not isinstance(text, str) or len(text) > 256:
        raise CryptoError("invalid P-256 public key")
    try:
        data = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise CryptoError("invalid P-256 public key")
    if len(data) != 91 or not data.startswith(P256_SPKI_PREFIX):
        raise CryptoError("public key must be P-256 SPKI DER")
    return data


class KeyPair(object):
    """A context-managed private key; default repr contains no key material."""
    def __init__(self, public_key, native_key, owner):
        self.public_key = public_key
        self.public_key_b64 = public_key
        self._native_key = native_key
        self._owner = owner
        self._lock = threading.RLock()
        self.closed = False

    def close(self):
        with self._lock:
            if not self.closed:
                self.closed = True
                key = self._native_key
                self._native_key = None
                if key:
                    self._owner.EC_KEY_free(key)

    def __enter__(self):
        if self.closed:
            raise CryptoError("private key has been closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class OpenSslCrypto(object):
    def __init__(self, executable="/usr/bin/openssl", timeout=10, crypto_library=None, temp_root=None):
        if not isinstance(executable, str) or not os.path.isabs(executable) or not os.path.isfile(executable):
            raise CryptoError("an existing absolute OpenSSL executable is required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise CryptoError("invalid OpenSSL timeout")
        if temp_root is not None and (not isinstance(temp_root, str) or not os.path.isabs(temp_root) or not os.path.isdir(temp_root)):
            raise CryptoError("invalid private temporary directory")
        self.executable = executable
        self.timeout = timeout
        self.temp_root = temp_root
        self._lib = self._load_library(crypto_library)

    def _load_library(self, selected):
        candidates = []
        if selected is not None:
            if not isinstance(selected, str) or not os.path.isabs(selected) or not os.path.isfile(selected):
                raise CryptoError("invalid OpenSSL library path")
            candidates = [selected]
        elif os.name == "nt":
            directory = os.path.dirname(self.executable)
            candidates = [os.path.join(directory, "libcrypto-3-x64.dll"),
                          os.path.join(directory, "libcrypto-1_1-x64.dll")]
            # Git's usr/bin executable is MSYS-based. Load the native Win64
            # library, not msys-crypto, into the native Python process.
            if os.path.basename(directory).lower() == "bin" and os.path.basename(os.path.dirname(directory)).lower() == "usr":
                candidates.append(os.path.join(os.path.dirname(os.path.dirname(directory)), "mingw64", "bin", "libcrypto-3-x64.dll"))
        else:
            candidates = ["/usr/lib/libcrypto.so.1.0.2", "/usr/lib/libcrypto.so.1.0.0"]
            discovered = ctypes.util.find_library("crypto")
            if discovered:
                candidates.append(discovered)
        library = None
        for candidate in candidates:
            try:
                library = ctypes.CDLL(candidate)
                break
            except (OSError, ValueError):
                pass
        if library is None:
            raise CryptoError("OpenSSL EVP library is unavailable")
        try:
            library.EVP_CIPHER_CTX_new.argtypes = []
            library.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            library.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            library.EVP_CIPHER_CTX_free.restype = None
            library.EVP_aes_256_ctr.argtypes = []
            library.EVP_aes_256_ctr.restype = ctypes.c_void_p
            library.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            library.EVP_EncryptInit_ex.restype = ctypes.c_int
            library.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
            library.EVP_EncryptUpdate.restype = ctypes.c_int
            library.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            library.EVP_EncryptFinal_ex.restype = ctypes.c_int
            library.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]
            library.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
            library.EC_KEY_generate_key.argtypes = [ctypes.c_void_p]
            library.EC_KEY_generate_key.restype = ctypes.c_int
            library.EC_KEY_set_asn1_flag.argtypes = [ctypes.c_void_p, ctypes.c_int]
            library.EC_KEY_set_asn1_flag.restype = None
            library.EC_KEY_free.argtypes = [ctypes.c_void_p]
            library.EC_KEY_free.restype = None
            library.EC_KEY_check_key.argtypes = [ctypes.c_void_p]
            library.EC_KEY_check_key.restype = ctypes.c_int
            library.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]
            library.EC_KEY_get0_group.restype = ctypes.c_void_p
            library.EC_GROUP_get_curve_name.argtypes = [ctypes.c_void_p]
            library.EC_GROUP_get_curve_name.restype = ctypes.c_int
            library.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]
            library.EC_KEY_get0_public_key.restype = ctypes.c_void_p
            library.i2d_EC_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
            library.i2d_EC_PUBKEY.restype = ctypes.c_int
            library.d2i_EC_PUBKEY.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.c_long]
            library.d2i_EC_PUBKEY.restype = ctypes.c_void_p
            library.ECDH_compute_key.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            library.ECDH_compute_key.restype = ctypes.c_int
        except AttributeError:
            raise CryptoError("OpenSSL native P-256/SPKI/ECDH/AES API is unavailable")
        return library

    def _validate_native_key(self, key):
        group = self._lib.EC_KEY_get0_group(key)
        # NID_X9_62_prime256v1 is 415 in the OpenSSL ASN.1 object registry.
        # Require the actual native curve, not only a caller-supplied DER prefix.
        if (not group or self._lib.EC_GROUP_get_curve_name(group) != 415 or
                self._lib.EC_KEY_check_key(key) != 1):
            raise CryptoError("invalid native P-256 key")

    def _public_spki(self, key):
        length = self._lib.i2d_EC_PUBKEY(key, None)
        if length != 91:
            raise CryptoError("invalid P-256 SPKI length")
        buffer = ctypes.create_string_buffer(length)
        pointer = ctypes.c_void_p(ctypes.addressof(buffer))
        written = self._lib.i2d_EC_PUBKEY(key, ctypes.byref(pointer))
        if written != length or pointer.value != ctypes.addressof(buffer) + length:
            raise CryptoError("P-256 SPKI encoding failed")
        public_key = base64.b64encode(buffer.raw).decode("ascii")
        _public_der(public_key)
        return public_key

    def generate_keypair(self):
        key = self._lib.EC_KEY_new_by_curve_name(415)
        if not key:
            raise CryptoError("P-256 key allocation failed")
        try:
            # 1.0.2 vendor builds can default to explicit EC parameters;
            # MTA/Java SPKI requires the named prime256v1 OID (91 bytes).
            self._lib.EC_KEY_set_asn1_flag(key, 1)  # OPENSSL_EC_NAMED_CURVE
            if self._lib.EC_KEY_generate_key(key) != 1:
                raise CryptoError("P-256 key generation failed")
            self._validate_native_key(key)
            public_key = self._public_spki(key)
            result = KeyPair(public_key, key, self._lib)
            key = None  # native pointer ownership transferred to KeyPair
            return result
        except Exception:
            raise
        finally:
            if key:
                self._lib.EC_KEY_free(key)

    def derive_shared(self, own_keypair, peer_public_key):
        if not isinstance(own_keypair, KeyPair):
            raise CryptoError("an active local key pair is required")
        # ctypes releases the GIL; guard against concurrent cancellation
        # freeing the EC key during ECDH in another thread.
        with own_keypair._lock:
            if (own_keypair.closed or own_keypair._owner is not self._lib or not own_keypair._native_key):
                raise CryptoError("an active local key pair is required")
            return self._derive_native(own_keypair, peer_public_key)

    def _derive_native(self, own_keypair, peer_public_key):
        der = _public_der(peer_public_key)
        buffer = ctypes.create_string_buffer(der, len(der))
        pointer = ctypes.c_void_p(ctypes.addressof(buffer))
        peer = self._lib.d2i_EC_PUBKEY(None, ctypes.byref(pointer), len(der))
        if not peer:
            raise CryptoError("P-256 public-key parsing failed")
        shared_buffer = ctypes.create_string_buffer(32)
        try:
            if pointer.value != ctypes.addressof(buffer) + len(der):
                raise CryptoError("P-256 public-key trailing data")
            self._validate_native_key(peer)
            point = self._lib.EC_KEY_get0_public_key(peer)
            if not point:
                raise CryptoError("P-256 public point is unavailable")
            length = self._lib.ECDH_compute_key(shared_buffer, 32, point, own_keypair._native_key, None)
            if length != 32:
                raise CryptoError("invalid ECDH shared-secret length")
            return shared_buffer.raw
        finally:
            self._lib.EC_KEY_free(peer)
            ctypes.memset(ctypes.addressof(shared_buffer), 0, 32)

    def aes_ctr(self, data, shared_secret):
        if not isinstance(data, bytes) or len(data) > 8192:
            raise CryptoError("AES input byte limit")
        if not isinstance(shared_secret, (bytes, bytearray)) or len(shared_secret) != 32:
            raise CryptoError("AES key must be 32 bytes")
        context = self._lib.EVP_CIPHER_CTX_new()
        if not context:
            raise CryptoError("AES context allocation failed")
        key_buffer = ctypes.create_string_buffer(bytes(shared_secret), 32)
        iv_buffer = ctypes.create_string_buffer(ASCII_IV, 16)
        input_buffer = ctypes.create_string_buffer(data, max(1, len(data)))
        output_buffer = ctypes.create_string_buffer(len(data) + 16)
        first = ctypes.c_int(0)
        last = ctypes.c_int(0)
        try:
            if self._lib.EVP_EncryptInit_ex(context, self._lib.EVP_aes_256_ctr(), None, key_buffer, iv_buffer) != 1:
                raise CryptoError("AES initialization failed")
            if self._lib.EVP_EncryptUpdate(context, output_buffer, ctypes.byref(first), input_buffer, len(data)) != 1:
                raise CryptoError("AES operation failed")
            if first.value < 0 or first.value > len(data):
                raise CryptoError("AES output length mismatch")
            end = ctypes.c_void_p(ctypes.addressof(output_buffer) + first.value)
            if self._lib.EVP_EncryptFinal_ex(context, end, ctypes.byref(last)) != 1:
                raise CryptoError("AES finalization failed")
            if first.value + last.value != len(data):
                raise CryptoError("AES output length mismatch")
            return output_buffer.raw[:len(data)]
        finally:
            self._lib.EVP_CIPHER_CTX_free(context)
            ctypes.memset(ctypes.addressof(key_buffer), 0, 32)
            ctypes.memset(ctypes.addressof(input_buffer), 0, max(1, len(data)))
            ctypes.memset(ctypes.addressof(output_buffer), 0, len(data) + 16)

    def encrypt(self, plaintext, shared_secret):
        if not isinstance(plaintext, str) or not plaintext or len(plaintext.encode("utf-8")) > MAX_CREDENTIAL_BYTES:
            raise CryptoError("invalid credential plaintext")
        return base64.b64encode(self.aes_ctr(plaintext.encode("utf-8"), shared_secret)).decode("ascii")

    def decrypt(self, encrypted, shared_secret):
        if not isinstance(encrypted, str) or not encrypted or len(encrypted) > MAX_CREDENTIAL_BYTES * 2:
            raise CryptoError("invalid encrypted credential")
        try:
            data = base64.b64decode(encrypted.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            raise CryptoError("invalid encrypted credential")
        if not data or len(data) > MAX_CREDENTIAL_BYTES:
            raise CryptoError("encrypted credential byte limit")
        try:
            return self.aes_ctr(data, shared_secret).decode("utf-8")
        except UnicodeError:
            raise CryptoError("credential decryption failed")

    def encrypt_credentials(self, plain_info, own_keypair, peer_public_key):
        if not isinstance(plain_info, P2pInfo) or plain_info.key is not None:
            raise CryptoError("plaintext P2pInfo is required")
        shared = self.derive_shared(own_keypair, peer_public_key)
        return P2pInfo(self.encrypt(plain_info.ssid, shared), self.encrypt(plain_info.psk, shared),
                       self.encrypt(plain_info.mac, shared), plain_info.port,
                       own_keypair.public_key, plain_info.id, plain_info.cat_share)

    def decrypt_credentials(self, encrypted_info, own_keypair):
        if not isinstance(encrypted_info, P2pInfo) or encrypted_info.key is None:
            raise CryptoError("encrypted P2pInfo is required")
        shared = self.derive_shared(own_keypair, encrypted_info.key)
        try:
            return P2pInfo(self.decrypt(encrypted_info.ssid, shared), self.decrypt(encrypted_info.psk, shared),
                           self.decrypt(encrypted_info.mac, shared), encrypted_info.port,
                           None, encrypted_info.id, encrypted_info.cat_share)
        except ProtocolError:
            raise CryptoError("decrypted credentials failed validation")

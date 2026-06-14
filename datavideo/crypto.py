"""Crypto layer for FrameCourier.

Three concrete crypto layers are supported. Each has a single ``encryptor`` /
``decryptor`` factory and a streaming-friendly chunked variant for the AEAD modes.

================  ==================  ==============================================
Layer id          KDF                 Cipher
================  ==================  ==============================================
``aes-ctr``       PBKDF2-HMAC-SHA256  AES-256-CTR (stream cipher, no auth)
``aes-gcm``       Argon2id            AES-256-GCM in 64 KiB chunks (auth per chunk)
``chacha-poly``   Argon2id            XChaCha20-Poly1305 in 64 KiB chunks (auth)
================  ==================  ==============================================

The chunked AEAD modes treat the input as a sequence of fixed-size chunks. Each
chunk gets a unique 12-byte nonce derived as ``base_nonce XOR chunk_index`` and
its own auth tag. The header stores the base nonce and the chunk size; tampering
with any chunk fails its auth tag.
"""

import base64
import os
import struct

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12

DEFAULT_PBKDF2_ITERATIONS = 200_000

DEFAULT_ARGON2_TIME = 3
DEFAULT_ARGON2_MEMORY_KB = 64 * 1024
DEFAULT_ARGON2_PARALLELISM = 4

CHUNK_SIZE = 64 * 1024
AEAD_TAG_BYTES = 16

KDF_PBKDF2 = "pbkdf2-hmac-sha256"
KDF_ARGON2ID = "argon2id"

LAYER_NONE = "none"
LAYER_AES_CTR = "aes-ctr"
LAYER_AES_GCM = "aes-gcm"
LAYER_CHACHA_POLY = "chacha-poly"
LAYER_X25519_CHACHA = "x25519-chacha20"
LAYER_DENIABLE = "deniable"
LAYER_X25519_MULTI = "x25519-multi-chacha20"

LAYER_IDS = {
    LAYER_NONE: 0,
    LAYER_AES_CTR: 1,
    LAYER_AES_GCM: 2,
    LAYER_CHACHA_POLY: 3,
    LAYER_X25519_CHACHA: 4,
    LAYER_DENIABLE: 5,
    LAYER_X25519_MULTI: 6,
}
LAYER_NAMES = {v: k for k, v in LAYER_IDS.items()}

KDF_HKDF_SHA256 = "hkdf-sha256"

KDF_IDS = {
    "none": 0,
    KDF_PBKDF2: 1,
    KDF_ARGON2ID: 2,
    KDF_HKDF_SHA256: 3,
}
KDF_NAMES = {v: k for k, v in KDF_IDS.items()}

X25519_PUBKEY_BYTES = 32
X25519_PRIVKEY_BYTES = 32
X25519_HKDF_INFO = b"framecourier-x25519-chacha20-v1"


def _to_bytes(password):
    if password is None:
        raise ValueError("Password is required")
    if isinstance(password, bytes):
        if not password:
            raise ValueError("Password must not be empty")
        return password
    if isinstance(password, str):
        if not password:
            raise ValueError("Password must not be empty")
        return password.encode("utf-8")
    raise TypeError("Password must be str or bytes")


def new_salt():
    return os.urandom(SALT_BYTES)


def new_nonce():
    return os.urandom(NONCE_BYTES)


def derive_key_pbkdf2(password, salt, iterations=DEFAULT_PBKDF2_ITERATIONS):
    pw = _to_bytes(password)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, iterations=iterations)
    return kdf.derive(pw)


def derive_key_argon2id(password, salt, time_cost=DEFAULT_ARGON2_TIME, memory_kb=DEFAULT_ARGON2_MEMORY_KB, parallelism=DEFAULT_ARGON2_PARALLELISM):
    pw = _to_bytes(password)
    return hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kb,
        parallelism=parallelism,
        hash_len=KEY_BYTES,
        type=Argon2Type.ID,
    )


def derive_key(password, salt, kdf=KDF_ARGON2ID, **kwargs):
    if kdf == KDF_PBKDF2:
        iterations = kwargs.get("iterations", DEFAULT_PBKDF2_ITERATIONS)
        return derive_key_pbkdf2(password, salt, iterations=iterations)
    if kdf == KDF_ARGON2ID:
        return derive_key_argon2id(
            password,
            salt,
            time_cost=kwargs.get("time_cost", DEFAULT_ARGON2_TIME),
            memory_kb=kwargs.get("memory_kb", DEFAULT_ARGON2_MEMORY_KB),
            parallelism=kwargs.get("parallelism", DEFAULT_ARGON2_PARALLELISM),
        )
    raise ValueError(f"Unsupported KDF: {kdf}")


def _build_ctr_cipher(key, nonce):
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"Nonce must be {NONCE_BYTES} bytes")
    iv = nonce + b"\x00\x00\x00\x00"
    return Cipher(algorithms.AES(key), modes.CTR(iv))


def aes_ctr_encryptor(key, nonce):
    return _build_ctr_cipher(key, nonce).encryptor()


def aes_ctr_decryptor(key, nonce):
    return _build_ctr_cipher(key, nonce).decryptor()


def _chunk_nonce(base_nonce, index):
    if len(base_nonce) != NONCE_BYTES:
        raise ValueError(f"Base nonce must be {NONCE_BYTES} bytes")
    counter = struct.pack(">Q", index)
    out = bytearray(base_nonce)
    for i in range(8):
        out[NONCE_BYTES - 8 + i] ^= counter[i]
    return bytes(out)


class _ChunkedAEADStream:
    """Streaming AEAD: plaintext fed in arbitrary sizes, ciphertext emitted in
    ``CHUNK_SIZE``+tag-sized blocks. ``finalize`` flushes the trailing partial chunk.
    """

    def __init__(self, aead, base_nonce, encrypt, chunk_size=CHUNK_SIZE):
        self._aead = aead
        self._base_nonce = base_nonce
        self._encrypt = encrypt
        self._chunk_size = chunk_size
        self._buffer = bytearray()
        self._index = 0
        self._closed = False

    def update(self, data):
        if self._closed:
            raise RuntimeError("Stream finalized")
        if not data:
            return b""
        self._buffer.extend(data)
        out = bytearray()
        step = self._chunk_size if self._encrypt else self._chunk_size + AEAD_TAG_BYTES
        while len(self._buffer) >= step:
            chunk = bytes(self._buffer[:step])
            del self._buffer[:step]
            nonce = _chunk_nonce(self._base_nonce, self._index)
            if self._encrypt:
                out.extend(self._aead.encrypt(nonce, chunk, None))
            else:
                out.extend(self._aead.decrypt(nonce, chunk, None))
            self._index += 1
        return bytes(out)

    def finalize(self):
        if self._closed:
            raise RuntimeError("Stream already finalized")
        self._closed = True
        if not self._buffer:
            return b""
        chunk = bytes(self._buffer)
        self._buffer.clear()
        nonce = _chunk_nonce(self._base_nonce, self._index)
        self._index += 1
        if self._encrypt:
            return self._aead.encrypt(nonce, chunk, None)
        return self._aead.decrypt(nonce, chunk, None)


def aes_gcm_encryptor(key, base_nonce):
    return _ChunkedAEADStream(AESGCM(key), base_nonce, encrypt=True)


def aes_gcm_decryptor(key, base_nonce):
    return _ChunkedAEADStream(AESGCM(key), base_nonce, encrypt=False)


def chacha_poly_encryptor(key, base_nonce):
    return _ChunkedAEADStream(ChaCha20Poly1305(key), base_nonce, encrypt=True)


def chacha_poly_decryptor(key, base_nonce):
    return _ChunkedAEADStream(ChaCha20Poly1305(key), base_nonce, encrypt=False)


def aead_overhead_bytes(plaintext_len, chunk_size=CHUNK_SIZE):
    """Bytes added by chunked AEAD: one tag per chunk including the final partial chunk."""
    if plaintext_len <= 0:
        return AEAD_TAG_BYTES
    full = plaintext_len // chunk_size
    partial = 1 if (plaintext_len % chunk_size) else 0
    return (full + partial) * AEAD_TAG_BYTES


def make_encryptor(layer, key, base_nonce):
    if layer == LAYER_AES_CTR:
        return aes_ctr_encryptor(key, base_nonce)
    if layer == LAYER_AES_GCM:
        return aes_gcm_encryptor(key, base_nonce)
    if layer == LAYER_CHACHA_POLY:
        return chacha_poly_encryptor(key, base_nonce)
    raise ValueError(f"Unsupported crypto layer: {layer}")


def make_decryptor(layer, key, base_nonce):
    if layer == LAYER_AES_CTR:
        return aes_ctr_decryptor(key, base_nonce)
    if layer == LAYER_AES_GCM:
        return aes_gcm_decryptor(key, base_nonce)
    if layer == LAYER_CHACHA_POLY:
        return chacha_poly_decryptor(key, base_nonce)
    raise ValueError(f"Unsupported crypto layer: {layer}")


def b64e(blob):
    return base64.b64encode(blob).decode("ascii")


def b64d(text):
    return base64.b64decode(text.encode("ascii"))


# ---------------------------------------------------------------------------
# X25519 asymmetric layer
# ---------------------------------------------------------------------------

_X25519_PRIV_HEADER = b"FCX25519-PRIVATE-KEY-v1\n"
_X25519_PUB_HEADER = b"FCX25519-PUBLIC-KEY-v1\n"


def x25519_generate_keypair():
    """Return (private_key_bytes, public_key_bytes), both 32 bytes."""
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    priv_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


def x25519_pubkey_from_private(priv_raw):
    sk = X25519PrivateKey.from_private_bytes(priv_raw)
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_serialize_private(priv_raw):
    if len(priv_raw) != X25519_PRIVKEY_BYTES:
        raise ValueError("X25519 private key must be 32 bytes")
    return _X25519_PRIV_HEADER + base64.b64encode(priv_raw) + b"\n"


def x25519_serialize_public(pub_raw):
    if len(pub_raw) != X25519_PUBKEY_BYTES:
        raise ValueError("X25519 public key must be 32 bytes")
    return _X25519_PUB_HEADER + base64.b64encode(pub_raw) + b"\n"


def _parse_x25519_blob(text, header):
    if isinstance(text, str):
        text = text.encode("ascii")
    text = text.strip()
    if not text.startswith(header.strip()):
        raise ValueError("Not a FrameCourier X25519 key blob")
    lines = [ln for ln in text.splitlines() if not ln.startswith(b"FCX25519")]
    if not lines:
        raise ValueError("Empty key blob")
    raw = base64.b64decode(b"".join(lines))
    return raw


def x25519_load_private(text):
    raw = _parse_x25519_blob(text, _X25519_PRIV_HEADER)
    if len(raw) != X25519_PRIVKEY_BYTES:
        raise ValueError(f"Expected {X25519_PRIVKEY_BYTES}-byte private key, got {len(raw)}")
    return raw


def x25519_load_public(text):
    raw = _parse_x25519_blob(text, _X25519_PUB_HEADER)
    if len(raw) != X25519_PUBKEY_BYTES:
        raise ValueError(f"Expected {X25519_PUBKEY_BYTES}-byte public key, got {len(raw)}")
    return raw


# ---------- age interop ----------

_AGE_PUB_HRP = "age"
_AGE_PRIV_HRP = "AGE-SECRET-KEY-"


def x25519_to_age_public(pub_raw):
    """Encode a 32-byte X25519 public key as an ``age1...`` recipient string."""
    from . import bech32
    if len(pub_raw) != X25519_PUBKEY_BYTES:
        raise ValueError("X25519 public key must be 32 bytes")
    return bech32.encode(_AGE_PUB_HRP, pub_raw)


def x25519_to_age_secret(priv_raw):
    """Encode a 32-byte X25519 private key as an ``AGE-SECRET-KEY-1...`` string."""
    from . import bech32
    if len(priv_raw) != X25519_PRIVKEY_BYTES:
        raise ValueError("X25519 private key must be 32 bytes")
    return bech32.encode(_AGE_PRIV_HRP, priv_raw).upper()


def x25519_from_age_public(text):
    """Parse an ``age1...`` recipient string. Returns raw 32-byte X25519 public key."""
    from . import bech32
    if isinstance(text, bytes):
        text = text.decode("ascii", errors="replace")
    text = text.strip().splitlines()
    # Tolerate # comment lines that age tools sometimes write.
    candidates = [ln.strip() for ln in text if ln.strip() and not ln.strip().startswith("#")]
    for cand in candidates:
        if cand.lower().startswith("age1"):
            return bech32.decode(_AGE_PUB_HRP, cand.lower())
    raise ValueError("No age recipient line (age1...) found")


def x25519_from_age_secret(text):
    """Parse an age private key blob. Returns raw 32-byte X25519 private key."""
    from . import bech32
    if isinstance(text, bytes):
        text = text.decode("ascii", errors="replace")
    text = text.strip().splitlines()
    candidates = [ln.strip() for ln in text if ln.strip() and not ln.strip().startswith("#")]
    for cand in candidates:
        upper = cand.upper()
        if upper.startswith("AGE-SECRET-KEY-1"):
            return bech32.decode(_AGE_PRIV_HRP, upper)
    raise ValueError("No age secret line (AGE-SECRET-KEY-1...) found")


def x25519_derive_shared(local_priv_raw, peer_pub_raw):
    sk = X25519PrivateKey.from_private_bytes(local_priv_raw)
    pk = X25519PublicKey.from_public_bytes(peer_pub_raw)
    return sk.exchange(pk)


def _hkdf_key(shared, salt):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        info=X25519_HKDF_INFO,
    ).derive(shared)


def x25519_sender_encryptor(recipient_pub_raw, salt, base_nonce):
    """Generate an ephemeral keypair, derive the per-carrier key, return
    (ephemeral_public_key_bytes, chunked_chacha20poly1305_encryptor)."""
    eph_priv, eph_pub = x25519_generate_keypair()
    shared = x25519_derive_shared(eph_priv, recipient_pub_raw)
    key = _hkdf_key(shared, salt)
    return eph_pub, chacha_poly_encryptor(key, base_nonce)


def x25519_recipient_decryptor(recipient_priv_raw, ephemeral_pub_raw, salt, base_nonce):
    shared = x25519_derive_shared(recipient_priv_raw, ephemeral_pub_raw)
    key = _hkdf_key(shared, salt)
    return chacha_poly_decryptor(key, base_nonce)


# ---------- Multi-recipient X25519 (envelope encryption) ----------

X25519_WRAP_NONCE = b"\x00" * NONCE_BYTES
X25519_WRAPPED_DEK_BYTES = KEY_BYTES + 16  # 32 ct + 16 tag


def x25519_multi_envelope_seal(recipient_pubs, salt):
    """Generate ephemeral keypair + random DEK. Wrap the DEK once per recipient.

    Returns (eph_pub_bytes, wrapped_deks_list, dek). The DEK should be used to
    encrypt the actual payload (typically with ChaCha20-Poly1305 chunked).
    Each wrapped DEK is ``X25519_WRAPPED_DEK_BYTES`` bytes.
    """
    if not recipient_pubs:
        raise ValueError("At least one recipient public key is required")
    eph_priv, eph_pub = x25519_generate_keypair()
    dek = os.urandom(KEY_BYTES)
    wrapped = []
    for pk_recipient in recipient_pubs:
        shared = x25519_derive_shared(eph_priv, pk_recipient)
        wrap_key = _hkdf_key(shared, salt)
        aead = ChaCha20Poly1305(wrap_key)
        wrapped.append(aead.encrypt(X25519_WRAP_NONCE, dek, None))
    return eph_pub, wrapped, dek


# ---------- Ed25519 signing ----------

_ED25519_PRIV_HEADER = b"FCED25519-PRIVATE-KEY-v1\n"
_ED25519_PUB_HEADER = b"FCED25519-PUBLIC-KEY-v1\n"

ED25519_PRIVKEY_BYTES = 32
ED25519_PUBKEY_BYTES = 32
ED25519_SIG_BYTES = 64


def ed25519_generate_keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


def ed25519_pubkey_from_private(priv_raw):
    sk = Ed25519PrivateKey.from_private_bytes(priv_raw)
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_serialize_private(priv_raw):
    if len(priv_raw) != ED25519_PRIVKEY_BYTES:
        raise ValueError("Ed25519 private key must be 32 bytes")
    return _ED25519_PRIV_HEADER + base64.b64encode(priv_raw) + b"\n"


def ed25519_serialize_public(pub_raw):
    if len(pub_raw) != ED25519_PUBKEY_BYTES:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return _ED25519_PUB_HEADER + base64.b64encode(pub_raw) + b"\n"


def ed25519_load_private(text):
    if isinstance(text, str):
        text = text.encode("ascii")
    text = text.strip()
    if not text.startswith(_ED25519_PRIV_HEADER.strip()):
        raise ValueError("Not a FrameCourier Ed25519 private key blob")
    lines = [ln for ln in text.splitlines() if not ln.startswith(b"FCED25519")]
    raw = base64.b64decode(b"".join(lines))
    if len(raw) != ED25519_PRIVKEY_BYTES:
        raise ValueError(f"Expected {ED25519_PRIVKEY_BYTES}-byte Ed25519 private key, got {len(raw)}")
    return raw


def ed25519_load_public(text):
    if isinstance(text, str):
        text = text.encode("ascii")
    text = text.strip()
    if not text.startswith(_ED25519_PUB_HEADER.strip()):
        raise ValueError("Not a FrameCourier Ed25519 public key blob")
    lines = [ln for ln in text.splitlines() if not ln.startswith(b"FCED25519")]
    raw = base64.b64decode(b"".join(lines))
    if len(raw) != ED25519_PUBKEY_BYTES:
        raise ValueError(f"Expected {ED25519_PUBKEY_BYTES}-byte Ed25519 public key, got {len(raw)}")
    return raw


def ed25519_sign(priv_raw, message):
    sk = Ed25519PrivateKey.from_private_bytes(priv_raw)
    return sk.sign(message)


def ed25519_verify(pub_raw, signature, message):
    """Return True on valid signature, False otherwise."""
    try:
        pk = Ed25519PublicKey.from_public_bytes(pub_raw)
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def x25519_multi_envelope_open(local_priv, eph_pub, wrapped_list, salt):
    """Try each wrapped DEK with the local private key. Returns the DEK on the
    first slot that authenticates, or ``None`` if no slot matches."""
    shared = x25519_derive_shared(local_priv, eph_pub)
    wrap_key = _hkdf_key(shared, salt)
    aead = ChaCha20Poly1305(wrap_key)
    for wrapped_dek in wrapped_list:
        try:
            return aead.decrypt(X25519_WRAP_NONCE, wrapped_dek, None)
        except Exception:
            continue
    return None


# --- Backwards compat aliases for the original AES-CTR API used by segmenter.py ---

CIPHER_NAME = LAYER_AES_CTR
KDF_NAME = KDF_PBKDF2
DEFAULT_KDF_ITERATIONS = DEFAULT_PBKDF2_ITERATIONS


def encryptor(password, salt, nonce, iterations=DEFAULT_PBKDF2_ITERATIONS):
    key = derive_key_pbkdf2(password, salt, iterations=iterations)
    return aes_ctr_encryptor(key, nonce)


def decryptor(password, salt, nonce, iterations=DEFAULT_PBKDF2_ITERATIONS):
    key = derive_key_pbkdf2(password, salt, iterations=iterations)
    return aes_ctr_decryptor(key, nonce)


class EncryptingReader:
    """Backwards-compatible AES-CTR streaming wrapper used by segmenter.py."""

    def __init__(self, source, encryptor_obj):
        self._source = source
        self._enc = encryptor_obj

    def read(self, n=-1):
        chunk = self._source.read(n)
        if not chunk:
            return b""
        return self._enc.update(chunk)

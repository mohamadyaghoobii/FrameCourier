"""Reed-Solomon forward error correction.

Wraps the ``reedsolo`` library with a fixed RS(255, 223) configuration: each
block of 223 data bytes produces 32 parity bytes for a total of 255 bytes per
codeword. The result can correct up to 16 byte errors per block (about 13 %
overhead).

The encode/decode functions split arbitrarily long input into 223-byte chunks,
pad the final chunk with zeros, and remember the original byte length so the
decoder can strip the padding.
"""

import struct

from reedsolo import RSCodec, ReedSolomonError

ECC_NONE = "none"
ECC_RS_255_223 = "rs-255-223"

ECC_IDS = {
    ECC_NONE: 0,
    ECC_RS_255_223: 1,
}
ECC_NAMES = {v: k for k, v in ECC_IDS.items()}

RS_DATA_PER_BLOCK = 223
RS_PARITY_PER_BLOCK = 32
RS_TOTAL_PER_BLOCK = RS_DATA_PER_BLOCK + RS_PARITY_PER_BLOCK

# 8-byte big-endian length prefix so the decoder can strip the trailing zero pad.
RS_LEN_PREFIX = 8


def encode_rs(data):
    """Encode ``data`` with RS(255,223). The output starts with an 8-byte
    big-endian length prefix that itself is *not* RS-encoded; this prefix tells
    the decoder how many real bytes there are once parity is stripped."""
    n = len(data)
    prefix = struct.pack(">Q", n)
    padded = data
    pad_len = (-n) % RS_DATA_PER_BLOCK
    if pad_len:
        padded = data + b"\x00" * pad_len
    codec = RSCodec(RS_PARITY_PER_BLOCK)
    parts = bytearray(prefix)
    for i in range(0, len(padded), RS_DATA_PER_BLOCK):
        block = padded[i:i + RS_DATA_PER_BLOCK]
        encoded = codec.encode(block)
        parts.extend(encoded)
    return bytes(parts)


def encoded_size(data_len):
    pad_len = (-data_len) % RS_DATA_PER_BLOCK
    blocks = (data_len + pad_len) // RS_DATA_PER_BLOCK
    return RS_LEN_PREFIX + blocks * RS_TOTAL_PER_BLOCK


def decode_rs(blob):
    """Inverse of ``encode_rs``. Raises ReedSolomonError if too many bytes are corrupt."""
    if len(blob) < RS_LEN_PREFIX:
        raise ValueError("RS blob too short for length prefix")
    n = struct.unpack(">Q", blob[:RS_LEN_PREFIX])[0]
    payload = blob[RS_LEN_PREFIX:]
    if len(payload) % RS_TOTAL_PER_BLOCK != 0:
        raise ValueError(f"RS blob length {len(payload)} not a multiple of {RS_TOTAL_PER_BLOCK}")
    codec = RSCodec(RS_PARITY_PER_BLOCK)
    out = bytearray()
    for i in range(0, len(payload), RS_TOTAL_PER_BLOCK):
        block = payload[i:i + RS_TOTAL_PER_BLOCK]
        decoded, _decoded_full, _errata = codec.decode(block)
        out.extend(decoded)
    return bytes(out[:n])


__all__ = [
    "ECC_NONE",
    "ECC_RS_255_223",
    "ECC_IDS",
    "ECC_NAMES",
    "RS_DATA_PER_BLOCK",
    "RS_PARITY_PER_BLOCK",
    "RS_TOTAL_PER_BLOCK",
    "encode_rs",
    "decode_rs",
    "encoded_size",
    "ReedSolomonError",
]

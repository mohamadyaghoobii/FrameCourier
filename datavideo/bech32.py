"""Minimal pure-Python Bech32 implementation (BIP-0173).

Only what FrameCourier needs for age interop: encode/decode for the bech32
variant (not bech32m), an 8-bit-to-5-bit converter, and HRP/data wiring.

Constant-time checksum verification is not attempted (Bech32 is not designed
for that). Inputs from disk should be trusted only after parsing succeeds.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_REV = {c: i for i, c in enumerate(CHARSET)}


def _polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp, data):
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _verify_checksum(hrp, data):
    return _polymod(_hrp_expand(hrp) + data) == 1


def convertbits(data, frombits, tobits, pad=True):
    """Generic group-of-bits converter used to pack 8-bit bytes into 5-bit groups."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(hrp, raw_bytes):
    """Encode 8-bit ``raw_bytes`` to a bech32 string with the given HRP."""
    data = convertbits(list(raw_bytes), 8, 5, True)
    if data is None:
        raise ValueError("Could not convert bits for bech32 encode")
    combined = data + _create_checksum(hrp.lower(), data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def decode(expected_hrp, string):
    """Decode a bech32 ``string``; verifies the HRP and returns the raw bytes
    that were originally encoded. Raises ValueError on any problem."""
    if any(ord(c) < 33 or ord(c) > 126 for c in string):
        raise ValueError("Bech32 string has invalid characters")
    if string.lower() != string and string.upper() != string:
        raise ValueError("Bech32 string mixes case")
    s = string.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("Bech32 separator missing or in wrong place")
    hrp = s[:pos]
    data_part = s[pos + 1:]
    if hrp != expected_hrp.lower():
        raise ValueError(f"Bech32 HRP mismatch: expected {expected_hrp!r}, got {hrp!r}")
    try:
        data = [_CHARSET_REV[c] for c in data_part]
    except KeyError as exc:
        raise ValueError(f"Bech32 data has invalid character: {exc}")
    if not _verify_checksum(hrp, data):
        raise ValueError("Bech32 checksum verification failed")
    decoded = convertbits(data[:-6], 5, 8, False)
    if decoded is None:
        raise ValueError("Bech32 data unpack failed")
    return bytes(decoded)

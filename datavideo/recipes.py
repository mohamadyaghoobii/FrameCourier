"""Named bundles of (mode, crypto, kdf, ecc) that the CLI uses for ``--preset``
and ``framecourier recipes``.

Each preset has:
  * a one-line label
  * a longer 'when to reach for this' note
  * the exact embed arguments it expands to

The recipe descriptions are the canonical place to put 'how do I use this
tool for X' guidance.
"""

from . import crypto, ecc, stego


PRESETS = {
    "paranoid": {
        "label": "Strongest symmetric config: edge-adaptive LSB + AES-GCM + Argon2id + Reed-Solomon ECC.",
        "when": (
            "Use when payload is moderate-size (under ~10% of cover capacity), the "
            "cover has natural texture, and the threat model includes a motivated "
            "forensic analyst. Highest visual fidelity, lowest blind-steganalysis "
            "score, AEAD integrity, and RS protection against sparse bit errors."
        ),
        "args": {
            "mode": stego.MODE_ADAPTIVE,
            "crypto": crypto.LAYER_AES_GCM,
            "kdf": crypto.KDF_ARGON2ID,
            "ecc": ecc.ECC_RS_255_223,
        },
        "needs": ["password"],
    },
    "stealth": {
        "label": "Default-strength stealth: shuffled LSB + AES-GCM + Argon2id.",
        "when": (
            "Recommended general default. Balances stealth, speed, and robustness "
            "for typical payloads on typical covers. Defeats simple clustering "
            "detection and is authenticated."
        ),
        "args": {
            "mode": stego.MODE_SHUFFLED,
            "crypto": crypto.LAYER_AES_GCM,
            "kdf": crypto.KDF_ARGON2ID,
            "ecc": ecc.ECC_NONE,
        },
        "needs": ["password"],
    },
    "robust": {
        "label": "Sequential LSB + ChaCha-Poly1305 + Argon2id + RS ECC.",
        "when": (
            "Use when the carrier will live on storage that may introduce sparse "
            "bit errors (USB sticks, NAS replication, CDs). RS-255-223 corrects up "
            "to 16 byte errors per 255-byte block. Pair with shuffled LSB if you "
            "also need steganalysis resistance."
        ),
        "args": {
            "mode": stego.MODE_SEQ,
            "crypto": crypto.LAYER_CHACHA_POLY,
            "kdf": crypto.KDF_ARGON2ID,
            "ecc": ecc.ECC_RS_255_223,
        },
        "needs": ["password"],
    },
    "asymmetric": {
        "label": "Shuffled LSB + X25519/ChaCha20-Poly1305 (no shared passphrase).",
        "when": (
            "Use when the recipient has published an X25519 public key and you do "
            "not want to share a passphrase. Forward secrecy across carriers; per-"
            "carrier ephemeral keypair. Best for one-to-one or one-to-many "
            "asynchronous delivery."
        ),
        "args": {
            "mode": stego.MODE_SHUFFLED,
            "crypto": crypto.LAYER_X25519_CHACHA,
            "kdf": crypto.KDF_HKDF_SHA256,
            "ecc": ecc.ECC_NONE,
        },
        "needs": ["recipient"],
    },
    "deniable": {
        "label": "Shuffled LSB + two-slot deniable AEAD.",
        "when": (
            "Use when you may be compelled to reveal a passphrase. The real and "
            "decoy passphrases each unlock their own slot; neither reveals the "
            "existence of the other. Provide --decoy-file and --decoy-password "
            "alongside --password."
        ),
        "args": {
            "mode": stego.MODE_SHUFFLED,
            "crypto": crypto.LAYER_DENIABLE,
            "kdf": crypto.KDF_ARGON2ID,
            "ecc": ecc.ECC_NONE,
        },
        "needs": ["password", "decoy-file"],
    },
    "plain": {
        "label": "No encryption, no ECC. Raw LSB hide.",
        "when": "Demo / testing only. Carriers are recoverable by anyone who finds them.",
        "args": {
            "mode": stego.MODE_SHUFFLED,
            "crypto": crypto.LAYER_NONE,
            "kdf": "none",
            "ecc": ecc.ECC_NONE,
        },
        "needs": [],
    },
}


def get(name):
    return PRESETS.get(name)


def names():
    return list(PRESETS.keys())


# ---------------------------------------------------------------------------
# Examples (rendered by ``framecourier examples``)
# ---------------------------------------------------------------------------

EXAMPLES = [
    {
        "name": "quick-symmetric",
        "title": "Quick symmetric: hide & recover a file with a passphrase.",
        "commands": [
            "python framecourier.py embed secret.zip carrier.mp4 --prompt-password",
            "python framecourier.py extract carrier.mp4 recovered.zip --prompt-password",
        ],
    },
    {
        "name": "asymmetric-flow",
        "title": "Asymmetric delivery: recipient publishes a public key.",
        "commands": [
            "# recipient generates a keypair (private stays local, public is shared):",
            "python framecourier.py keygen alice.key",
            "# sender hides a file using only alice.key.pub:",
            "python framecourier.py embed secret.zip carrier.mp4 --recipient alice.key.pub",
            "# alice recovers it with her private key:",
            "python framecourier.py extract carrier.mp4 recovered.zip --identity alice.key",
        ],
    },
    {
        "name": "deniable-pair",
        "title": "Plausible deniability: real + decoy under different passphrases.",
        "commands": [
            "$env:FC_REAL='right-pass'",
            "$env:FC_DECOY='innocuous-pass'",
            "python framecourier.py embed secret.zip carrier.mp4 \\",
            "    --decoy-file decoy.zip --password-env FC_REAL --decoy-password-env FC_DECOY",
            "# real password reveals secret.zip:",
            "python framecourier.py extract carrier.mp4 out.zip --password-env FC_REAL",
            "# decoy password reveals decoy.zip:",
            "python framecourier.py extract carrier.mp4 out.zip --password-env FC_DECOY",
        ],
    },
    {
        "name": "preset-paranoid",
        "title": "Use the 'paranoid' preset for strongest symmetric config.",
        "commands": [
            "python framecourier.py embed secret.zip carrier.mp4 --preset paranoid --prompt-password",
        ],
    },
    {
        "name": "audit-carrier",
        "title": "Look at a carrier without trying to extract it.",
        "commands": [
            "python framecourier.py probe carrier.mp4",
            "python framecourier.py info carrier.mp4",
            "python framecourier.py steganalyse carrier.mp4 --frames 8",
        ],
    },
    {
        "name": "evaluate-modes",
        "title": "Compare detection rates across modes on the same cover.",
        "commands": [
            "python framecourier.py evaluate --cover-video cover.mp4 --payload-size 50000",
        ],
    },
    {
        "name": "doctor",
        "title": "Validate the environment (FFmpeg, codecs, deps).",
        "commands": ["python framecourier.py doctor"],
    },
]

"""Catalogue of common errors with explanations and concrete fixes.

``framecourier why <substring>`` matches case-insensitively against the message
keys below. Each entry has a short ``cause`` paragraph and one or more concrete
``fix`` steps. Designed for users hitting a cryptic FrameCourier error in the
middle of an operation -- copy the relevant line of the error into ``why`` and
get a recipe back.
"""

CATALOGUE = [
    {
        "key": "Payload too large for cover",
        "cause": (
            "The plain payload (after optional ECC and crypto overhead) needs more LSB "
            "capacity than the cover can give. LSB capacity per yuv420p frame is "
            "W*H*3/16 bytes; multiply by frame_count for the total."
        ),
        "fix": [
            "Pick a longer cover (more frames) or a higher resolution.",
            "If using --ecc rs-255-223: drop ECC to free ~13% capacity (--ecc none).",
            "If using stego-adaptive with a high --adaptive-threshold: lower the threshold to use more positions.",
            "Run `framecourier cover-score <cover>` to see exact capacity per mode.",
        ],
    },
    {
        "key": "Could not decode first frame",
        "cause": (
            "The carrier file does not contain a readable yuv420p video stream, or the "
            "stream's first frame was truncated. Often means the file was re-encoded by "
            "an intermediary (chat app, cloud upload) or is corrupt."
        ),
        "fix": [
            "Check with `ffprobe -v error -show_streams carrier.mp4` that there is exactly one h264 yuv420p video stream.",
            "Re-fetch the carrier as a binary file/attachment, not as a re-encoded video upload.",
            "Run `framecourier probe carrier.mp4` to see the container shape and any anomalies.",
        ],
    },
    {
        "key": "Not a FrameCourier stego carrier",
        "cause": (
            "The first frame's LSBs do not start with the FrameCourier magic "
            "(stego-v1 or stego-v2). Either the carrier is from another tool, has been "
            "re-encoded (LSBs destroyed), or you passed an unrelated video."
        ),
        "fix": [
            "Confirm you saved the carrier without re-encoding (file copy, not video share).",
            "If the carrier is large but ffprobe shows it is a tiny video, the file was likely truncated; re-download.",
            "Run `framecourier probe carrier.mp4` -- it reports v1/v2 magic and other signs.",
        ],
    },
    {
        "key": "SHA-256 mismatch",
        "cause": (
            "Decryption produced bytes whose SHA-256 does not match the value recorded "
            "in the carrier header. Two common reasons: wrong passphrase, or the "
            "carrier was modified after embed."
        ),
        "fix": [
            "Double-check the passphrase or --identity file you used.",
            "If using --verify-with, confirm the .sig file was produced by the same signer.",
            "If you imported the carrier through chat/cloud, re-fetch as a file attachment without re-encoding.",
        ],
    },
    {
        "key": "Wrong password or carrier modified",
        "cause": "Same root cause as a SHA-256 mismatch -- the recovered plaintext fails the integrity check.",
        "fix": [
            "Re-enter the passphrase exactly. Passphrases are case-sensitive.",
            "If using AEAD (aes-gcm / chacha-poly / x25519-chacha20), this also fires if the carrier was tampered.",
        ],
    },
    {
        "key": "None of the wrapped slots match this private key",
        "cause": (
            "You are extracting an x25519-multi-chacha20 carrier with a private key that "
            "is not in the recipient set the sender used."
        ),
        "fix": [
            "Ask the sender to either re-embed with your pubkey listed, or send you a "
            "single-recipient carrier addressed only to you.",
            "Check `framecourier fingerprint <carrier>` to see the slot count -- if it is 1, the carrier is single-recipient.",
        ],
    },
    {
        "key": "Slot-set binding MAC mismatch",
        "cause": (
            "An x25519-multi-chacha20 carrier was tampered: somebody added, removed, or "
            "replaced one of the recipient slots after the sender produced it."
        ),
        "fix": [
            "Get a fresh copy of the carrier directly from the sender.",
            "If you control the embed, re-run embed and distribute the new carrier through an authenticated channel.",
        ],
    },
    {
        "key": "This carrier is encrypted",
        "cause": "The carrier's crypto layer is not 'none', but you did not pass a passphrase (or --identity).",
        "fix": [
            "For symmetric carriers: add --password, --password-env, --password-stdin, or --prompt-password.",
            "For asymmetric carriers: add --identity <X25519 private key file>.",
            "Inspect with `framecourier info <carrier>` to see which mode/crypto was used.",
        ],
    },
    {
        "key": "Cover video dimensions must be even",
        "cause": (
            "yuv420p requires both width and height to be even integers. Some webcams "
            "or screen captures produce odd dimensions."
        ),
        "fix": [
            "Re-encode the cover with `ffmpeg -i in.mp4 -vf scale=trunc(iw/2)*2:trunc(ih/2)*2 -c:v libx264 even.mp4`.",
            "Or use `framecourier make-cover` to generate a fresh test cover at known-good dimensions.",
        ],
    },
    {
        "key": "FFmpeg encoder failed",
        "cause": "libx264 (or another encoder) exited non-zero. Most common: the cover format is incompatible or libx264 is missing.",
        "fix": [
            "Run `framecourier doctor` to confirm libx264 is in your FFmpeg build.",
            "Try a smaller cover to rule out memory issues.",
            "Re-encode the cover to a known-good shape: `ffmpeg -i in.mp4 -c:v libx264 -pix_fmt yuv420p clean.mp4`.",
        ],
    },
    {
        "key": "Carrier missing ephemeral public key",
        "cause": "An asymmetric carrier was produced but the X25519 ephemeral public key field is all zeros, which should never happen.",
        "fix": [
            "Re-produce the carrier with a recent FrameCourier (>=0.4) version.",
            "If you produced this with a custom script, ensure you pass `recipient_pubkey` to `embed_stego`.",
        ],
    },
    {
        "key": "Reed-Solomon decoding failed",
        "cause": (
            "The carrier was produced with --ecc rs-255-223 and the recovered ciphertext "
            "contains more byte errors per 255-byte block than the code can correct (16)."
        ),
        "fix": [
            "Confirm the carrier was not re-encoded (RS can correct sparse errors, not bulk LSB destruction).",
            "If you produced the carrier yourself, re-embed and transfer as a file/attachment.",
        ],
    },
    {
        "key": "Neither deniable slot decrypts",
        "cause": "You provided a passphrase that does not match either slot of a deniable carrier.",
        "fix": [
            "Try the other passphrase (the real or the decoy).",
            "Inspect with `framecourier info` -- if crypto is 'deniable', there are exactly two slots, both AEAD-protected.",
        ],
    },
]


def lookup(query):
    """Return the catalogue entries whose key contains ``query`` (case-insensitive)."""
    q = query.lower()
    return [entry for entry in CATALOGUE if q in entry["key"].lower()]


def all_entries():
    return list(CATALOGUE)

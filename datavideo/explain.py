"""Detailed reference content for every mode / crypto layer / ECC layer.

The CLI ``explain`` command renders these dictionaries. Each entry is intended
to be a self-contained briefing: how the technique works, what it defeats, how
it can still be detected (SIEM / Sysmon / Event Viewer / ffprobe / steganalysis
/ manual), and what counter-measures the operator has. The text is intentionally
verbose -- this *is* the documentation.
"""

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

MODES = {
    "stego-seq": {
        "category": "mode",
        "summary": "Sequential LSB hide in lossless H.264 yuv420p. Simplest, fastest, most detectable.",
        "mechanism": """
Each yuv420p frame is decoded to raw pixel bytes. Bit ``i`` of the payload is
written to the least-significant bit of pixel byte ``i`` of the first frame
(after the 192-byte v2 header), spilling over into successive frames as needed.
Frames are re-encoded with ``libx264 -qp 0`` which is bit-exact lossless H.264
at yuv420p, so the LSBs survive the encode/decode roundtrip exactly.
""".strip(),
        "strengths": [
            "Implementation is small and trivially auditable.",
            "Fastest of the three stego modes (no per-frame PRNG, no variance scan).",
            "Visually identical to the cover: at most 1 / 255 brightness change per modified channel.",
            "Carrier reports as a single h264 yuv420p video stream to ffprobe / MediaInfo.",
        ],
        "weaknesses": [
            "Modifications cluster at the start of each frame. Chi-square and sample-pair statistical attacks have a much easier time spotting a 'high-entropy region, then natural region' boundary.",
            "If the payload is shorter than one frame, ONLY the first ~N bytes of the first frame have modified LSBs while the rest of the video is untouched -- this is the textbook signature stegdetect/StegSecret/aletheia look for.",
            "Bitrate of lossless H.264 is 5-20x a normal MP4 of the same length; a 'video file is much larger than its visible content warrants' rule will flag it.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": """
Single ``codec_name=h264``, ``pix_fmt=yuv420p``. No FFV1, no extra streams,
no project tags. Nothing visible at this layer. PASSES casual ffprobe.
""".strip(),
            "splunk_siem": """
Useful SPL signals:
  index=proxy OR index=dlp file_name="*.mp4"
    | stats values(uri_path) max(file_size) by user
    | where file_size > 5*1024*1024 AND duration < 30
    -> "video file too large for its claimed duration" anomaly.

  index=edr image_loaded="*ffmpeg*" command_line="*libx264*qp*0*"
    -> direct catch of lossless H.264 encode on endpoint (Sysmon Event 7).
""".strip(),
            "sysmon": """
Event ID 1 (ProcessCreate):    ffmpeg.exe with '-qp 0', '-c:v libx264' in
                                CommandLine. Build a rule on this exact pattern.
Event ID 11 (FileCreate):      .mp4 written under user Downloads / Desktop with
                                size that doesn't match the duration probed by
                                a follow-up ffprobe call.
Event ID 3 (NetworkConnect):   if the carrier is uploaded, look for unusual
                                file-size egress to file-sharing destinations.
""".strip(),
            "event_viewer": """
Microsoft-Windows-Sysmon/Operational  -- as above.
Microsoft-Windows-Windows Defender/Operational  -- Defender reads the file on
  write; no detection by default but custom ASR rules can fire on x264 process.
Security log 4663 (file access) on Downloads folder if SACL is configured.
""".strip(),
            "statistical_steganalysis": """
chi-square (Pfitzmann/Westfeld): ~99% detection on unencrypted payload longer
   than ~500 bytes. With encryption (uniform bits) chi-square drops to ~70-80%
   but is still significantly elevated vs. clean cover.
RS analysis (Fridrich):          spots the partial-frame embedding signature
   even with encryption -- the unmodified tail of the frame has very different
   LSB statistics from the modified head.
Sample-pair analysis:            similar story, sensitive to ~5-10% LSB
   modification rate which sequential mode definitely produces in the modified
   region.

Tools that automate this: stegdetect, StegSecret, aletheia, stegoVeritas,
binwalk -E (entropy spike).
""".strip(),
            "manual": """
- File-size sanity check: lossless 720p H.264 is ~16 Mbps; if a 'phone clip'
  reports that bitrate, that's the tell.
- Hex dump of a decoded frame (ffmpeg -i carrier.mp4 -f rawvideo -):  the first
  ~N bytes have uniformly random LSBs, the tail does not -- visible to the eye
  as a histogram of (byte & 1) per region.
- Visual diff of cover vs carrier frame: invisible to the eye but
  numpy.abs(cover - carrier).max() == 1 for modified pixels, 0 elsewhere.
""".strip(),
            "network_dlp": """
Most DLP focuses on MIME / extension / size. A 25 MB .mp4 looks normal to
generic DLP. Modern DLP (Symantec, Forcepoint) may run YARA across egress; no
public YARA rule for FrameCourier exists yet, but a rule on 'magic
\\xfc\\x46\\x43\\xa2 within first 16 KB of a video' would trivially flag the
v2 carrier (the magic lives in pixel-LSBs and would NOT be present here).
""".strip(),
        },
        "counter_detection": [
            "Always pair with --crypto aes-gcm or chacha-poly so the LSBs are uniformly random; chi-square is far less informative on encrypted bits.",
            "Prefer stego-shuffled or stego-adaptive for any non-trivial payload; reserve stego-seq for very small payloads where the modification region is essentially one frame anyway.",
            "Use a cover whose natural bitrate is plausibly high (screen recordings, archival).",
            "Never re-use the same cover across multiple carriers; reuse enables cover-difference attacks.",
        ],
        "best_for": "Tiny payloads, scripted batch jobs, situations where speed beats stealth.",
    },

    "stego-shuffled": {
        "category": "mode",
        "summary": "PRNG-scattered LSB positions keyed by a per-carrier random seed. Defeats the 'modifications cluster at start' tell.",
        "mechanism": """
Same lossless H.264 yuv420p backbone as stego-seq. Difference: payload bits are
written to LSB positions chosen by a per-frame PRNG. The PRNG is seeded by
SHA-256(position_seed || frame_index) where ``position_seed`` is 16 random bytes
written into the v2 header. The header itself still occupies a FIXED range
(positions 0..1535) of frame 0's LSBs so the extractor can find it without
prior knowledge.
""".strip(),
        "strengths": [
            "LSB modifications are spread uniformly across every frame; no spatial clustering.",
            "Chi-square / sample-pair attacks measure 'how non-uniform is the LSB distribution within a region'. Spreading modifications evenly raises the noise floor of those tests.",
            "Same visual fidelity as stego-seq (modifications still touch only the LSB).",
            "Carrier still reports as a single h264 yuv420p stream to ffprobe.",
        ],
        "weaknesses": [
            "The PRNG seed lives in the v2 header (in the first 1536 LSBs of frame 0). A focused analyst reading that header sees the same shape of stego carrier as stego-seq.",
            "Bitrate anomaly (lossless H.264) is still present.",
            "Doesn't defeat *content-aware* steganalysis (e.g., HUGO) which looks at where modifications fall relative to image content.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Identical to stego-seq: single h264 yuv420p stream, normal encoder tags. No leak.",
            "splunk_siem": "Same as stego-seq: bitrate-vs-duration anomaly, ffmpeg+libx264+qp 0 process pattern.",
            "sysmon": "Same Event ID 1 pattern on ffmpeg invocation. The Python process running FrameCourier is identical to stego-seq.",
            "event_viewer": "Identical to stego-seq.",
            "statistical_steganalysis": """
chi-square / sample-pair effectiveness drops sharply because the modifications
are spread across the whole frame instead of concentrated at the start. With
encrypted payload AND shuffled positions, generic LSB detectors typically score
'inconclusive' rather than 'positive'.
Content-aware detectors (HUGO, SPAM features) are NOT defeated by shuffling --
they look at where modifications fall relative to image edges and textures.
""".strip(),
            "manual": "Same hex-level analysis applies, but the 'partial-modification region' tell is gone.",
            "network_dlp": "Same as stego-seq.",
        },
        "counter_detection": [
            "Use --crypto aes-gcm or chacha-poly so the bits themselves are uniform random; combined with shuffling this is the strongest *non-adaptive* defense.",
            "Use a longer cover than strictly needed so the modification rate per frame stays low (under ~25%).",
        ],
        "best_for": "Default for any payload that isn't trivially small. Best balance of stealth vs. simplicity.",
    },

    "stego-adaptive": {
        "category": "mode",
        "summary": "Embed only in high-variance pixel positions (edges / textures). Reduces steganalysis traces by hiding noise inside natural noise.",
        "mechanism": """
For each frame, compute per-byte 'edge strength' as
``|(byte_i >> 1) - (byte_{i-1} >> 1)|`` -- the absolute change between adjacent
samples, using the upper 7 bits so the LSB modifications cannot change the
selector's decisions. Positions whose edge strength is at or above the configured
threshold form the candidate set. Candidates are then PRNG-shuffled (like
stego-shuffled). Payload bits are hidden only at those positions; smooth regions
(skies, walls) are left bit-exact.
""".strip(),
        "strengths": [
            "Hides modifications in regions that ALREADY have high LSB randomness due to natural image noise. Generic chi-square / sample-pair sees no statistical lift over baseline.",
            "Visual fidelity is even better than seq/shuffled: smooth gradients are 100% preserved, only textured areas change at LSB.",
            "Resists basic blind steganalysis significantly better than seq or shuffled.",
        ],
        "weaknesses": [
            "Capacity depends on the cover's natural texture. A featureless cover (blue sky video) has tiny capacity at any meaningful threshold.",
            "Header still lives in fixed positions of frame 0 (so the extractor can find it), so frame 0's first 1.5 KB is still detectable as 'modified' even if the rest is clean.",
            "Content-aware steganalysis (S-UNIWARD, MiPOD) is specifically tuned for exactly this kind of embedding and CAN detect it given enough payload.",
            "Threshold has to be high enough to give meaningful stealth but low enough to fit the payload. Wrong choice can fail at embed time.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Identical to stego-seq/shuffled: single h264 yuv420p stream.",
            "splunk_siem": "Same bitrate anomaly; same ffmpeg process pattern.",
            "sysmon": "Same Event ID 1 patterns.",
            "event_viewer": "Same as stego-seq.",
            "statistical_steganalysis": """
Generic blind steganalysis (chi-square, RS, sample-pair, BIC): minimal lift
above clean cover; encrypted+adaptive is usually the limit of what these tools
can detect.
Content-aware steganalysis (S-UNIWARD, MiPOD, SRNet, YeNet): tuned for
content-adaptive embedding; CAN detect it but requires curated training data
and significant analyst expertise. Out of reach for typical SOC.
Cover-source mismatch: if the analyst has the ORIGINAL cover video (e.g., they
know what source you started from), a simple subtract-and-LSB-diff trivially
recovers all hidden bits. NEVER use a publicly findable cover.
""".strip(),
            "manual": "Diff against original cover (if obtained) shows the exact pixels modified.",
            "network_dlp": "Same generic posture as the other stego modes.",
        },
        "counter_detection": [
            "Use a cover with lots of natural texture: outdoor scenes, sports, video games, screen recordings of busy UIs. Avoid flat backgrounds.",
            "Choose --adaptive-threshold so 50-70% of pixels are eligible, then send 1/3 of capacity. Lower modification rate = lower detection probability.",
            "Always pair with --crypto aes-gcm and Argon2id KDF.",
            "Never re-distribute the original cover anywhere a steganalyst could pair it with the carrier.",
        ],
        "best_for": "Adversary is more than a SOC analyst (e.g., motivated forensic team), payload is moderate size, cover is naturally textured.",
    },

    "distributed": {
        "category": "mode",
        "summary": "Visible cover stream + one or more lossless FFV1 data streams in an MKV container. Not stego: data is in extra streams.",
        "mechanism": """
The cover is muxed into the MKV unchanged. Payload bytes are packed into raw
yuv420p frames of arbitrary FFV1-encoded streams which are added as additional
video streams (with empty title tag, language=und). The extractor recognises
these by ffv1 codec + a frame magic in pixel-position 0..3 of frame 0 of each
data stream.
""".strip(),
        "strengths": [
            "The visible cover stream is byte-exact unchanged; this matters if you need the cover to be cryptographically identical to its source.",
            "Capacity is gigantic: one full yuv420p frame per data frame, no LSB-only restriction.",
            "Fast encode (FFV1 is much faster than libx264 -qp 0).",
        ],
        "weaknesses": [
            "Two video streams in one MKV: trivially visible to ffprobe / MediaInfo. SOC-level detection is much easier than any stego mode.",
            "FFV1 codec in a casual file is itself a flag.",
            "MKV container with multiple video streams is uncommon in normal user content.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": """
Two STREAM blocks of codec_type=video. One ``h264`` (the cover), one or more
``ffv1`` (the payload). Even with stripped tags this is anomalous: a normal
multi-stream MKV has one video + N audio + N subtitle.
""".strip(),
            "splunk_siem": """
index=dlp file_name="*.mkv"
  | rex "(?<vid_streams>\\d+) video streams"
  | where vid_streams > 1
  -> matches almost any FrameCourier distributed carrier.
""".strip(),
            "sysmon": "Process pattern includes ffmpeg invocations with multiple ``-c:v ffv1`` outputs.",
            "event_viewer": "Same as stego modes for process-level visibility.",
            "statistical_steganalysis": "Not applicable -- the data isn't hidden, it's just in an extra stream.",
            "manual": "Open in MKVToolNix GUI: you see all streams listed by index. Immediate red flag.",
            "network_dlp": "MKV with >1 video stream + large size is a strong heuristic for an automated rule.",
        },
        "counter_detection": [
            "Use this mode only when you specifically need the cover byte-exact. Otherwise prefer stego modes.",
            "Use ``--segments 1`` to keep the FFV1 stream count minimal.",
        ],
        "best_for": "Research, integrity-critical workflows where the cover MUST match its source exactly.",
    },

    "stego-robust": {
        "category": "mode",
        "summary": "Planned: lossy H.264 with heavy ECC. NOT implemented at the LSB layer because empirical measurement shows it cannot work there.",
        "mechanism": """
The intent was: encode at libx264 CRF 14--18 (visually transparent lossy
H.264), apply Reed-Solomon (255, 127) for ~100% redundancy, and replicate each
bit across 3--5 pixels with majority voting on extract. The goal was to
produce carriers that survive a single platform re-encode (YouTube, Telegram).
""".strip(),
        "strengths": ["None at present -- the LSB approach does not work; see below."],
        "weaknesses": [
            "Empirical: a synthetic FrameCourier roundtrip on a Mandelbrot cover at 640x360, "
            "encoded with libx264 -preset veryfast at several CRFs, gave the following LSB "
            "survival rates: CRF 0 (lossless) 100%, CRF 14 ~16%, CRF 18 ~17%, CRF 23 ~19%, CRF 28 ~19%. "
            "Even with 3x repetition + RS(255, 127) the residual error rate is too high to recover "
            "the payload reliably.",
            "Higher-bit hiding (e.g., bit 3 or 4 instead of LSB) would survive but is visually obvious.",
            "Surviving lossy H.264 reliably requires DCT-domain hiding (F5-family), motion-vector "
            "modification, or spread-spectrum techniques -- all research-level engineering work.",
        ],
        "detection_vectors": {},
        "counter_detection": [
            "Until a working DCT-domain implementation lands, the practical advice is: do not upload "
            "FrameCourier carriers to services that re-encode. Send them as file attachments instead.",
        ],
        "best_for": "Not yet usable. Tracked on the roadmap as Phase 8+ research work.",
    },
    "legacy": {
        "category": "mode",
        "summary": "Original FrameCourier carrier: single FFV1 stream at duration/2, no encryption. Kept for compatibility only.",
        "mechanism": "Mux the cover as stream 0 and one FFV1 data stream at offset=duration/2 as stream 1.",
        "strengths": ["Simplest possible carrier layout for the very first FrameCourier carriers."],
        "weaknesses": [
            "Two streams, one of them FFV1 -- same exposure as distributed mode.",
            "No --password support; payload is plaintext in raw frame pixels.",
            "Considered deprecated; do not use for new carriers.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Same posture as distributed mode but with exactly 2 streams.",
            "splunk_siem": "Same multi-stream-MKV heuristic.",
            "sysmon": "Same as distributed.",
            "event_viewer": "Same as distributed.",
            "statistical_steganalysis": "Not applicable.",
            "manual": "MKVToolNix shows the two streams immediately.",
            "network_dlp": "Same as distributed.",
        },
        "counter_detection": ["Migrate to stego modes."],
        "best_for": "Reading back old carriers only.",
    },
}


# ---------------------------------------------------------------------------
# Crypto layers
# ---------------------------------------------------------------------------

CRYPTO_LAYERS = {
    "none": {
        "category": "crypto",
        "summary": "No encryption. Payload bytes are stored in the clear (after optional ECC).",
        "mechanism": "Payload is written to the carrier without any cryptographic transformation.",
        "strengths": ["No password to lose; recovery requires only the carrier."],
        "weaknesses": [
            "Payload is recoverable by anyone who finds the carrier.",
            "LSB statistical attacks see structured (non-uniform) bits; chi-square is highly effective.",
            "ECC alone does NOT provide confidentiality, only integrity against single-bit corruption.",
        ],
        "detection_vectors": {
            "statistical_steganalysis": "Plaintext bits are structured (file headers, ASCII, etc.) and chi-square trivially detects modification.",
            "manual": "If carrier is dumped to raw pixels, well-known file magics (PK, ZIP, JFIF, PDF) appear at the start of LSB-extracted data.",
        },
        "counter_detection": ["Don't use this layer for anything sensitive."],
        "best_for": "Demos, testing, public artifacts.",
    },
    "aes-ctr": {
        "category": "crypto",
        "summary": "AES-256-CTR with PBKDF2-HMAC-SHA256 (200k iters). Streaming stream-cipher, no per-chunk auth.",
        "mechanism": """
Key = PBKDF2(password, salt=16 random bytes, iterations=200,000, alg=HMAC-SHA256).
Cipher = AES-256 in CTR mode; 12-byte nonce + 4-byte counter starting at zero.
Plaintext bytes are XORed with the keystream produced from (key, nonce, counter).
Integrity is provided downstream by the plaintext SHA-256 stored in the header
-- not by the cipher itself.
""".strip(),
        "strengths": [
            "Streaming-friendly: no buffer requirement, works on arbitrarily large files.",
            "Output is the same size as input (no AEAD tag overhead).",
            "Encrypted bits are uniformly random; defeats blind chi-square on the encrypted region.",
        ],
        "weaknesses": [
            "No authenticated encryption. Bit-flip attacks are silent until the final plaintext SHA-256 check.",
            "PBKDF2 is GPU/ASIC-friendly; brute force at ~10^6 guesses/sec/GPU. Modern KDFs (Argon2id) are preferred.",
            "Nonce reuse across two carriers with the same password would leak XOR of plaintexts. New nonce per carrier is enforced but worth noting.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Not visible -- crypto is at payload layer, not container layer.",
            "splunk_siem": "Not directly visible. Indirect tell: high-entropy file content (entropy ~= 8.0 bits/byte).",
            "sysmon": "Not visible.",
            "event_viewer": "Not visible.",
            "statistical_steganalysis": """
Within the stego region the encrypted bits look uniformly random, which DEFEATS
chi-square. RS / sample-pair analysis still works on the *modification pattern*
(which pixels were touched) -- encryption doesn't help there.
""".strip(),
            "manual": "Encrypted bytes have entropy ~= 8.0 bits/byte; no file magics visible in LSB dump.",
        },
        "counter_detection": ["Prefer aes-gcm or chacha-poly for authenticated encryption."],
        "best_for": "Backward compatibility with FrameCourier v1 carriers, very large files where AEAD overhead matters.",
    },
    "aes-gcm": {
        "category": "crypto",
        "summary": "AES-256-GCM in 64 KiB chunks. AEAD: tamper-evident. Pairs with Argon2id KDF.",
        "mechanism": """
Key = Argon2id(password, salt=16 random bytes, t=3, m=64 MiB, p=4). 32-byte key.
Cipher = AES-256-GCM. Plaintext is split into 64 KiB chunks. Each chunk gets a
unique 12-byte nonce derived as base_nonce XOR chunk_index, and its own 16-byte
Poly1305-style auth tag. The encrypted stored blob is
   ct_0 || tag_0 || ct_1 || tag_1 || ... || ct_n || tag_n
The header carries base_nonce and Argon2 parameters; salt is per-carrier random.
""".strip(),
        "strengths": [
            "Authenticated encryption: any bit flip in any chunk fails that chunk's tag, decryption aborts immediately.",
            "Argon2id is memory-hard: GPU/ASIC brute force is hundreds of times slower per guess than against PBKDF2.",
            "Streaming-friendly via the chunked construction; no need to hold the whole plaintext in memory.",
            "Encrypted bits are uniformly random; blind chi-square is defeated.",
        ],
        "weaknesses": [
            "Overhead: 16 bytes per 64 KiB chunk (~0.025%).",
            "First failed chunk halts decryption; partial recovery is not supported.",
            "Argon2id needs ~64 MiB RAM at default params; very low-memory devices may need lower memory_kb (set explicitly).",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Not visible.",
            "splunk_siem": "Not directly visible.",
            "sysmon": "Not visible.",
            "event_viewer": "Not visible.",
            "statistical_steganalysis": "Same posture as aes-ctr (defeats blind chi-square on bit values, NOT modification-position attacks).",
            "manual": "Same -- encrypted bytes are statistically uniform.",
        },
        "counter_detection": ["Pair with a strong passphrase (>=14 chars random or a 5+ word diceware passphrase)."],
        "best_for": "Default for any real use. The combination of authenticated encryption + memory-hard KDF is the modern best practice.",
    },
    "deniable": {
        "category": "crypto",
        "summary": "Two-slot AEAD: real payload + decoy payload under separate passphrases. Neither password reveals the existence of the other slot.",
        "mechanism": """
The sender provides two payloads (real and decoy) and two passphrases.
Both plaintexts are padded with random bytes to the SAME slot size, each
prefixed with a 4-byte length tag. Slot 0 uses ChaCha20-Poly1305 with key
Argon2id(real_password, salt_0) and nonce_0; slot 1 uses ChaCha20-Poly1305
with key Argon2id(decoy_password, salt_1) and nonce_1. The stored blob is
slot_0_ciphertext || slot_1_ciphertext. Both slots are byte-equal in length;
ciphertext order is fixed. The carrier header carries (salt_0, nonce_0,
salt_1, nonce_1) but no information that distinguishes which slot is "real".
Extraction tries the supplied passphrase against slot 0 first, then slot 1;
whichever slot's AEAD tag verifies wins, and the trailing random padding is
stripped using the per-slot 4-byte length prefix. The header's plaintext SHA
and plaintext length fields are set to zeros for deniable carriers so the
identifying SHA does not bind the carrier to one specific plaintext.
""".strip(),
        "strengths": [
            "Plausible deniability under coercion: revealing one passphrase does not betray the existence of the other slot.",
            "Per-slot AEAD: tampering with either ciphertext aborts decryption cleanly.",
            "Both slots are byte-identical in length and ciphertext structure -- there is no length-based tell about which is the 'real' payload.",
            "Same Argon2id memory-hard KDF as the symmetric AEAD layers; no degradation in key strength.",
        ],
        "weaknesses": [
            "Stored size is at least 2 x max(real_size, decoy_size) plus chunk-AEAD overhead.",
            "Number of slots (2) is structural and known; analysts who know the FrameCourier format know that exactly one of two slots is the real payload.",
            "Coercion model is limited: an adversary who watches you embed can see you supplied two payloads; deniability only protects after the fact, when only the carrier is available.",
            "The decoy must be a CREDIBLE payload of a similar size. A 1-byte decoy or an empty file leaks 'this is the real payload' indirectly.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Not visible at container layer.",
            "splunk_siem": "Not directly visible.",
            "sysmon": "Not visible.",
            "event_viewer": "Not visible.",
            "statistical_steganalysis": "Same posture as the AEAD layers: ciphertext is uniformly random, defeating blind chi-square on bit values. Modification position is governed by the chosen stego mode (seq/shuffled/adaptive).",
            "manual": "Carrier stored size is roughly twice an equivalent single-payload carrier. If an analyst knows the FrameCourier format, this can hint at deniable mode.",
        },
        "counter_detection": [
            "Pick a decoy that you can plausibly justify revealing -- a private journal, an old draft, a tax form. Empty decoys are an obvious tell.",
            "Make the decoy roughly the same size or larger than the real payload so a size-anomaly rule cannot distinguish them.",
            "Pair with --mode stego-shuffled so the modification pattern itself is not also a tell.",
        ],
        "best_for": "Adversarial environments where the operator may be compelled to reveal a passphrase (rubber-hose attacks, border searches). NEVER use as a substitute for proper key management.",
    },
    "x25519-multi-chacha20": {
        "category": "crypto",
        "summary": "Envelope encryption: one carrier addressed to many X25519 public keys at once. Each recipient unwraps with their own private key.",
        "mechanism": """
The sender provides a LIST of recipient public keys (one or more). One random
data encryption key (DEK) is generated per carrier. An ephemeral X25519 keypair
(sk_eph, pk_eph) is created. For every recipient i, the sender computes a
shared secret X25519(sk_eph, pk_i), derives a wrap-key with HKDF-SHA256(salt,
info="framecourier-x25519-chacha20-v1"), and uses that wrap-key with ChaCha20-
Poly1305 (fixed zero nonce, safe because each carrier uses a fresh DEK) to
encrypt the 32-byte DEK -- producing a 48-byte wrapped slot per recipient.

The carrier's stored blob is laid out as:

  1 byte:        slot_count N (1..255)
  N x 48 bytes:  wrapped DEKs, one per recipient (plus optional dummy slots)
  32 bytes:     HMAC-SHA256(DEK, "framecourier-slots-binding-v1" || pk_eph || slot_table)
                  -- binds the slot list to the ephemeral pubkey so an attacker
                  cannot strip dummies or substitute slots without invalidating
                  the MAC (they do not know the DEK).
  rest:          payload encrypted with ChaCha20-Poly1305 chunked under the DEK

The carrier header stores pk_eph, salt, and the base nonce. On extract, every
listed recipient can derive the same wrap-key from X25519(sk_recipient, pk_eph)
and try it against each wrapped slot; whichever slot's AEAD tag verifies yields
the DEK, which then verifies the binding MAC and decrypts the body. Non-
recipients see only random-looking wrapped slots that none of their wrap-keys
open.
""".strip(),
        "strengths": [
            "Single carrier for many recipients -- no per-recipient re-encode of the cover video.",
            "Recipient anonymity within the recipient set: any wrapped slot looks like any other to outsiders.",
            "Same AEAD guarantee as single-recipient: tampered slots fail their auth tag.",
            "Forward secrecy carried over from single-recipient X25519: the ephemeral secret is destroyed after embed.",
        ],
        "weaknesses": [
            "Carrier size grows by ~48 bytes per recipient (the wrapped DEK). 100 recipients = ~4.8 KB extra.",
            "Number of recipients is visible (1 byte) to anyone who decodes the LSBs of the first frame. Pad with dummy slots if you must hide the count.",
            "All recipients can decrypt the same plaintext: any one of them leaking the file also leaks all the others' copies.",
            "Compromising any one recipient's private key gives an attacker access to past carriers addressed to them. There is no per-message ratchet.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Not visible at container layer.",
            "splunk_siem": "Not directly visible.",
            "sysmon": "Not visible.",
            "event_viewer": "Not visible.",
            "statistical_steganalysis": "Same as the AEAD layers: ciphertext bits are uniformly random which defeats blind chi-square on the encrypted region.",
            "manual": "If the analyst knows the FrameCourier format, the slot_count byte at the start of the stored blob is recoverable from frame-0 LSBs and reveals the recipient set size.",
        },
        "counter_detection": [
            "Pad the recipient list with dummy slots (random 48-byte blobs that nobody can unwrap) to hide the real recipient count.",
            "Pair with stego-shuffled or stego-adaptive so the modification pattern itself does not also leak.",
            "Distribute recipient public keys through authenticated channels; otherwise an attacker who swaps in their own key can read the carrier.",
        ],
        "best_for": "Group communications, broadcast-style delivery to a set of recipients you have public keys for.",
    },
    "x25519-chacha20": {
        "category": "crypto",
        "summary": "Asymmetric: ChaCha20-Poly1305 keyed by an ephemeral X25519 ECDH share. Sender needs only the recipient's public key; no shared passphrase.",
        "mechanism": """
Sender holds the recipient's 32-byte X25519 public key. For every carrier the
sender generates a fresh ephemeral keypair (sk_eph, pk_eph), computes the shared
secret as X25519(sk_eph, pk_recipient), derives a 32-byte symmetric key with
HKDF-SHA256 (salt = 16 random bytes, info = "framecourier-x25519-chacha20-v1"),
and encrypts the payload with ChaCha20-Poly1305 in 64 KiB chunks. The carrier
header stores pk_eph (32 bytes), the random salt, and the base nonce. The
ephemeral secret key is discarded immediately after encryption.
Recipient holds the matching 32-byte private key; they recompute the same
shared secret, derive the same symmetric key, and authenticate-decrypt.
""".strip(),
        "strengths": [
            "No shared passphrase to coordinate; recipients publish only a public key.",
            "Forward secrecy across carriers: the ephemeral secret is destroyed after embed, so a future compromise of the recipient's private key still requires that private key to decrypt past carriers (no key escrow).",
            "AEAD-authenticated like aes-gcm/chacha-poly: tampered chunks abort decryption.",
            "X25519 is constant-time and side-channel friendly in cryptography.io.",
        ],
        "weaknesses": [
            "Adds 32 bytes (the ephemeral pubkey) to every carrier header. Detectable as 32 high-entropy bytes at offset 122 of the LSB-encoded header.",
            "Recipient compromise = past carrier compromise. There is no separate forward-secrecy ratchet.",
            "Public-key distribution is on you. If you fetch the recipient's pubkey over an untrusted channel, an attacker can substitute their own key.",
            "Argon2id memory hardness does NOT apply here; an attacker who steals the private key can decrypt instantly. Protect the private key file with disk encryption.",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Not visible at container layer.",
            "splunk_siem": "Not directly visible.",
            "sysmon": "Not visible.",
            "event_viewer": "Not visible.",
            "statistical_steganalysis": "Same as the symmetric AEAD layers: the ciphertext is uniformly random which defeats blind chi-square on the encrypted region.",
            "manual": "On a known FrameCourier carrier, a constant 32-byte high-entropy field at LSB offset 122 hints at an X25519 ephemeral pubkey. Without knowing the recipient's public key the analyst cannot link sender to recipient.",
        },
        "counter_detection": [
            "Pair with --mode stego-shuffled or stego-adaptive so the LSB positions themselves are not also a tell.",
            "Distribute recipient public keys out-of-band over an authenticated channel.",
            "Rotate recipient keypairs if you suspect any private-key compromise.",
        ],
        "best_for": "One-to-many or one-to-one delivery where the sender doesn't want to share a passphrase, or where the recipient may want a long-lived identity.",
    },
    "chacha-poly": {
        "category": "crypto",
        "summary": "XChaCha20-Poly1305 in 64 KiB chunks. AEAD with a faster software profile than AES-GCM on CPUs without AES-NI.",
        "mechanism": """
Key derivation identical to aes-gcm (Argon2id, 32-byte key).
Cipher = ChaCha20-Poly1305 over 64 KiB chunks; nonce + counter derivation identical
to aes-gcm. Same chunked storage layout: ct || tag per chunk.
""".strip(),
        "strengths": [
            "Same AEAD security profile as aes-gcm.",
            "Software-only: doesn't depend on AES-NI hardware acceleration; on ARM (Raspberry Pi, mobile) often faster than AES-GCM.",
            "Constant-time implementation in cryptography.io; resistant to timing side channels.",
        ],
        "weaknesses": [
            "Slightly less common in compliance frameworks than AES-GCM; some auditors only accept FIPS-approved AES.",
            "Same overhead as aes-gcm (16 bytes per chunk).",
        ],
        "detection_vectors": {
            "ffprobe_mediainfo": "Not visible.",
            "splunk_siem": "Not directly visible.",
            "sysmon": "Not visible.",
            "event_viewer": "Not visible.",
            "statistical_steganalysis": "Same as aes-gcm.",
            "manual": "Same as aes-gcm.",
        },
        "counter_detection": ["Pair with a strong passphrase."],
        "best_for": "Software-only systems, ARM hosts, or when AES-NI cannot be assumed.",
    },
}


# ---------------------------------------------------------------------------
# ECC layers
# ---------------------------------------------------------------------------

ECC_LAYERS = {
    "none": {
        "category": "ecc",
        "summary": "No forward error correction. A single LSB flip in the stored region corrupts the payload.",
        "mechanism": "Payload bytes (post-crypto) are embedded verbatim.",
        "strengths": ["Zero overhead.", "Simplest path."],
        "weaknesses": [
            "Brittle: a single bit flip in storage or transit fails extraction.",
            "Cannot survive any kind of re-encoding, even very mild.",
        ],
        "counter_detection": ["Use rs-255-223 if any chance of bit errors exists."],
        "best_for": "Air-gapped offline transfer where the file is exactly preserved.",
    },
    "rs-255-223": {
        "category": "ecc",
        "summary": "Reed-Solomon (255, 223): ~13% overhead, corrects up to 16 byte errors per 255-byte block.",
        "mechanism": """
Payload is split into 223-byte data blocks; each block has 32 parity bytes
appended to make a 255-byte codeword. An 8-byte big-endian length prefix is
stored verbatim at the start so the decoder can strip padding from the last
block. Decoding can correct up to 16 byte errors per codeword; beyond that, the
codeword is rejected.
""".strip(),
        "strengths": [
            "Robust against light corruption in storage or transit.",
            "Tunable: switch to RS(255,191) -- 32 errors corrected -- if more robustness is needed.",
            "Independent of crypto: works above or below the crypto layer.",
        ],
        "weaknesses": [
            "Overhead of ~13% means less capacity in the carrier.",
            "Doesn't survive full re-encoding (where every byte changes); only point corruption.",
            "If too many errors accumulate in one codeword, that block fails and the rest of the payload after it may be unrecoverable.",
        ],
        "counter_detection": [
            "Always couple with --crypto aes-gcm so that a single corrupted byte that slips past RS still triggers the AEAD tag failure.",
        ],
        "best_for": "Carriers transferred over channels that may introduce sparse bit errors (USB drives, NAS replication, lightly buggy transports).",
    },
}


# ---------------------------------------------------------------------------
# Detection-vector glossary (rendered by ``explain detection``)
# ---------------------------------------------------------------------------

DETECTION_GLOSSARY = {
    "ffprobe_mediainfo": "Container / codec analysis: stream count, codec_name, pix_fmt, container tags. Run by every casual analyst.",
    "splunk_siem": "Centralised log search via SPL queries. Looks for log patterns across many endpoints / proxies.",
    "sysmon": "Windows host-level events from the Sysinternals driver. Captures process create, file create, network connect, image load, registry edit.",
    "event_viewer": "Built-in Windows event log. Defender, Security (4663 SACL), Application logs.",
    "statistical_steganalysis": "Algorithmic detectors that look at LSB distributions or content-aware features. Chi-square, RS, sample-pair, S-UNIWARD, SRNet.",
    "manual": "Hands-on inspection: hex dumps, PSNR/SSIM diffs, file-size sanity, MKVToolNix browsing.",
    "network_dlp": "DLP appliances at egress: MIME validation, MIME-vs-extension consistency, YARA rules, anomalous size heuristics.",
}


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def lookup(name):
    if name in MODES:
        return MODES[name]
    if name in CRYPTO_LAYERS:
        return CRYPTO_LAYERS[name]
    if name in ECC_LAYERS:
        return ECC_LAYERS[name]
    return None


def list_all():
    return {
        "modes": list(MODES.keys()),
        "crypto": list(CRYPTO_LAYERS.keys()),
        "ecc": list(ECC_LAYERS.keys()),
    }

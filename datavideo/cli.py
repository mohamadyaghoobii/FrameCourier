"""``framecourier`` command-line interface.

Subcommands::

    framecourier embed        hide a payload into a cover video
    framecourier extract      recover a payload from a carrier
    framecourier modes        list every mode / crypto / ecc with one-liners
    framecourier explain      deep explanation of a specific mode / crypto / ecc
    framecourier probe        scan a video for FrameCourier signatures and stego hints
    framecourier info         read the embedded metadata of a stego carrier
    framecourier benchmark    PSNR / SSIM of cover vs. carrier, plus capacity report
    framecourier interactive  menu-driven walkthrough for embed/extract

Run ``framecourier <subcommand> --help`` for command-specific options.
"""

import argparse
import getpass
import json
import os
import subprocess
import sys
import textwrap

from pathlib import Path

from . import audit, benchmark, config, cover_quality, crypto, ecc, explain, fingerprint as fp, probe_analysis, recipes, stego, steganalysis, why as why_mod


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _add_password_args(parser):
    g = parser.add_argument_group("passphrase (pick one)")
    g.add_argument("--password", help="Passphrase as a literal string (visible in shell history)")
    g.add_argument("--password-stdin", action="store_true", help="Read passphrase from stdin (one line)")
    g.add_argument("--password-env", help="Read passphrase from the named environment variable")
    g.add_argument("--prompt-password", action="store_true", help="Prompt interactively for the passphrase")


def _resolve_password(args, confirm=False):
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "password_env", None):
        value = os.environ.get(args.password_env)
        if not value:
            raise SystemExit(f"Environment variable {args.password_env} is empty or not set")
        return value
    if getattr(args, "password_stdin", False):
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise SystemExit("Empty passphrase read from stdin")
        return value
    if getattr(args, "prompt_password", False):
        value = getpass.getpass("Passphrase: ")
        if confirm:
            second = getpass.getpass("Confirm:    ")
            if value != second:
                raise SystemExit("Passphrases did not match")
        if not value:
            raise SystemExit("Empty passphrase")
        return value
    return None


def _wrap(text, width=88, indent=""):
    text = textwrap.dedent(text).strip()
    out = []
    for paragraph in text.split("\n\n"):
        out.append(textwrap.fill(paragraph, width=width, initial_indent=indent, subsequent_indent=indent))
    return "\n\n".join(out)


# ---------------------------------------------------------------------------
# embed
# ---------------------------------------------------------------------------


def _cmd_embed(args):
    from .carrier import embed_file_distributed
    from .cover import embed_file_in_cover
    from .stego_carrier import embed_stego

    cfg = config.load()
    if args.mode is None:
        args.mode = cfg.get("default_mode", stego.MODE_SHUFFLED)
    if args.crypto is None:
        args.crypto = cfg.get("default_crypto", crypto.LAYER_AES_GCM)
    if args.kdf is None:
        args.kdf = cfg.get("default_kdf", crypto.KDF_ARGON2ID)
    if args.ecc is None:
        args.ecc = cfg.get("default_ecc", ecc.ECC_NONE)
    if args.cover_video is None:
        args.cover_video = cfg.get("default_cover")
    if args.default_dir is None:
        args.default_dir = cfg.get("default_dir", "default")
    if args.x264_preset is None:
        args.x264_preset = cfg.get("x264_preset", "veryfast")
    if args.adaptive_threshold is None:
        args.adaptive_threshold = cfg.get("adaptive_threshold", 4)

    if getattr(args, "preset", None):
        preset = recipes.get(args.preset)
        if not preset:
            raise SystemExit(f"Unknown preset: {args.preset}")
        # Override only if the user did not pass the corresponding flag
        # explicitly. argparse defaults make this tricky -- use the preset
        # values unconditionally; user can still set --recipient / --decoy-* on top.
        a = preset["args"]
        args.mode = a["mode"]
        args.crypto = a["crypto"]
        args.kdf = a["kdf"]
        args.ecc = a["ecc"]

    password = _resolve_password(args, confirm=args.prompt_password)
    progress = not args.quiet
    recipient_pubkey = None
    recipient_pubkeys = None

    def _load_pubkey(path):
        raw = Path(path).read_bytes()
        try:
            return crypto.x25519_load_public(raw)
        except Exception:
            return crypto.x25519_from_age_public(raw)

    if getattr(args, "recipient", None):
        recipients = args.recipient if isinstance(args.recipient, list) else [args.recipient]
        keys = [_load_pubkey(r) for r in recipients]
        if len(keys) == 1:
            recipient_pubkey = keys[0]
        else:
            recipient_pubkeys = keys

    decoy_password = None
    decoy_path = getattr(args, "decoy_file", None)
    if decoy_path:
        if getattr(args, "decoy_password", None):
            decoy_password = args.decoy_password
        elif getattr(args, "decoy_password_env", None):
            decoy_password = os.environ.get(args.decoy_password_env)
            if not decoy_password:
                raise SystemExit(f"Environment variable {args.decoy_password_env} is empty or not set")
        else:
            decoy_password = getpass.getpass("Decoy passphrase: ")
            if not decoy_password:
                raise SystemExit("Empty decoy passphrase")

    if args.mode in (stego.MODE_SEQ, stego.MODE_SHUFFLED, stego.MODE_ADAPTIVE):
        crypto_layer = args.crypto
        kdf = args.kdf
        if recipient_pubkeys is not None:
            crypto_layer = crypto.LAYER_X25519_MULTI
            kdf = crypto.KDF_HKDF_SHA256
        elif recipient_pubkey is not None:
            crypto_layer = crypto.LAYER_X25519_CHACHA
            kdf = crypto.KDF_HKDF_SHA256
        elif decoy_path is not None:
            crypto_layer = crypto.LAYER_DENIABLE
            kdf = crypto.KDF_ARGON2ID
            if password is None:
                raise SystemExit("Deniable mode requires --password (or one of --password-* / --prompt-password) for the real payload.")
        elif crypto_layer == crypto.LAYER_X25519_CHACHA:
            raise SystemExit("Crypto layer x25519-chacha20 requires --recipient pointing to a public key file.")
        elif crypto_layer == crypto.LAYER_DENIABLE:
            raise SystemExit("Crypto layer deniable requires --decoy-file pointing to the decoy payload.")
        elif crypto_layer == crypto.LAYER_NONE:
            kdf = "none"
        elif password is None:
            raise SystemExit(f"Mode {args.mode} with crypto {crypto_layer} needs a passphrase or --recipient.")

        result = embed_stego(
            args.input,
            args.output,
            mode=args.mode,
            crypto_layer=crypto_layer,
            kdf=kdf,
            ecc_layer=args.ecc,
            cover_video=args.cover_video,
            default_dir=args.default_dir,
            password=password,
            recipient_pubkey=recipient_pubkey,
            recipient_pubkeys=recipient_pubkeys,
            decoy_path=decoy_path,
            decoy_password=decoy_password,
            pad_recipients=getattr(args, "pad_recipients", 0),
            preset=args.x264_preset,
            adaptive_threshold=args.adaptive_threshold,
            progress=progress,
        )
        print("Embed complete (stego)")
    elif args.mode == "distributed":
        if password is not None:
            from .carrier import embed_file_distributed
            result = embed_file_distributed(
                args.input,
                args.output,
                cover_video=args.cover_video,
                default_dir=args.default_dir,
                segments=args.segments,
                schedule=args.schedule,
                seed=args.seed,
                width=args.width,
                height=args.height,
                fps=args.fps,
                password=password,
                progress=progress,
            )
        else:
            result = embed_file_distributed(
                args.input,
                args.output,
                cover_video=args.cover_video,
                default_dir=args.default_dir,
                segments=args.segments,
                schedule=args.schedule,
                seed=args.seed,
                width=args.width,
                height=args.height,
                fps=args.fps,
                progress=progress,
            )
        print("Embed complete (distributed)")
    elif args.mode == "legacy":
        if password is not None:
            raise SystemExit("Legacy mode does not support a passphrase. Pick a stego or distributed mode.")
        result = embed_file_in_cover(
            args.input,
            args.output,
            cover_video=args.cover_video,
            default_dir=args.default_dir,
            width=args.width,
            height=args.height,
            fps=args.fps,
            progress=progress,
        )
        print("Embed complete (legacy)")
    else:
        raise SystemExit(f"Unknown mode: {args.mode}")

    for k in ("output", "mode", "crypto", "kdf", "ecc", "payload_size", "stored_size", "sha256", "encrypted", "frames_processed", "capacity_bytes"):
        if k in result:
            print(f"  {k}: {result[k]}")
    audit.append(op="embed", metadata=result, carrier_path=args.output)

    if getattr(args, "sign_with", None):
        priv_raw = crypto.ed25519_load_private(Path(args.sign_with).read_bytes())
        pub_raw = crypto.ed25519_pubkey_from_private(priv_raw)
        digest = _sha256_file(args.output)
        sig = crypto.ed25519_sign(priv_raw, digest)
        sig_path = Path(str(args.output) + ".sig")
        record = {
            "magic": SIG_MAGIC, "version": SIG_VERSION, "alg": "ed25519",
            "file_sha256": digest.hex(),
            "signer_pubkey_b64": crypto.b64e(pub_raw),
            "signature_b64": crypto.b64e(sig),
            "signed_path_hint": str(args.output),
        }
        sig_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"  signature written to {sig_path}")


def _build_embed_parser(sub):
    p = sub.add_parser(
        "embed",
        help="hide a payload into a cover video",
        description="Hide a binary payload into a cover video via a chosen mode + crypto + ECC stack.",
    )
    p.add_argument("input", help="payload file to hide")
    p.add_argument("output", help="carrier file to write")
    p.add_argument("--preset", choices=recipes.names(),
                   help="apply a named preset bundle (overrides --mode/--crypto/--kdf/--ecc). See 'framecourier recipes'.")
    p.add_argument("--mode", choices=list(stego.MODE_IDS) + ["distributed", "legacy"], default=None,
                   help="carrier mode (config default_mode -> stego-shuffled)")
    p.add_argument("--crypto", choices=list(crypto.LAYER_IDS), default=None,
                   help="crypto layer (config default_crypto -> aes-gcm)")
    p.add_argument("--kdf", choices=list(crypto.KDF_IDS), default=None,
                   help="KDF (config default_kdf -> argon2id; ignored if --crypto=none)")
    p.add_argument("--ecc", choices=list(ecc.ECC_IDS), default=None,
                   help="forward error correction (config default_ecc -> none)")
    p.add_argument("--cover-video", default=None, help="path to cover video; falls back to config default_cover, then first file in --default-dir")
    p.add_argument("--default-dir", default=None, help="folder searched for a default cover (config default_dir -> default)")
    p.add_argument("--x264-preset", dest="x264_preset", default=None, help="x264 preset for stego modes (config x264_preset -> veryfast)")
    p.add_argument("--adaptive-threshold", type=int, default=None, help="stego-adaptive: minimum edge strength to embed (config adaptive_threshold -> 4)")
    p.add_argument("--segments", type=int, default=1, help="distributed mode: number of FFV1 segments (default: 1)")
    p.add_argument("--schedule", choices=["even", "center-weighted", "seeded-random"], default="even", help="distributed mode: segment placement schedule")
    p.add_argument("--seed", type=int, default=1337, help="distributed mode: PRNG seed for placement")
    p.add_argument("--width", type=int, default=1920, help="distributed/legacy mode: data-frame width")
    p.add_argument("--height", type=int, default=1080, help="distributed/legacy mode: data-frame height")
    p.add_argument("--fps", type=int, default=30, help="distributed/legacy mode: data-frame fps")
    p.add_argument("--quiet", action="store_true", help="suppress progress output")
    p.add_argument("--recipient", action="append", help="path to an X25519 public key file (generated by 'framecourier keygen'). Repeat for multi-recipient (uses x25519-multi-chacha20).")
    p.add_argument("--decoy-file", help="path to a decoy payload. Implies --crypto deniable. The decoy is revealed by --decoy-password; the real payload by --password.")
    p.add_argument("--decoy-password", help="literal decoy passphrase (visible in shell history)")
    p.add_argument("--decoy-password-env", help="environment variable containing the decoy passphrase")
    p.add_argument("--sign-with", dest="sign_with", help="Ed25519 private key file. After producing the carrier, write a detached signature to <output>.sig.")
    p.add_argument("--pad-recipients", dest="pad_recipients", type=int, default=0, help="multi-recipient: append N indistinguishable dummy slots to hide the real recipient count.")
    _add_password_args(p)
    p.set_defaults(func=_cmd_embed)


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------


def _cmd_extract(args):
    from .extractor import extract_auto

    password = _resolve_password(args, confirm=False)
    identity_privkey = None
    if getattr(args, "identity", None):
        raw = Path(args.identity).read_bytes()
        try:
            identity_privkey = crypto.x25519_load_private(raw)
        except Exception:
            identity_privkey = crypto.x25519_from_age_secret(raw)

    if getattr(args, "verify_with", None):
        sig_path = Path(args.verify_sig) if getattr(args, "verify_sig", None) else Path(str(args.input) + ".sig")
        if not sig_path.exists():
            raise SystemExit(f"No signature file found at {sig_path}. Provide --verify-sig or remove --verify-with.")
        record = json.loads(sig_path.read_text(encoding="utf-8"))
        if record.get("magic") != SIG_MAGIC:
            raise SystemExit("Signature file magic mismatch.")
        digest = _sha256_file(args.input)
        if record.get("file_sha256") != digest.hex():
            raise SystemExit("Carrier SHA-256 does not match the signature's recorded hash.")
        expected_pub = crypto.ed25519_load_public(Path(args.verify_with).read_bytes())
        if crypto.b64d(record["signer_pubkey_b64"]) != expected_pub:
            raise SystemExit("Signer pubkey in .sig does not match --verify-with.")
        if not crypto.ed25519_verify(expected_pub, crypto.b64d(record["signature_b64"]), digest):
            raise SystemExit("Signature is invalid for this carrier.")
        if not args.quiet:
            print(f"Signature verified against {args.verify_with}")

    progress = not args.quiet
    result = extract_auto(args.input, args.output, password=password, identity_privkey=identity_privkey, progress=progress)
    print("Extract complete")
    for k in ("output", "mode", "crypto", "kdf", "ecc", "payload_size", "file_size", "stored_size", "encrypted", "sha256"):
        if k in result:
            print(f"  {k}: {result[k]}")
    audit.append(op="extract", metadata=result, carrier_path=args.input)


def _build_extract_parser(sub):
    p = sub.add_parser(
        "extract",
        help="recover a payload from a carrier",
        description="Auto-detects the carrier type (stego v1/v2, distributed, legacy) and recovers the payload.",
    )
    p.add_argument("input", help="carrier file to read")
    p.add_argument("output", help="payload file to write")
    p.add_argument("--quiet", action="store_true", help="suppress progress output")
    p.add_argument("--identity", help="path to your X25519 private key file (use when the carrier was made with --recipient)")
    p.add_argument("--verify-with", dest="verify_with", help="before extracting, verify the carrier's signature against this Ed25519 public key file.")
    p.add_argument("--verify-sig", dest="verify_sig", help="path to the .sig file (default: <input>.sig)")
    _add_password_args(p)
    p.set_defaults(func=_cmd_extract)


# ---------------------------------------------------------------------------
# modes / explain
# ---------------------------------------------------------------------------


def _cmd_modes(args):
    print("MODES")
    for name, entry in explain.MODES.items():
        print(f"  {name:<18}  {entry['summary']}")
    print()
    print("CRYPTO LAYERS")
    for name, entry in explain.CRYPTO_LAYERS.items():
        print(f"  {name:<18}  {entry['summary']}")
    print()
    print("ECC LAYERS")
    for name, entry in explain.ECC_LAYERS.items():
        print(f"  {name:<18}  {entry['summary']}")
    print()
    print("Run 'framecourier explain <name>' for a full briefing on any of these.")


def _build_modes_parser(sub):
    p = sub.add_parser("modes", help="list all available modes / crypto / ECC")
    p.set_defaults(func=_cmd_modes)


def _render_entry(entry, name):
    print(f"== {name} ({entry['category']}) ==\n")
    print(_wrap(entry["summary"]))
    print()
    print("Mechanism")
    print("---------")
    print(_wrap(entry["mechanism"]))
    print()
    if "strengths" in entry:
        print("Strengths")
        print("---------")
        for s in entry["strengths"]:
            print(_wrap(f"+ {s}"))
        print()
    if "weaknesses" in entry:
        print("Weaknesses")
        print("----------")
        for s in entry["weaknesses"]:
            print(_wrap(f"- {s}"))
        print()
    if "detection_vectors" in entry:
        print("Detection vectors")
        print("-----------------")
        for vector, body in entry["detection_vectors"].items():
            label = explain.DETECTION_GLOSSARY.get(vector, vector)
            print(f"\n[{vector}] {label}")
            print(_wrap(body, indent="  "))
        print()
    if "counter_detection" in entry:
        print("Counter-detection")
        print("-----------------")
        for s in entry["counter_detection"]:
            print(_wrap(f"* {s}"))
        print()
    if "best_for" in entry:
        print("Best for")
        print("--------")
        print(_wrap(entry["best_for"]))
        print()


def _cmd_explain(args):
    if args.name == "detection":
        print("DETECTION-VECTOR GLOSSARY")
        for v, label in explain.DETECTION_GLOSSARY.items():
            print(f"\n[{v}] -- {label}")
        return
    entry = explain.lookup(args.name)
    if not entry:
        print(f"Unknown name: {args.name}")
        print()
        _cmd_modes(args)
        raise SystemExit(2)
    _render_entry(entry, args.name)


def _build_explain_parser(sub):
    p = sub.add_parser(
        "explain",
        help="detailed mechanism / strengths / detection vectors of a mode or layer",
        description="Show a complete briefing on a specific mode, crypto layer, or ECC layer.",
    )
    p.add_argument("name", help="name to explain (e.g., stego-shuffled, aes-gcm, rs-255-223, detection)")
    p.set_defaults(func=_cmd_explain)


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


def _cmd_probe(args):
    report = probe_analysis.analyse(args.input)
    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"== Probe report: {report['path']} ==\n")
    c = report["container"]
    print(f"Container:")
    print(f"  format            {c.get('format_name')}")
    print(f"  duration_sec      {c.get('duration')}")
    print(f"  size_bytes        {c.get('size_bytes')}")
    print(f"  video_streams     {c.get('video_streams')}  codecs={c.get('video_codecs')}  pix_fmts={c.get('video_pix_fmts')}")
    print(f"  audio_streams     {c.get('audio_streams')}")
    print(f"  subtitle_streams  {c.get('subtitle_streams')}")
    print()
    a = report["anomalies"]
    if a.get("bitrate"):
        b = a["bitrate"]
        print(f"Bitrate analysis:")
        print(f"  observed         {b.get('bitrate_mbps', 0):.2f} Mbps")
        if b.get("expected_bitrate_mbps") is not None:
            print(f"  expected (h.264) {b['expected_bitrate_mbps']:.2f} Mbps")
            print(f"  overweight ratio {b.get('overweight_ratio', 0):.2f}x")
        print()
    if a.get("chi_square_y"):
        chi = a["chi_square_y"]
        print(f"chi-square LSB (Y plane):")
        print(f"  stego_likelihood {chi['stego_likelihood']:.2%}")
        print(f"  chi              {chi['chi']:.2f}")
        print(f"  df               {chi['df']}")
        print()
    if a.get("stego_magic"):
        print(f"Stego magic:        {a['stego_magic']}\n")
    print("Findings:")
    for f in report["findings"]:
        print(f"  [{f['severity'].upper():<8}] ({f['category']}) {f['detail']}")


def _build_probe_parser(sub):
    p = sub.add_parser(
        "probe",
        help="analyse a video for FrameCourier signatures and stego hints",
        description="Read-only inspection: container shape, bitrate anomaly, LSB chi-square, stego magic.",
    )
    p.add_argument("input", help="video file to probe")
    p.add_argument("--json", action="store_true", help="emit the report as JSON")
    p.set_defaults(func=_cmd_probe)


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def _cmd_info(args):
    from .stego_carrier import _probe_video, _read_first_frame_bytes, is_stego_carrier
    import numpy as np

    if not is_stego_carrier(args.input):
        print("Not a FrameCourier stego carrier (magic missing). Try 'framecourier probe' for general analysis.")
        raise SystemExit(2)
    info = _probe_video(args.input)
    width, height = info["width"], info["height"]
    frame_size = stego.yuv420p_frame_bytes(width, height)
    first = _read_first_frame_bytes(args.input, width, height, frame_size)
    arr = np.frombuffer(first, dtype=np.uint8)
    magic = stego.reveal_bytes_from_plane(arr, 4, offset=0)
    if magic == stego.STEGO_MAGIC_V2:
        header_bytes = stego.reveal_bytes_from_plane(arr, stego.HEADER_SIZE, offset=0)
        header = stego.parse_stego_header_v2(header_bytes)
        print(f"FrameCourier stego carrier (v2)")
        print(f"  mode             {stego.MODE_NAMES.get(header['mode_id'])}  ({header['mode_id']})")
        print(f"  crypto           {crypto.LAYER_NAMES.get(header['crypto_id'])}")
        print(f"  kdf              {crypto.KDF_NAMES.get(header['kdf_id'])}")
        print(f"  ecc              {ecc.ECC_NAMES.get(header['ecc_id'])}")
        print(f"  plaintext_bytes  {header['plaintext_len']:,}")
        print(f"  stored_bytes     {header['stored_len']:,}")
        print(f"  plaintext_sha256 {header['plaintext_sha256']}")
        if header['pbkdf2_iterations']:
            print(f"  pbkdf2_iters     {header['pbkdf2_iterations']}")
        if header['argon2_time']:
            print(f"  argon2 t={header['argon2_time']}  m={header['argon2_memory_kb']} KiB  p={header['argon2_parallelism']}")
        return
    print("FrameCourier stego carrier (v1; legacy)")
    probe_bytes = stego.reveal_bytes_from_plane(arr, stego.HEADER_ENCRYPTED_BYTES, offset=0)
    header = stego.parse_stego_header(probe_bytes)
    print(f"  encrypted        {header['encrypted']}")
    print(f"  payload_bits     {header['payload_bit_length']:,}")
    print(f"  plaintext_sha256 {header['plaintext_sha256']}")


def _build_info_parser(sub):
    p = sub.add_parser("info", help="read-only metadata of a FrameCourier stego carrier")
    p.add_argument("input", help="stego carrier")
    p.set_defaults(func=_cmd_info)


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------


def _cmd_benchmark(args):
    from .stego_carrier import _probe_video
    info = _probe_video(args.cover)
    result = benchmark.benchmark(args.cover, args.carrier, info["width"], info["height"], info["frame_count"])
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Cover:   {result['cover']}")
    print(f"Carrier: {result['carrier']}")
    print()
    if result["psnr"]:
        p = result["psnr"]
        print(f"PSNR:  average={p['average_db']:.2f} dB   min={p['min_db']:.2f} dB   max={p['max_db']:.2f} dB")
        print("       (>=50 dB == effectively imperceptible LSB modification)")
    if result["ssim"]:
        s = result["ssim"]
        print(f"SSIM:  all={s['all']:.6f}  (1.0 == identical, >=0.999 == imperceptible)")
    print()
    c = result["capacity"]
    print(f"Capacity (1-bit-per-byte LSB):")
    print(f"  per_frame_bytes  {c['per_frame_bytes']:,}")
    print(f"  total_bytes      {c['total_bytes']:,}")


def _build_benchmark_parser(sub):
    p = sub.add_parser("benchmark", help="PSNR/SSIM of cover vs. carrier and capacity report")
    p.add_argument("cover", help="cover video (the source)")
    p.add_argument("carrier", help="carrier produced by 'framecourier embed'")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=_cmd_benchmark)


# ---------------------------------------------------------------------------
# interactive
# ---------------------------------------------------------------------------


def _menu(title, options):
    while True:
        print()
        print(title)
        for i, (label, _) in enumerate(options, 1):
            print(f"  {i}) {label}")
        choice = input("> ").strip()
        if not choice:
            continue
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx][1]
        except ValueError:
            pass
        print("Invalid choice, try again.")


def _cmd_interactive(args):
    print(textwrap.dedent("""
        FrameCourier interactive mode
        =============================
        Walk through embed or extract step by step. The equivalent CLI command
        is printed at the end so you can script it next time.
    """).strip())

    action = _menu("What would you like to do?", [
        ("Hide a file inside a video (embed)", "embed"),
        ("Recover a file from a carrier (extract)", "extract"),
        ("Read mode docs (explain)", "explain"),
        ("Analyse a video file (probe)", "probe"),
        ("Quit", "quit"),
    ])

    if action == "quit":
        return

    if action == "explain":
        print()
        for name, entry in explain.MODES.items():
            print(f"  {name}  -- {entry['summary']}")
        for name, entry in explain.CRYPTO_LAYERS.items():
            print(f"  {name}  -- {entry['summary']}")
        for name, entry in explain.ECC_LAYERS.items():
            print(f"  {name}  -- {entry['summary']}")
        target = input("\nname to explain> ").strip()
        ns = argparse.Namespace(name=target)
        _cmd_explain(ns)
        return

    if action == "probe":
        path = input("\nvideo path> ").strip().strip('"')
        ns = argparse.Namespace(input=path, json=False)
        _cmd_probe(ns)
        return

    if action == "embed":
        input_path = input("\nPayload file to hide> ").strip().strip('"')
        output_path = input("Carrier file to write> ").strip().strip('"')
        cover = input("Cover video [empty = default/]> ").strip().strip('"') or None
        mode = _menu("Mode (see explain <mode> later):", [
            ("stego-shuffled  -- PRNG-scattered LSB (recommended default)", stego.MODE_SHUFFLED),
            ("stego-adaptive  -- only edge/texture pixels (best vs steganalysis)", stego.MODE_ADAPTIVE),
            ("stego-seq       -- sequential LSB (simplest, most detectable)", stego.MODE_SEQ),
            ("distributed     -- FFV1 streams alongside cover", "distributed"),
            ("legacy          -- midpoint FFV1 (deprecated)", "legacy"),
        ])
        crypto_layer = _menu("Crypto layer:", [
            ("aes-gcm     -- AEAD (recommended)", crypto.LAYER_AES_GCM),
            ("chacha-poly -- AEAD, software-friendly", crypto.LAYER_CHACHA_POLY),
            ("aes-ctr     -- streaming, no auth (legacy)", crypto.LAYER_AES_CTR),
            ("none        -- no encryption", crypto.LAYER_NONE),
        ])
        kdf = crypto.KDF_ARGON2ID
        if crypto_layer == crypto.LAYER_AES_CTR:
            kdf = crypto.KDF_PBKDF2
        if crypto_layer == crypto.LAYER_NONE:
            kdf = "none"
        ecc_layer = _menu("ECC layer:", [
            ("none        -- no parity (default)", ecc.ECC_NONE),
            ("rs-255-223  -- Reed-Solomon, ~13% overhead", ecc.ECC_RS_255_223),
        ])
        password = None
        if crypto_layer != crypto.LAYER_NONE:
            password = getpass.getpass("Passphrase: ")
            confirm = getpass.getpass("Confirm:    ")
            if password != confirm:
                raise SystemExit("Passphrases did not match")

        from .stego_carrier import embed_stego
        from .carrier import embed_file_distributed
        from .cover import embed_file_in_cover

        equivalent = ["framecourier", "embed", input_path, output_path, "--mode", mode]
        if cover:
            equivalent.extend(["--cover-video", cover])
        if mode in stego.MODE_IDS:
            equivalent.extend(["--crypto", crypto_layer, "--kdf", kdf, "--ecc", ecc_layer])
        if password is not None:
            equivalent.append("--prompt-password")
        print("\nEquivalent command:")
        print("  " + " ".join(equivalent))
        print()

        if mode in stego.MODE_IDS:
            result = embed_stego(
                input_path, output_path,
                mode=mode, crypto_layer=crypto_layer, kdf=kdf, ecc_layer=ecc_layer,
                cover_video=cover, password=password, progress=True,
            )
        elif mode == "distributed":
            result = embed_file_distributed(
                input_path, output_path,
                cover_video=cover, password=password, progress=True,
            )
        else:
            result = embed_file_in_cover(input_path, output_path, cover_video=cover, progress=True)
        print("\nEmbed complete.")
        return

    if action == "extract":
        input_path = input("\nCarrier file> ").strip().strip('"')
        output_path = input("Output file>   ").strip().strip('"')
        password = getpass.getpass("Passphrase (empty if unencrypted): ") or None
        from .extractor import extract_auto
        result = extract_auto(input_path, output_path, password=password, progress=True)
        print("\nExtract complete.")
        for k, v in result.items():
            print(f"  {k}: {v}")


def _build_interactive_parser(sub):
    p = sub.add_parser("interactive", help="menu-driven walkthrough")
    p.set_defaults(func=_cmd_interactive)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _cmd_config(args):
    if args.action == "show":
        path = config.config_path()
        data = config.load()
        if not data:
            print(f"No config at {path}. Use 'framecourier config set <key> <value>'.")
            return
        print(f"Config file: {path}\n")
        print(json.dumps(data, indent=2))
    elif args.action == "get":
        if not args.key:
            raise SystemExit("config get requires a key")
        val = config.get(args.key)
        print(val if val is not None else "")
    elif args.action == "set":
        if not args.key:
            raise SystemExit("config set requires a key")
        if args.value is None:
            raise SystemExit("config set requires a value (or use 'config unset')")
        if args.key not in config.KNOWN_FIELDS:
            print(f"warning: {args.key} is not a recognised FrameCourier config key. Known: {sorted(config.KNOWN_FIELDS)}")
        # Try numeric coercion for adaptive_threshold
        value = args.value
        if args.key == "adaptive_threshold":
            try:
                value = int(value)
            except ValueError:
                raise SystemExit("adaptive_threshold must be an integer")
        data = config.set_(args.key, value)
        print(f"Set {args.key} = {value!r} in {config.config_path()}")
    elif args.action == "unset":
        if not args.key:
            raise SystemExit("config unset requires a key")
        config.set_(args.key, None)
        print(f"Unset {args.key} in {config.config_path()}")
    elif args.action == "path":
        print(config.config_path())
    elif args.action == "keys":
        print("Recognised keys:")
        for k in sorted(config.KNOWN_FIELDS):
            print(f"  {k}")
    else:
        raise SystemExit(f"Unknown config action: {args.action}")


def _cmd_why(args):
    if args.query:
        entries = why_mod.lookup(args.query)
        if not entries:
            print(f"No catalogue entry matches {args.query!r}. Run 'framecourier why' (no arg) to list all keys.")
            raise SystemExit(2)
    else:
        entries = why_mod.all_entries()
        print("All known FrameCourier error keys:\n")
        for e in entries:
            print(f"  {e['key']}")
        print()
        print("Pass any substring of an error message to get the full explanation:")
        print("  framecourier why \"SHA-256 mismatch\"")
        return
    for e in entries:
        print(f"== {e['key']} ==\n")
        print(_wrap(e['cause']))
        print()
        print("Fix:")
        for step in e["fix"]:
            print(_wrap(f"* {step}"))
        print()


def _build_why_parser(sub):
    p = sub.add_parser(
        "why",
        help="explain a common FrameCourier error and give a concrete fix",
        description="Paste any substring of a FrameCourier error message; this command looks up the explanation and concrete fix steps.",
    )
    p.add_argument("query", nargs="?", help="substring of the error message (omit to list all known keys)")
    p.set_defaults(func=_cmd_why)


def _cmd_make_cover(args):
    from .ffmpeg_tools import ffmpeg_path
    src_filters = {
        "testsrc2": f"testsrc2=size={args.width}x{args.height}:rate={args.fps}",
        "mandelbrot": f"mandelbrot=size={args.width}x{args.height}:rate={args.fps}",
        "smptebars": f"smptebars=size={args.width}x{args.height}:rate={args.fps}",
        "noise": f"color=size={args.width}x{args.height}:rate={args.fps}:color=black,format=yuv420p,geq='random(1)*255':'128':'128'",
        "gradient": f"gradients=size={args.width}x{args.height}:rate={args.fps}",
    }
    if args.filter not in src_filters:
        raise SystemExit(f"Unknown filter: {args.filter}. Choices: {', '.join(src_filters)}")
    out = Path(args.output)
    if out.exists() and not args.force:
        raise SystemExit(f"Output already exists: {out}. Pass --force to overwrite.")
    cmd = [
        ffmpeg_path(), "-v", "error", "-y",
        "-f", "lavfi", "-i", src_filters[args.filter],
        "-t", str(args.duration),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        str(out),
    ]
    subprocess.run(cmd, check=True)
    sz = out.stat().st_size
    print(f"Cover written: {out}  ({sz:,} bytes; {args.width}x{args.height} @ {args.fps} fps; {args.duration}s; filter={args.filter})")


def _build_make_cover_parser(sub):
    p = sub.add_parser(
        "make-cover",
        help="generate a quick test cover video so you don't need to remember the ffmpeg flags",
    )
    p.add_argument("output", help="output cover file (e.g., default/default.mp4)")
    p.add_argument("--filter", default="testsrc2",
                   help="lavfi source filter: testsrc2 | mandelbrot | smptebars | noise | gradient")
    p.add_argument("--width", type=int, default=1280)
    p.add_argument("--height", type=int, default=720)
    p.add_argument("--fps", type=int, default=30)
    p.add_argument("--duration", type=int, default=10, help="cover duration in seconds (default 10)")
    p.add_argument("--force", action="store_true", help="overwrite if the output file already exists")
    p.set_defaults(func=_cmd_make_cover)


def _cmd_bulk_embed(args):
    from .stego_carrier import embed_stego
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    if not in_dir.is_dir():
        raise SystemExit(f"Input directory not found: {in_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    pattern = args.pattern or "*"
    files = sorted(p for p in in_dir.glob(pattern) if p.is_file())
    if not files:
        print(f"No files matched {pattern!r} under {in_dir}.")
        return
    password = _resolve_password(args, confirm=False)
    successes = 0
    failures = 0
    for src in files:
        carrier_name = src.with_suffix(src.suffix + ".mp4").name
        carrier_path = out_dir / carrier_name
        try:
            embed_stego(
                str(src), str(carrier_path),
                mode=args.mode or stego.MODE_SHUFFLED,
                crypto_layer=args.crypto or (crypto.LAYER_AES_GCM if password is not None else crypto.LAYER_NONE),
                kdf=args.kdf or (crypto.KDF_ARGON2ID if password is not None else "none"),
                ecc_layer=args.ecc or ecc.ECC_NONE,
                cover_video=args.cover_video,
                password=password,
                progress=False,
            )
            print(f"  OK  {src.name}  ->  {carrier_path.name}")
            successes += 1
        except Exception as exc:
            print(f"  ERR {src.name}: {exc}")
            failures += 1
    print()
    print(f"Embedded {successes}/{len(files)} files into {out_dir}; failures={failures}")


def _build_bulk_embed_parser(sub):
    p = sub.add_parser(
        "bulk-embed",
        help="embed every file in a folder using the same cover/options",
        description="Bulk-embed every file in <input-dir> into its own carrier in <output-dir>.",
    )
    p.add_argument("input_dir", help="folder of payload files to hide")
    p.add_argument("output_dir", help="folder to write carriers into (created if missing)")
    p.add_argument("--cover-video", required=True, help="single cover video used for every payload")
    p.add_argument("--pattern", help="glob pattern relative to input-dir (default: every file)")
    p.add_argument("--mode", choices=list(stego.MODE_IDS) + [None], default=None,
                   help="carrier mode (default: stego-shuffled)")
    p.add_argument("--crypto", choices=list(crypto.LAYER_IDS) + [None], default=None,
                   help="crypto layer (default: aes-gcm if --password, else none)")
    p.add_argument("--kdf", choices=list(crypto.KDF_IDS) + [None], default=None)
    p.add_argument("--ecc", choices=list(ecc.ECC_IDS) + [None], default=None)
    _add_password_args(p)
    p.set_defaults(func=_cmd_bulk_embed)


def _cmd_bulk_extract(args):
    from .extractor import extract_auto
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    if not in_dir.is_dir():
        raise SystemExit(f"Input directory not found: {in_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    pattern = args.pattern or "*.mp4"
    carriers = sorted(p for p in in_dir.glob(pattern) if p.is_file())
    if not carriers:
        print(f"No carriers matched {pattern!r} under {in_dir}.")
        return
    password = _resolve_password(args, confirm=False)
    identity_privkey = None
    if getattr(args, "identity", None):
        raw = Path(args.identity).read_bytes()
        try:
            identity_privkey = crypto.x25519_load_private(raw)
        except Exception:
            identity_privkey = crypto.x25519_from_age_secret(raw)
    successes = 0
    failures = 0
    for src in carriers:
        out_name = src.stem
        if out_name.endswith(".bin") or out_name.endswith(".zip") or "." in out_name:
            target = out_dir / out_name
        else:
            target = out_dir / (out_name + ".bin")
        try:
            extract_auto(str(src), str(target), password=password,
                         identity_privkey=identity_privkey, progress=False)
            print(f"  OK  {src.name}  ->  {target.name}")
            successes += 1
        except Exception as exc:
            print(f"  ERR {src.name}: {exc}")
            failures += 1
    print()
    print(f"Extracted {successes}/{len(carriers)} carriers into {out_dir}; failures={failures}")


def _build_bulk_extract_parser(sub):
    p = sub.add_parser(
        "bulk-extract",
        help="extract every carrier in a folder",
        description="Bulk-extract every carrier in <input-dir> into <output-dir>.",
    )
    p.add_argument("input_dir", help="folder of carrier files")
    p.add_argument("output_dir", help="folder to write recovered payloads (created if missing)")
    p.add_argument("--pattern", help="glob pattern (default: *.mp4)")
    p.add_argument("--identity", help="X25519 private key (FrameCourier or age format)")
    _add_password_args(p)
    p.set_defaults(func=_cmd_bulk_extract)


def _cmd_fingerprint(args):
    report = fp.fingerprint(args.input)
    print(json.dumps(report, indent=2, sort_keys=True))


def _build_fingerprint_parser(sub):
    p = sub.add_parser(
        "fingerprint",
        help="emit a deterministic JSON fingerprint of a carrier (sha256 + container shape + stego header)",
    )
    p.add_argument("input", help="carrier video file")
    p.set_defaults(func=_cmd_fingerprint)


def _cmd_diff(args):
    a = fp.fingerprint(args.a)
    b = fp.fingerprint(args.b)
    differences = fp.diff(a, b)
    if args.json:
        print(json.dumps({"a": args.a, "b": args.b, "differences": [
            {"field": k, "a": av, "b": bv} for k, av, bv in differences
        ]}, indent=2))
        return
    print(f"== diff {args.a}  vs  {args.b} ==\n")
    if not differences:
        print("  identical (byte-exact and same stego header).")
        return
    width = max(len(k) for k, _, _ in differences)
    for k, av, bv in differences:
        print(f"  {k:<{width}}  A={av!r}  B={bv!r}")


def _build_diff_parser(sub):
    p = sub.add_parser(
        "diff",
        help="compare two carriers by fingerprint (sha256, header, container shape, signature)",
    )
    p.add_argument("a", help="first carrier")
    p.add_argument("b", help="second carrier")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=_cmd_diff)


def _cmd_version(args):
    import importlib
    print(f"FrameCourier 1.0.0")
    print()
    import sys as _sys
    print(f"  Python:        {_sys.version.splitlines()[0]}")
    print(f"  Executable:    {_sys.executable}")
    print()
    deps = ("numpy", "cryptography", "argon2", "reedsolo")
    print("  Python deps:")
    for name in deps:
        try:
            m = importlib.import_module(name)
            print(f"    {name:<14} {getattr(m, '__version__', '?')}")
        except ImportError:
            print(f"    {name:<14} MISSING")
    print()
    from .ffmpeg_tools import ffmpeg_path
    try:
        out = subprocess.run([ffmpeg_path(), "-version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        print(f"  FFmpeg:        {out}")
    except Exception:
        print(f"  FFmpeg:        not found")
    print()
    config_path = config.config_path()
    print(f"  Config path:   {config_path} ({'exists' if config_path.exists() else 'not present'})")
    audit_path = audit.log_path()
    print(f"  Audit log:     {audit_path if audit_path else 'disabled'}")


def _build_version_parser(sub):
    p = sub.add_parser("version", help="FrameCourier + Python + FFmpeg + dep versions")
    p.set_defaults(func=_cmd_version)


def _build_config_parser(sub):
    p = sub.add_parser(
        "config",
        help="view / edit ~/.framecourier/config.json (defaults for embed)",
        description="Per-user defaults file. CLI flags always override config values.",
    )
    p.add_argument("action", choices=["show", "get", "set", "unset", "path", "keys"], help="action")
    p.add_argument("key", nargs="?", help="config key (for get/set/unset)")
    p.add_argument("value", nargs="?", help="value (for set)")
    p.set_defaults(func=_cmd_config)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def _cmd_audit(args):
    if not audit.is_enabled():
        print(f"Audit log is disabled. Set the {audit.ENV_VAR} env var to a file path to enable.")
        print()
        print("Example (PowerShell):")
        print(f"  $env:{audit.ENV_VAR} = \"$env:USERPROFILE\\framecourier-audit.log\"")
        print("Example (bash):")
        print(f"  export {audit.ENV_VAR}=~/.framecourier/audit.log")
        return
    rows = audit.read(filter_substring=args.filter, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print(f"No matching rows in {audit.log_path()}.")
        return
    print(f"== Audit log: {audit.log_path()} ==")
    print(f"  {len(rows)} row(s)")
    print()
    for r in rows:
        ts = r.get("ts", "?")
        op = r.get("op", "?").upper()
        mode = r.get("mode") or "-"
        crypto_layer = r.get("crypto") or "-"
        bytes_ = r.get("payload_bytes") or "-"
        sha = (r.get("payload_sha256") or "-")[:16]
        carrier = r.get("carrier") or "-"
        print(f"  [{ts}] {op:<7} {mode:<16} crypto={crypto_layer:<14} bytes={bytes_:<8} sha={sha}…")
        print(f"           carrier: {carrier}")


def _build_audit_parser(sub):
    p = sub.add_parser(
        "audit",
        help="show the local audit log (opt-in via FRAMECOURIER_AUDIT_LOG env var)",
        description="Append-only audit log of every embed/extract. Passphrases and plaintext are NEVER recorded.",
    )
    p.add_argument("--filter", help="case-insensitive substring to filter on")
    p.add_argument("--limit", type=int, help="show only the last N rows")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=_cmd_audit)


# ---------------------------------------------------------------------------
# cover-score / suggest-cover
# ---------------------------------------------------------------------------


def _cmd_cover_score(args):
    report = cover_quality.analyse(args.input, sample_frames=args.frames)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print(f"== Cover score: {report['path']} ==\n")
    print(f"  dimensions      {report['width']}x{report['height']} @ {report['fps']:.2f} fps")
    print(f"  duration        {report['duration_sec']:.2f} s ({report['frame_count']} frames)")
    print(f"  size            {report['size_bytes']:,} bytes ({report['bitrate_mbps']:.2f} Mbps)")
    print(f"  codec / pix_fmt {report['video_codec']} / {report['video_pix_fmt']}")
    print(f"  has audio       {report['has_audio']}")
    print()
    print(f"  texture (mean block variance):   {report['mean_block_variance']:.1f}")
    print(f"  Y-plane LSB entropy:             {report['mean_lsb_entropy_bits']:.3f} bits  (closer to 1.0 = more natural noise)")
    print(f"  bitrate plausibility:            {report['bitrate_plausibility']}")
    print()
    print(f"  capacity (sequential, max):      {report['capacity_seq_bytes']:,} bytes")
    print(f"  capacity (adaptive, estimated):  {report['capacity_adaptive_bytes']:,} bytes")
    print()
    mode, why = report["recommend_mode"]
    print(f"  recommend mode:                  {mode}")
    print(f"  reason:                          {why}")
    print()
    print(f"  overall score:                   {report['score_0_100']:.1f} / 100")


def _build_cover_score_parser(sub):
    p = sub.add_parser("cover-score", help="rate a video's suitability as a FrameCourier cover")
    p.add_argument("input", help="video file to analyse")
    p.add_argument("--frames", type=int, default=6, help="sample frames for texture/entropy (default: 6)")
    p.add_argument("--json", action="store_true", help="emit the report as JSON")
    p.set_defaults(func=_cmd_cover_score)


def _cmd_suggest_cover(args):
    rows = cover_quality.rank(args.folder, sample_frames=args.frames)
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print(f"No video files found in {args.folder}.")
        return
    print(f"== Cover ranking: {args.folder} ==\n")
    print(f"  {'score':>6}  {'mode':<16}  {'res':<10}  {'frames':>7}  {'bitrate':>9}  path")
    print(f"  {'-'*6}  {'-'*16}  {'-'*10}  {'-'*7}  {'-'*9}  {'-'*40}")
    for r in rows:
        if "error" in r:
            print(f"  {'ERR':>6}  {'-':<16}  {'-':<10}  {'-':>7}  {'-':>9}  {r['path']}  ({r['error']})")
            continue
        res = f"{r['width']}x{r['height']}"
        bitrate = f"{r['bitrate_mbps']:.1f} Mbps"
        print(f"  {r['score']:>6.1f}  {r['recommend_mode']:<16}  {res:<10}  {r['frames']:>7}  {bitrate:>9}  {r['path']}")


def _build_suggest_cover_parser(sub):
    p = sub.add_parser("suggest-cover", help="rank video files in a folder by stego suitability")
    p.add_argument("folder", help="directory containing candidate cover videos")
    p.add_argument("--frames", type=int, default=4, help="sample frames per candidate (default: 4)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=_cmd_suggest_cover)


# ---------------------------------------------------------------------------
# doctor / recipes / examples / search
# ---------------------------------------------------------------------------


def _cmd_doctor(args):
    """Validate the environment: Python, FFmpeg, codecs, optional external tools."""
    import importlib
    import shutil
    import sys as _sys

    findings = []
    print("== FrameCourier doctor ==\n")

    # Python
    print(f"Python:          {_sys.version.splitlines()[0]}")
    if _sys.version_info < (3, 10):
        findings.append(("error", "Python 3.10+ required"))

    # Required deps
    for mod in ("numpy", "cryptography", "argon2", "reedsolo"):
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", "?")
            print(f"  {mod:<14} {ver}")
        except ImportError:
            print(f"  {mod:<14} MISSING")
            findings.append(("error", f"Required Python dependency missing: {mod}. Run: pip install -r requirements.txt"))

    # FFmpeg + ffprobe
    print()
    from .ffmpeg_tools import ffmpeg_path, ffprobe_path
    try:
        p = ffmpeg_path()
        print(f"FFmpeg:          {p}")
        import subprocess as sp
        out = sp.run([p, "-version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        print(f"  version line:  {out}")
    except Exception as exc:
        findings.append(("error", f"ffmpeg not found: {exc}"))
    try:
        p = ffprobe_path()
        print(f"FFprobe:         {p}")
    except Exception as exc:
        findings.append(("error", f"ffprobe not found: {exc}"))

    # libx264 / FFV1 support
    import subprocess as sp
    try:
        encoders = sp.run([ffmpeg_path(), "-hide_banner", "-encoders"], capture_output=True, text=True, timeout=10).stdout
        for enc in ("libx264", "ffv1"):
            tag = "OK" if enc in encoders else "MISSING"
            print(f"  encoder {enc:<10} {tag}")
            if enc not in encoders:
                findings.append(("warn", f"Encoder '{enc}' not advertised by ffmpeg; some modes will fail."))
    except Exception:
        findings.append(("warn", "Could not list ffmpeg encoders."))

    # Optional external steganalysis tools
    print()
    print("Optional steganalysis tools:")
    for tool in ("stegdetect", "aletheia"):
        path = shutil.which(tool)
        if path:
            print(f"  {tool:<10} found at {path}")
        else:
            print(f"  {tool:<10} not installed (optional)")

    # Default cover
    print()
    default_cover = Path(args.default_dir) / "default.mp4"
    if default_cover.exists():
        print(f"Default cover:   {default_cover} ({default_cover.stat().st_size:,} bytes)")
    else:
        print(f"Default cover:   {default_cover} (missing -- create one or always pass --cover-video)")
        findings.append(("info", f"No default cover at {default_cover}. Set with --cover-video on each embed."))

    # Config file
    cfg_path = config.config_path()
    if cfg_path.exists():
        print(f"Config file:     {cfg_path} ({cfg_path.stat().st_size:,} bytes)")
        try:
            data = config.load()
            for k, v in data.items():
                print(f"  {k:<22} {v}")
        except Exception as exc:
            findings.append(("warn", f"Config file present but unreadable: {exc}"))
    else:
        print(f"Config file:     {cfg_path} (none -- using defaults; run 'framecourier config set ...' to customise)")

    # Audit log
    al = audit.log_path()
    if al is None:
        print(f"Audit log:       disabled (set FRAMECOURIER_AUDIT_LOG or 'config set audit_log ...')")
    else:
        print(f"Audit log:       {al}")
        try:
            al.parent.mkdir(parents=True, exist_ok=True)
            probe = al.parent / ".framecourier-doctor-probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except Exception as exc:
            findings.append(("warn", f"Audit log directory not writable ({al.parent}): {exc}"))

    # Free disk space at the current directory
    import shutil as _shutil
    try:
        usage = _shutil.disk_usage(Path.cwd())
        free_gb = usage.free / (1024 ** 3)
        print(f"Free disk:       {free_gb:.1f} GiB at {Path.cwd()}")
        if free_gb < 1.0:
            findings.append(("warn", "Less than 1 GiB free; large carriers may fail."))
    except Exception:
        pass

    print()
    if not findings:
        print("All required checks passed.")
        return
    print("Findings:")
    rc = 0
    for sev, msg in findings:
        print(f"  [{sev.upper():<5}] {msg}")
        if sev == "error":
            rc = 1
    if rc:
        raise SystemExit(rc)


def _build_doctor_parser(sub):
    p = sub.add_parser("doctor", help="validate the environment (Python, FFmpeg, codecs, optional tools)")
    p.add_argument("--default-dir", default="default", help="where to look for the default cover")
    p.set_defaults(func=_cmd_doctor)


def _cmd_recipes(args):
    if args.name:
        preset = recipes.get(args.name)
        if not preset:
            print(f"Unknown preset: {args.name}. Available: {', '.join(recipes.names())}")
            raise SystemExit(2)
        print(f"== {args.name} ==\n")
        print(_wrap(preset["label"]))
        print()
        print(_wrap(preset["when"]))
        print()
        print("Expands to:")
        for k, v in preset["args"].items():
            print(f"  --{k:<8} {v}")
        if preset.get("needs"):
            print()
            print("Also needs:", ", ".join(preset["needs"]))
        return
    print("PRESETS")
    for name, preset in recipes.PRESETS.items():
        print(f"  {name:<12}  {preset['label']}")
    print()
    print("Run 'framecourier recipes <name>' for the full description.")


def _build_recipes_parser(sub):
    p = sub.add_parser("recipes", help="named bundles of mode+crypto+kdf+ecc (used by --preset)")
    p.add_argument("name", nargs="?", help="preset to detail (omit to list all)")
    p.set_defaults(func=_cmd_recipes)


def _cmd_examples(args):
    if args.name:
        ex = next((e for e in recipes.EXAMPLES if e["name"] == args.name), None)
        if not ex:
            print(f"Unknown example: {args.name}. Available: {', '.join(e['name'] for e in recipes.EXAMPLES)}")
            raise SystemExit(2)
        print(f"== {ex['name']} ==\n{ex['title']}\n")
        for line in ex["commands"]:
            print(f"  {line}")
        return
    print("EXAMPLES")
    for ex in recipes.EXAMPLES:
        print(f"  {ex['name']:<22}  {ex['title']}")
    print()
    print("Run 'framecourier examples <name>' for the actual commands.")


def _build_examples_parser(sub):
    p = sub.add_parser("examples", help="real-world workflow examples")
    p.add_argument("name", nargs="?", help="example to show in full (omit to list)")
    p.set_defaults(func=_cmd_examples)


def _cmd_search(args):
    query = args.query.lower()
    hits = []
    # Search modes / crypto / ecc entries
    for source in (explain.MODES, explain.CRYPTO_LAYERS, explain.ECC_LAYERS):
        for name, entry in source.items():
            haystack = " ".join([
                name,
                entry.get("summary", ""),
                entry.get("mechanism", ""),
                " ".join(entry.get("strengths", []) or []),
                " ".join(entry.get("weaknesses", []) or []),
                " ".join((entry.get("detection_vectors") or {}).values()),
                " ".join(entry.get("counter_detection", []) or []),
                entry.get("best_for", "") or "",
            ]).lower()
            if query in haystack:
                hits.append((entry["category"], name, entry.get("summary", "")))
    # Search recipes
    for name, preset in recipes.PRESETS.items():
        haystack = " ".join([name, preset["label"], preset["when"]]).lower()
        if query in haystack:
            hits.append(("preset", name, preset["label"]))
    # Search examples
    for ex in recipes.EXAMPLES:
        haystack = " ".join([ex["name"], ex["title"], " ".join(ex["commands"])]).lower()
        if query in haystack:
            hits.append(("example", ex["name"], ex["title"]))

    if not hits:
        print(f"No matches for '{args.query}'.")
        raise SystemExit(1)
    print(f"Matches for '{args.query}':\n")
    width = max(len(c) for c, _, _ in hits)
    for cat, name, summary in hits:
        print(f"  [{cat:<{width}}] {name:<22}  {summary}")
    print()
    print("Drill in with 'framecourier explain <name>', 'framecourier recipes <name>',")
    print("or 'framecourier examples <name>'.")


def _build_search_parser(sub):
    p = sub.add_parser("search", help="search modes / crypto / ECC / presets / examples by keyword")
    p.add_argument("query", help="case-insensitive substring to look for")
    p.set_defaults(func=_cmd_search)


# ---------------------------------------------------------------------------
# steganalyse / evaluate
# ---------------------------------------------------------------------------


def _cmd_steganalyse(args):
    result = steganalysis.analyse(args.input, max_frames=args.frames, run_external_tools=args.external)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    r = result["results"]
    print(f"== Steganalysis report: {result['path']} ==")
    print(f"  dimensions:    {result['width']}x{result['height']}")
    print(f"  frames tested: {r.get('frames_tested', 0)}")
    print()
    if not r.get("frames_tested"):
        print("No frames could be analysed.")
        return
    def _row(label, block):
        print(f"  {label:<18}  mean={block['mean']:.3f}   max={block['max']:.3f}")
    _row("chi-square LSB",  r["chi_square"])
    _row("sample-pair",     r["sample_pair"])
    _row("rs-divergence",   r["rs_divergence"])
    overall = steganalysis.verdict(r)
    print()
    if overall >= 0.7:
        bucket = "HIGH"
    elif overall >= 0.4:
        bucket = "MEDIUM"
    else:
        bucket = "LOW"
    print(f"  combined verdict: {overall:.3f}  ({bucket})")
    if "external" in result:
        ext = result["external"]
        print()
        avail = ext.get("available", {})
        for tool, path in avail.items():
            status = "installed" if path else "not installed"
            print(f"  {tool}: {status}")
        for tool, outs in (ext.get("results") or {}).items():
            print(f"\n  {tool} output:")
            for o in outs:
                if "error" in o:
                    print(f"    {o['file']}: ERROR {o['error']}")
                else:
                    head = (o.get("stdout") or "").splitlines()
                    print(f"    {o['file']}: rc={o['rc']}  {head[0] if head else ''}")
    print()
    print("  Reminder: these are classical detectors. State-of-the-art content-aware")
    print("  steganalysis (S-UNIWARD, SRNet) can detect cases these miss. Use this as")
    print("  a baseline, not as proof of undetectability.")


def _build_steganalyse_parser(sub):
    p = sub.add_parser(
        "steganalyse",
        help="run built-in LSB steganalysis detectors against a video",
        description="Runs chi-square LSB, sample-pair, and a simplified RS-style detector and prints per-test scores.",
    )
    p.add_argument("input", help="video file to analyse")
    p.add_argument("--frames", type=int, default=8, help="how many leading frames to test (default: 8)")
    p.add_argument("--external", action="store_true", help="also run installed external tools (stegdetect / aletheia) if present")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a human-readable report")
    p.set_defaults(func=_cmd_steganalyse)


def _cmd_evaluate(args):
    """Generate carriers across mode/crypto combinations and report detection."""
    import os
    import tempfile
    from .stego_carrier import embed_stego

    cover = args.cover_video
    payload_bytes = os.urandom(args.payload_size)
    combos = []
    for mode in (stego.MODE_SEQ, stego.MODE_SHUFFLED, stego.MODE_ADAPTIVE):
        for crypto_layer in (crypto.LAYER_NONE, crypto.LAYER_AES_GCM):
            combos.append((mode, crypto_layer))

    rows = []
    with tempfile.TemporaryDirectory() as td:
        payload_path = Path(td) / "payload.bin"
        payload_path.write_bytes(payload_bytes)
        clean = steganalysis.analyse(cover, max_frames=args.frames)
        clean_v = steganalysis.verdict(clean["results"])
        for mode, crypto_layer in combos:
            kdf = crypto.KDF_ARGON2ID if crypto_layer != crypto.LAYER_NONE else "none"
            carrier_path = Path(td) / f"carrier_{mode}_{crypto_layer}.mp4"
            try:
                embed_stego(
                    str(payload_path), str(carrier_path),
                    mode=mode, crypto_layer=crypto_layer, kdf=kdf,
                    ecc_layer=ecc.ECC_NONE,
                    cover_video=cover,
                    password="eval-pass" if crypto_layer != crypto.LAYER_NONE else None,
                    progress=False,
                )
                report = steganalysis.analyse(carrier_path, max_frames=args.frames)
                v = steganalysis.verdict(report["results"])
                rows.append({
                    "mode": mode,
                    "crypto": crypto_layer,
                    "verdict": v,
                    "chi": report["results"]["chi_square"]["mean"],
                    "sp": report["results"]["sample_pair"]["mean"],
                    "rs": report["results"]["rs_divergence"]["mean"],
                })
            except Exception as exc:
                rows.append({"mode": mode, "crypto": crypto_layer, "error": str(exc)})

    if args.json:
        print(json.dumps({"clean_cover_verdict": clean_v, "rows": rows}, indent=2))
        return

    print(f"== Evaluation: payload={args.payload_size} bytes, cover={cover}, frames_tested={args.frames} ==")
    print(f"  clean-cover combined verdict: {clean_v:.3f}")
    print()
    print(f"  {'mode':<18} {'crypto':<14} {'chi':>7} {'sp':>7} {'rs':>7} {'verdict':>9}")
    print(f"  {'-'*18} {'-'*14} {'-'*7} {'-'*7} {'-'*7} {'-'*9}")
    for r in rows:
        if "error" in r:
            print(f"  {r['mode']:<18} {r['crypto']:<14}  ERROR: {r['error']}")
            continue
        print(f"  {r['mode']:<18} {r['crypto']:<14} {r['chi']:7.3f} {r['sp']:7.3f} {r['rs']:7.3f} {r['verdict']:9.3f}")
    print()
    print("  Closer to clean-cover verdict is better (less detectable).")


def _build_evaluate_parser(sub):
    p = sub.add_parser(
        "evaluate",
        help="batch-generate carriers across modes and measure steganalysis detection",
        description="Helps you compare modes/crypto layers on the same cover.",
    )
    p.add_argument("--cover-video", required=True, help="cover video to test against")
    p.add_argument("--payload-size", type=int, default=20_000, help="random-payload size in bytes (default: 20000)")
    p.add_argument("--frames", type=int, default=8, help="frames to analyse per carrier (default: 8)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=_cmd_evaluate)


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def _cmd_keygen(args):
    if args.type == "ed25519":
        if args.import_age:
            raise SystemExit("--import-age is only valid for X25519 keys (age uses X25519).")
        if args.export_age:
            raise SystemExit("--export-age is only valid for X25519 keys.")
        priv_raw, pub_raw = crypto.ed25519_generate_keypair()
        priv_blob = crypto.ed25519_serialize_private(priv_raw)
        pub_blob = crypto.ed25519_serialize_public(pub_raw)
        kind = "Ed25519"
        sender_hint = f"framecourier sign carrier.mp4 --key {args.out}"
        recipient_hint = "framecourier verify carrier.mp4 carrier.mp4.sig"
    else:
        if args.import_age:
            text = Path(args.import_age).read_bytes()
            try:
                priv_raw = crypto.x25519_from_age_secret(text)
            except ValueError:
                # Maybe the file is a recipients file (public-only). Then we
                # can still write a pub-only blob.
                try:
                    pub_raw = crypto.x25519_from_age_public(text)
                    priv_raw = None
                except ValueError as exc:
                    raise SystemExit(f"Could not parse age key file at {args.import_age}: {exc}")
                # public-only flow: write pub key only.
                pub_path = Path(args.out + ".pub") if not Path(args.out).suffix else Path(args.out).with_suffix(Path(args.out).suffix + ".pub")
                if args.pub_out:
                    pub_path = Path(args.pub_out)
                if pub_path.exists() and not args.force:
                    raise SystemExit(f"Refusing to overwrite existing public key: {pub_path}. Pass --force.")
                pub_path.write_bytes(crypto.x25519_serialize_public(pub_raw))
                print("Imported age public key (recipient).")
                print(f"  public  key (X25519, FrameCourier format)  {pub_path}")
                return
            pub_raw = crypto.x25519_pubkey_from_private(priv_raw)
        else:
            priv_raw, pub_raw = crypto.x25519_generate_keypair()
        priv_blob = crypto.x25519_serialize_private(priv_raw)
        pub_blob = crypto.x25519_serialize_public(pub_raw)
        kind = "X25519"
        sender_hint = f"framecourier embed in.bin out.mp4 --recipient {args.out}.pub"
        recipient_hint = f"framecourier extract out.mp4 recovered.bin --identity {args.out}"
    priv_path = Path(args.out)
    pub_path = priv_path.with_suffix(priv_path.suffix + ".pub") if priv_path.suffix else Path(str(priv_path) + ".pub")
    if args.pub_out:
        pub_path = Path(args.pub_out)
    if priv_path.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing private key: {priv_path}. Pass --force to overwrite.")
    if pub_path.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing public key: {pub_path}. Pass --force to overwrite.")
    priv_path.write_bytes(priv_blob)
    pub_path.write_bytes(pub_blob)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    print(f"{kind} keypair written.")
    print(f"  private key  {priv_path}  (KEEP THIS SECRET)")
    print(f"  public  key  {pub_path}   (share this with the other side)")
    if args.export_age and args.type == "x25519":
        print()
        print("  age recipient (share this with age users):")
        print(f"    {crypto.x25519_to_age_public(pub_raw)}")
        print("  age secret key (KEEP THIS SECRET):")
        print(f"    {crypto.x25519_to_age_secret(priv_raw)}")
    print()
    print(f"  sender:    {sender_hint}")
    print(f"  recipient: {recipient_hint}")


def _build_keygen_parser(sub):
    p = sub.add_parser(
        "keygen",
        help="generate an X25519 (encryption) or Ed25519 (signing) keypair",
        description="Generate a 32-byte keypair stored as FrameCourier text blobs. Default type is X25519 for the asymmetric crypto layer.",
    )
    p.add_argument("out", help="path for the private key (public key is written to <out>.pub by default)")
    p.add_argument("--type", choices=["x25519", "ed25519"], default="x25519", help="key type (default: x25519)")
    p.add_argument("--pub-out", help="override the public key destination path")
    p.add_argument("--force", action="store_true", help="overwrite existing key files")
    p.add_argument("--export-age", action="store_true", help="(X25519 only) also print the keypair in age format")
    p.add_argument("--import-age", help="(X25519 only) read an age key/recipient file and save it in FrameCourier format")
    p.set_defaults(func=_cmd_keygen)


# ---------------------------------------------------------------------------
# sign / verify
# ---------------------------------------------------------------------------


SIG_VERSION = 1
SIG_MAGIC = "FCSIG-v1"


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def _cmd_sign(args):
    if not Path(args.input).exists():
        raise SystemExit(f"File not found: {args.input}")
    if not Path(args.key).exists():
        raise SystemExit(f"Signing key not found: {args.key}")
    priv_raw = crypto.ed25519_load_private(Path(args.key).read_bytes())
    pub_raw = crypto.ed25519_pubkey_from_private(priv_raw)
    digest = _sha256_file(args.input)
    signature = crypto.ed25519_sign(priv_raw, digest)
    out_path = Path(args.out) if args.out else Path(str(args.input) + ".sig")
    record = {
        "magic": SIG_MAGIC,
        "version": SIG_VERSION,
        "alg": "ed25519",
        "file_sha256": digest.hex(),
        "signer_pubkey_b64": crypto.b64e(pub_raw),
        "signature_b64": crypto.b64e(signature),
        "signed_path_hint": str(args.input),
    }
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"Signed {args.input}")
    print(f"  signature        {out_path}")
    print(f"  file sha-256     {digest.hex()}")
    print(f"  signer pubkey    {crypto.b64e(pub_raw)}")


def _build_sign_parser(sub):
    p = sub.add_parser(
        "sign",
        help="produce an Ed25519 detached signature over a file",
        description="Hash the file with SHA-256 and Ed25519-sign the digest. Writes a JSON .sig file next to the input by default.",
    )
    p.add_argument("input", help="file to sign (usually a FrameCourier carrier)")
    p.add_argument("--key", required=True, help="Ed25519 private key file (from 'framecourier keygen --type ed25519')")
    p.add_argument("--out", help="signature output path (default: <input>.sig)")
    p.set_defaults(func=_cmd_sign)


def _cmd_verify(args):
    if not Path(args.input).exists():
        raise SystemExit(f"File not found: {args.input}")
    if not Path(args.sig).exists():
        raise SystemExit(f"Signature not found: {args.sig}")
    try:
        record = json.loads(Path(args.sig).read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Could not parse signature file: {exc}")
    if record.get("magic") != SIG_MAGIC:
        raise SystemExit("Not a FrameCourier signature file")
    if record.get("alg") != "ed25519":
        raise SystemExit(f"Unsupported signature algorithm: {record.get('alg')}")

    digest = _sha256_file(args.input)
    expected_hex = record.get("file_sha256")
    if expected_hex != digest.hex():
        raise SystemExit(f"File contents do not match the signature's recorded SHA-256.\n"
                         f"  expected {expected_hex}\n"
                         f"  actual   {digest.hex()}")

    pub_in_sig = crypto.b64d(record["signer_pubkey_b64"])
    pubkey_to_use = pub_in_sig
    if args.pubkey:
        loaded_pub = crypto.ed25519_load_public(Path(args.pubkey).read_bytes())
        if loaded_pub != pub_in_sig:
            raise SystemExit("Pubkey supplied via --pubkey does not match the pubkey embedded in the .sig file.")
        pubkey_to_use = loaded_pub
    signature = crypto.b64d(record["signature_b64"])
    ok = crypto.ed25519_verify(pubkey_to_use, signature, digest)
    if not ok:
        raise SystemExit("Signature is invalid for this file.")
    print(f"Signature OK")
    print(f"  file              {args.input}")
    print(f"  file sha-256      {digest.hex()}")
    print(f"  signer pubkey     {crypto.b64e(pubkey_to_use)}")


def _build_verify_parser(sub):
    p = sub.add_parser(
        "verify",
        help="verify an Ed25519 detached signature over a file",
        description="Recompute SHA-256 of the file, check the signature in the .sig blob, optionally pin to a specific signer pubkey.",
    )
    p.add_argument("input", help="file whose signature you want to verify")
    p.add_argument("sig", help="signature file (.sig)")
    p.add_argument("--pubkey", help="optional: pin verification to this specific Ed25519 public key file")
    p.set_defaults(func=_cmd_verify)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="framecourier",
        description=textwrap.dedent("""\
            FrameCourier hides arbitrary binary files inside lossless H.264 video carriers.

            Run 'framecourier modes' to see every mode / crypto / ECC layer.
            Run 'framecourier explain <name>' for a complete briefing on any one of them,
            including detection vectors (Splunk, Sysmon, Event Viewer, statistical
            steganalysis, manual). Run 'framecourier interactive' for a menu-driven UI.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")
    _build_embed_parser(sub)
    _build_extract_parser(sub)
    _build_modes_parser(sub)
    _build_explain_parser(sub)
    _build_probe_parser(sub)
    _build_info_parser(sub)
    _build_benchmark_parser(sub)
    _build_interactive_parser(sub)
    _build_keygen_parser(sub)
    _build_sign_parser(sub)
    _build_verify_parser(sub)
    _build_steganalyse_parser(sub)
    _build_evaluate_parser(sub)
    _build_doctor_parser(sub)
    _build_recipes_parser(sub)
    _build_examples_parser(sub)
    _build_search_parser(sub)
    _build_cover_score_parser(sub)
    _build_suggest_cover_parser(sub)
    _build_audit_parser(sub)
    _build_config_parser(sub)
    _build_version_parser(sub)
    _build_fingerprint_parser(sub)
    _build_diff_parser(sub)
    _build_bulk_embed_parser(sub)
    _build_bulk_extract_parser(sub)
    _build_why_parser(sub)
    _build_make_cover_parser(sub)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

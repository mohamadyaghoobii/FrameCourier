import argparse
import getpass
import os
import sys

from datavideo.carrier import embed_file_distributed
from datavideo.cover import embed_file_in_cover
from datavideo.core import DEFAULT_FPS, DEFAULT_HEIGHT, DEFAULT_WIDTH
from datavideo.stego_carrier import embed_stego


def resolve_password(args):
    if args.password is not None:
        return args.password
    if args.password_env:
        value = os.environ.get(args.password_env)
        if not value:
            raise SystemExit(f"Environment variable {args.password_env} is empty or not set")
        return value
    if args.password_stdin:
        value = sys.stdin.readline().rstrip("\r\n")
        if not value:
            raise SystemExit("Empty password read from stdin")
        return value
    if args.prompt_password:
        value = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm:  ")
        if value != confirm:
            raise SystemExit("Passwords did not match")
        if not value:
            raise SystemExit("Empty password")
        return value
    return None


def main():
    parser = argparse.ArgumentParser(prog="embed.py")
    parser.add_argument("input_file")
    parser.add_argument("output_video")
    parser.add_argument("--mode", choices=["stego", "distributed", "legacy"], default="stego",
                        help="stego: H.264 LSB steganography (default, most normal-looking). distributed: extra FFV1 streams alongside cover. legacy: single FFV1 stream at midpoint.")
    parser.add_argument("--cover-video")
    parser.add_argument("--default-dir", default="default")
    parser.add_argument("--width", type=int, default=DEFAULT_WIDTH, help="distributed/legacy mode only")
    parser.add_argument("--height", type=int, default=DEFAULT_HEIGHT, help="distributed/legacy mode only")
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS, help="distributed/legacy mode only")
    parser.add_argument("--segments", type=int, default=1, help="distributed mode only")
    parser.add_argument("--schedule", choices=["even", "center-weighted", "seeded-random"], default="even", help="distributed mode only")
    parser.add_argument("--seed", type=int, default=1337, help="distributed mode only")
    parser.add_argument("--preset", default="veryfast", help="x264 preset for stego mode (ultrafast/superfast/veryfast/faster/fast/medium/slow)")
    parser.add_argument("--password", help="Encrypt payload with this passphrase (insecure: visible in shell history)")
    parser.add_argument("--password-stdin", action="store_true", help="Read passphrase from stdin")
    parser.add_argument("--password-env", help="Read passphrase from this environment variable")
    parser.add_argument("--prompt-password", action="store_true", help="Prompt interactively for the passphrase")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--keep-segments", action="store_true", help="distributed mode only")
    parser.add_argument("--temp-dir", help="distributed mode only")
    parser.add_argument("--keep-data-video", action="store_true", help="legacy mode only")
    parser.add_argument("--temp-data-video", help="legacy mode only")
    args = parser.parse_args()
    password = resolve_password(args)
    if args.mode == "legacy" and password is not None:
        raise SystemExit("Legacy single-track mode does not support --password yet")

    if args.mode == "stego":
        from datavideo import crypto as _crypto, ecc as _ecc, stego as _stego
        crypto_layer = _crypto.LAYER_AES_GCM if password is not None else _crypto.LAYER_NONE
        kdf = _crypto.KDF_ARGON2ID if password is not None else "none"
        metadata = embed_stego(
            args.input_file,
            args.output_video,
            mode=_stego.MODE_SEQ,
            crypto_layer=crypto_layer,
            kdf=kdf,
            ecc_layer=_ecc.ECC_NONE,
            cover_video=args.cover_video,
            default_dir=args.default_dir,
            password=password,
            preset=args.preset,
            progress=not args.quiet,
        )
        print("Embed complete (stego mode)")
        print("Output:", args.output_video)
        print("Cover video:", metadata["cover_video"])
        print("Payload bytes:", metadata["payload_size"])
        print("Capacity bytes:", metadata["capacity_bytes"])
        print("Frames processed:", metadata["frames_processed"])
        print("Encryption:", "on" if metadata.get("encrypted") else "off")
        print("SHA256 (plaintext):", metadata["sha256"])
        return

    if args.mode == "legacy":
        metadata = embed_file_in_cover(
            args.input_file,
            args.output_video,
            cover_video=args.cover_video,
            default_dir=args.default_dir,
            width=args.width,
            height=args.height,
            fps=args.fps,
            progress=not args.quiet,
            keep_data_video=args.keep_data_video,
            temp_data_video=args.temp_data_video,
        )
        print("Embed complete (legacy single-track)")
        print("Output:", args.output_video)
        print("Source file:", metadata["source_file_name"])
        print("Source bytes:", metadata["file_size"])
        print("Data frames:", metadata["total_frames"])
        print("Resolution:", f"{metadata['width']}x{metadata['height']}")
        print("FPS:", metadata["fps"])
        print("SHA256:", metadata["sha256"])
        return

    metadata = embed_file_distributed(
        args.input_file,
        args.output_video,
        cover_video=args.cover_video,
        default_dir=args.default_dir,
        segments=args.segments,
        schedule=args.schedule,
        seed=args.seed,
        width=args.width,
        height=args.height,
        fps=args.fps,
        password=password,
        progress=not args.quiet,
        keep_segments=args.keep_segments,
        temp_dir=args.temp_dir,
    )
    print("Embed complete (distributed mode)")
    print("Output:", args.output_video)
    print("Source bytes:", metadata["file_size"])
    print("Data frames:", metadata["total_frames"])
    print("Requested segments:", metadata["requested_segments"])
    print("Actual segments:", metadata["actual_segments"])
    print("Schedule:", metadata["schedule"])
    print("Resolution:", f"{metadata['width']}x{metadata['height']}")
    print("FPS:", metadata["fps"])
    print("Encryption:", "on" if metadata.get("encrypted") else "off")
    print("SHA256 (plaintext):", metadata["sha256"])


if __name__ == "__main__":
    main()

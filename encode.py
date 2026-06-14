import argparse
import getpass
import os
import sys

from datavideo.core import DEFAULT_FPS, DEFAULT_HEIGHT, DEFAULT_WIDTH
from datavideo.encoder import encode_file


def _resolve_password(args):
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
        a = getpass.getpass("Passphrase: ")
        b = getpass.getpass("Confirm:    ")
        if a != b:
            raise SystemExit("Passwords did not match")
        if not a:
            raise SystemExit("Empty passphrase")
        return a
    return None


def main():
    parser = argparse.ArgumentParser(prog="encode.py", description="Direct DataVideo encode: file -> FFV1 MKV (no cover).")
    parser.add_argument("input_file")
    parser.add_argument("output_video")
    parser.add_argument("--width", type=int, default=DEFAULT_WIDTH)
    parser.add_argument("--height", type=int, default=DEFAULT_HEIGHT)
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS)
    parser.add_argument("--password", help="encrypt payload with this passphrase (AES-CTR + Argon2id)")
    parser.add_argument("--password-env")
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument("--prompt-password", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    password = _resolve_password(args)
    metadata = encode_file(
        args.input_file, args.output_video,
        width=args.width, height=args.height, fps=args.fps,
        password=password,
        progress=not args.quiet,
    )
    print("DataVideo encode complete")
    print("Output:", args.output_video)
    print("Source file:", metadata["source_file_name"])
    print("Source bytes:", metadata["file_size"])
    print("Frames:", metadata["total_frames"])
    print("Resolution:", f"{metadata['width']}x{metadata['height']}")
    print("FPS:", metadata["fps"])
    print("Encryption:", "on" if metadata.get("encrypted") else "off")
    print("SHA256 (plaintext):", metadata["sha256"])


if __name__ == "__main__":
    main()

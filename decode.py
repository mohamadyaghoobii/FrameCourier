import argparse
import getpass
import os
import sys

from datavideo.decoder import decode_video


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
        v = getpass.getpass("Passphrase: ")
        if not v:
            raise SystemExit("Empty passphrase")
        return v
    return None


def main():
    parser = argparse.ArgumentParser(prog="decode.py", description="Direct DataVideo decode: FFV1 MKV -> file.")
    parser.add_argument("input_video")
    parser.add_argument("output_file")
    parser.add_argument("--password")
    parser.add_argument("--password-env")
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument("--prompt-password", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    password = _resolve_password(args)
    metadata = decode_video(args.input_video, args.output_file, password=password, progress=not args.quiet)
    print("DataVideo decode complete")
    print("Output:", args.output_file)
    print("Recovered bytes:", metadata["file_size"])
    print("Frames:", metadata["total_frames"])
    print("Encryption:", "on" if metadata.get("encrypted") else "off")
    print("SHA256 (plaintext):", metadata["sha256"])


if __name__ == "__main__":
    main()

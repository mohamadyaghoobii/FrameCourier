import argparse
import getpass
import os
import sys

from datavideo.extractor import extract_auto


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
        if not value:
            raise SystemExit("Empty password")
        return value
    return None


def main():
    parser = argparse.ArgumentParser(prog="extract.py")
    parser.add_argument("input_video")
    parser.add_argument("output_file")
    parser.add_argument("--password", help="Passphrase for encrypted carriers (insecure: visible in shell history)")
    parser.add_argument("--password-stdin", action="store_true", help="Read passphrase from stdin")
    parser.add_argument("--password-env", help="Read passphrase from this environment variable")
    parser.add_argument("--prompt-password", action="store_true", help="Prompt interactively for the passphrase")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    password = resolve_password(args)
    metadata = extract_auto(args.input_video, args.output_file, password=password, progress=not args.quiet)
    print("Extract complete")
    print("Output:", args.output_file)
    recovered = metadata.get("file_size") or metadata.get("payload_size")
    if recovered is not None:
        print("Recovered bytes:", recovered)
    if "total_frames" in metadata:
        print("Data frames:", metadata["total_frames"])
    if "total_segments" in metadata:
        print("Data segments:", metadata["total_segments"])
    if "mode" in metadata:
        print("Mode:", metadata["mode"])
    print("Encryption:", "on" if metadata.get("encrypted") else "off")
    print("SHA256 (plaintext):", metadata["sha256"])


if __name__ == "__main__":
    main()

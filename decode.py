import argparse

from datavideo.decoder import decode_video


def main():
    parser = argparse.ArgumentParser(prog="decode.py")
    parser.add_argument("input_video")
    parser.add_argument("output_file")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    metadata = decode_video(args.input_video, args.output_file, progress=not args.quiet)
    print("DataVideo decode complete")
    print("Output:", args.output_file)
    print("Recovered bytes:", metadata["file_size"])
    print("Frames:", metadata["total_frames"])
    print("SHA256:", metadata["sha256"])


if __name__ == "__main__":
    main()

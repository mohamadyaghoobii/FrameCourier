import argparse

from datavideo.extractor import extract_auto


def main():
    parser = argparse.ArgumentParser(prog="extract.py")
    parser.add_argument("input_video")
    parser.add_argument("output_file")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    metadata = extract_auto(args.input_video, args.output_file, progress=not args.quiet)
    print("DataVideo extract complete")
    print("Output:", args.output_file)
    print("Recovered bytes:", metadata["file_size"])
    print("Data frames:", metadata["total_frames"])
    if "total_segments" in metadata:
        print("Data segments:", metadata["total_segments"])
    print("SHA256:", metadata["sha256"])


if __name__ == "__main__":
    main()

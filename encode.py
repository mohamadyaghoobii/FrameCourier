import argparse

from datavideo.encoder import encode_file
from datavideo.core import DEFAULT_FPS, DEFAULT_HEIGHT, DEFAULT_WIDTH


def main():
    parser = argparse.ArgumentParser(prog="encode.py")
    parser.add_argument("input_file")
    parser.add_argument("output_video")
    parser.add_argument("--width", type=int, default=DEFAULT_WIDTH)
    parser.add_argument("--height", type=int, default=DEFAULT_HEIGHT)
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    metadata = encode_file(args.input_file, args.output_video, width=args.width, height=args.height, fps=args.fps, progress=not args.quiet)
    print("DataVideo encode complete")
    print("Output:", args.output_video)
    print("Source file:", metadata["source_file_name"])
    print("Source bytes:", metadata["file_size"])
    print("Frames:", metadata["total_frames"])
    print("Resolution:", f"{metadata['width']}x{metadata['height']}")
    print("FPS:", metadata["fps"])
    print("SHA256:", metadata["sha256"])


if __name__ == "__main__":
    main()

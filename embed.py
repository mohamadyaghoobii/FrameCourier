import argparse

from datavideo.carrier import embed_file_distributed
from datavideo.cover import embed_file_in_cover
from datavideo.core import DEFAULT_FPS, DEFAULT_HEIGHT, DEFAULT_WIDTH


def main():
    parser = argparse.ArgumentParser(prog="embed.py")
    parser.add_argument("input_file")
    parser.add_argument("output_video")
    parser.add_argument("--cover-video")
    parser.add_argument("--default-dir", default="default")
    parser.add_argument("--width", type=int, default=DEFAULT_WIDTH)
    parser.add_argument("--height", type=int, default=DEFAULT_HEIGHT)
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS)
    parser.add_argument("--segments", type=int, default=100)
    parser.add_argument("--schedule", choices=["even", "center-weighted", "seeded-random"], default="even")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--legacy-single-track", action="store_true", help="Use the older one-data-track-at-midpoint carrier mode")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--keep-segments", action="store_true")
    parser.add_argument("--temp-dir")
    parser.add_argument("--keep-data-video", action="store_true", help="Legacy mode only")
    parser.add_argument("--temp-data-video", help="Legacy mode only")
    args = parser.parse_args()

    if args.legacy_single_track:
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
        print("DataVideo legacy cover embed complete")
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
        progress=not args.quiet,
        keep_segments=args.keep_segments,
        temp_dir=args.temp_dir,
    )
    print("DataVideo distributed cover embed complete")
    print("Output:", args.output_video)
    print("Source file:", metadata["source_file_name"])
    print("Source bytes:", metadata["file_size"])
    print("Data frames:", metadata["total_frames"])
    print("Requested segments:", metadata["requested_segments"])
    print("Actual segments:", metadata["actual_segments"])
    print("Schedule:", metadata["schedule"])
    print("Resolution:", f"{metadata['width']}x{metadata['height']}")
    print("FPS:", metadata["fps"])
    print("SHA256:", metadata["sha256"])


if __name__ == "__main__":
    main()

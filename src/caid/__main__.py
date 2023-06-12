import argparse
import logging
from .libdeps import DependencyFinder


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def build_parser():
    parser = argparse.ArgumentParser(argument_default=None)
    parser.add_argument(
        "target_lib",
        help="Absolute path to library we want to find dependencies for.",
    )
    parser.add_argument(
        "device_id",
        help="ID of the connected Android device.",
    )
    parser.add_argument(
        "-w",
        "--workdir",
        required=False,
        dest="work_dir",
        help="Working directory for intermediate files."
        " Will create a tmpdir if omitted.",
    )
    parser.add_argument(
        "-e",
        "--elfdir",
        dest="elf_dir",
        help="Use this in case all ELF files are located in a dir on the" " host.",
        required=False,
    )
    parser.add_argument(
        "-j",
        "--json",
        dest="elf_json",
        help="JSON file containing list of ELF files on the device."
        " This file is part of the intermediate files, if it does not"
        " exist yet.",
    )
    parser.add_argument(
        "-p",
        "--platform",
        required=False,
        help="Platform ID as retrieved from 'getprop ro.product.platform'."
        " The value is read from the mobile phone, if it is not provided.",
    )
    parser.add_argument(
        "-s",
        "--sourcedir",
        required=False,
        dest="source_dir",
        help="Directory used as output for decompiled source-files of"
        " dex-files. Default value is 'workdir/jadx-source'.",
    )
    parser.add_argument(
        "-d",
        "--json-vdex",
        dest="vdex_json",
        help="JSON file containing list of VDEX files on the device."
        " This file is part of the intermediate files, if it does not"
        " exist yet.",
    )
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = vars(parser.parse_args())
    df = DependencyFinder(**args)
    df.main()

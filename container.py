#!/usr/bin/python3

import argparse
import contextlib
import subprocess
import sys


@contextlib.contextmanager
def loop_device(device, image):
    subprocess.check_output([
        "sudo", "losetup", device, image
    ])
    try:
        yield device
    finally:
        subprocess.check_output([
            "sudo", "losetup", "-d", device
        ])


def inspect(image):
    with loop_device("/dev/loop0", image):
        subprocess.run([
            "pvdisplay", "-m"
        ], check=False)
        subprocess.run([
            "lvs"
        ], check=False)


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(help='sub-command help')

    sb = sub.add_parser('create', help='create help')
    sb.set_defaults(command="create")

    sb = sub.add_parser('inspect', help='inspect help')
    sb.set_defaults(command="inspect")

    args = parser.parse_args()

    if not hasattr(args, "command"):
        print("Need sub-command")
        parser.print_usage()
        sys.exit(1)

    if args.command == "create":
        subprocess.check_call(["/code/create-lvm.sh"])
    elif args.command == "inspect":
        inspect("/shared/image.img")
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

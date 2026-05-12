#!/usr/bin/env python3
"""
Decode Windows UTF-16 LE DFIR output files to readable UTF-8.
The DFIR_WIN.ps1 script captures output via Out-File which defaults to UTF-16 LE on Windows,
resulting in wide-character spacing when read as UTF-8.

Usage:
  python3 decode_win_output.py <file>          # print decoded to stdout
  python3 decode_win_output.py <dir> --all     # print all .txt/.csv files decoded
  python3 decode_win_output.py <dir> --inplace # decode all files in-place (modifies files)
"""
import sys
import os
import argparse


def detect_and_read(path):
    for enc in ('utf-16', 'utf-16-le', 'utf-16-be', 'utf-8-sig', 'utf-8'):
        try:
            with open(path, 'r', encoding=enc) as f:
                content = f.read()
            # Check if it looks like wide-char garbage (alternating spaces between every char)
            if enc in ('utf-8', 'utf-8-sig'):
                lines = content.splitlines()
                if lines and len(lines[0]) > 4:
                    spaced = sum(1 for i in range(1, min(len(lines[0]), 20)) if lines[0][i] == ' ')
                    if spaced > len(lines[0]) // 3:
                        continue  # looks like mis-decoded wide chars, try next encoding
            return content
        except (UnicodeError, UnicodeDecodeError):
            continue
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def decode_file(path, output=None):
    content = detect_and_read(path)
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Decoded: {path} -> {output}", file=sys.stderr)
    else:
        print(content)


def main():
    parser = argparse.ArgumentParser(description='Decode Windows UTF-16 DFIR output files to UTF-8')
    parser.add_argument('path', help='File or directory to decode')
    parser.add_argument('--all', action='store_true', help='Decode all .txt/.csv files in directory tree')
    parser.add_argument('--inplace', action='store_true', help='Overwrite files with decoded UTF-8 content')
    args = parser.parse_args()

    if args.all and os.path.isdir(args.path):
        for root, dirs, files in os.walk(args.path):
            for fname in files:
                if fname.endswith(('.txt', '.csv')):
                    fpath = os.path.join(root, fname)
                    out = fpath if args.inplace else None
                    decode_file(fpath, out)
    else:
        decode_file(args.path)


if __name__ == '__main__':
    main()

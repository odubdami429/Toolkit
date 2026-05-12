#!/usr/bin/env python3
"""
Decode Windows UTF-16 LE DFIR output files to readable UTF-8.
The DFIR_WIN.ps1 script captures output via Out-File which defaults to UTF-16 LE on Windows,
resulting in wide-character spacing when read as UTF-8.

Encoding detection order (most-reliable-first):
  1. BOM bytes (\xff\xfe = UTF-16 LE, \xfe\xff = UTF-16 BE, \xef\xbb\xbf = UTF-8 BOM)
  2. If no BOM: try UTF-8 and validate via wide-char heuristic
  3. If UTF-8 looks like wide-char garbage: fall back to BOM-less UTF-16 LE

This makes the script idempotent: already-decoded UTF-8 files are detected via BOM
absence and returned unchanged. Running --inplace twice on the same directory is safe.

Usage:
  python3 decode_win_output.py <file>                 # print decoded to stdout
  python3 decode_win_output.py <dir> --all            # print all .txt/.csv files decoded
  python3 decode_win_output.py <dir> --all --inplace  # decode all files in-place (modifies files)
"""
import sys
import os
import argparse


def _looks_like_wide_char(content):
    """Return True if content looks like UTF-8 bytes mis-read as UTF-16 LE (wide-char garbage).

    When a UTF-16 LE file without BOM is read as UTF-8, every other byte (the high byte of each
    UTF-16 code unit) appears as a NUL or space, making text look like 'H o s t n a m e :'.
    Sample from the first substantive line to detect this pattern.
    """
    if not content:
        return False
    for line in content.splitlines():
        line = line.strip()
        if len(line) < 8:
            continue
        # In wide-char mis-decode, odd-indexed chars are almost all spaces/NULs
        sample = line[:min(len(line), 40)]
        odd_spaces = sum(1 for i in range(1, len(sample), 2) if sample[i] in (' ', '\x00'))
        if odd_spaces >= len(sample) // 4:
            return True
        break
    return False


def detect_and_read(path):
    """Read a file and return its content as a clean UTF-8 string.

    Uses BOM detection first to avoid mis-decoding already-UTF-8 files as UTF-16.
    """
    with open(path, 'rb') as f:
        bom = f.read(3)

    # BOM-based detection — highest confidence, never wrong
    if bom[:2] == b'\xff\xfe':
        # UTF-16 LE with BOM (PowerShell's default Out-File encoding)
        with open(path, 'r', encoding='utf-16') as f:
            return f.read()
    if bom[:2] == b'\xfe\xff':
        # UTF-16 BE with BOM
        with open(path, 'r', encoding='utf-16') as f:
            return f.read()
    if bom == b'\xef\xbb\xbf':
        # UTF-8 with BOM
        with open(path, 'r', encoding='utf-8-sig') as f:
            return f.read()

    # No BOM — try UTF-8 first (covers already-decoded files and ASCII output)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        if not _looks_like_wide_char(content):
            return content
        # Looks like wide-char garbage — fall through to UTF-16 LE attempt
    except UnicodeDecodeError:
        pass

    # BOM-less UTF-16 LE fallback (uncommon, but some tools omit the BOM)
    try:
        with open(path, 'r', encoding='utf-16-le') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()


def decode_file(path, output=None):
    content = detect_and_read(path)
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Decoded: {path} -> {output}", file=sys.stderr)
    else:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
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

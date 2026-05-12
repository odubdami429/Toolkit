#!/usr/bin/env python3
"""
Extract browser history from SQLite history files collected by DFIR scripts.
Works with Chrome, Edge (Chromium-based), and Safari history databases.

Usage:
  python3 read_browser_history.py <history_db_path> [--limit N] [--type chrome|safari|auto]
  python3 read_browser_history.py <dfir_output_dir> --scan   # find and read all history files
"""
import sys
import os
import sqlite3
import shutil
import tempfile
import argparse
from datetime import datetime, timezone


CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def chrome_ts(timestamp):
    if not timestamp:
        return "N/A"
    try:
        unix_ts = (timestamp / 1_000_000) - CHROME_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(timestamp)


def read_chrome_history(db_path, limit=300):
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(db_path, tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()

        print(f"{'Last Visit (UTC)':<25} {'Visits':>6}  URL")
        print("-" * 110)
        for url, title, visit_count, last_visit_time in rows:
            ts = chrome_ts(last_visit_time)
            print(f"{ts:<25} {visit_count:>6}  {url}")
        print(f"\n[{len(rows)} entries shown, limit={limit}]")
    finally:
        os.unlink(tmp_path)


def read_safari_history(db_path, limit=300):
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(db_path, tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT hi.url,
                       datetime(hv.visit_time + 978307200, 'unixepoch') AS visit_time,
                       hi.visit_count
                FROM history_visits hv
                JOIN history_items hi ON hv.history_item = hi.id
                ORDER BY hv.visit_time DESC
                LIMIT ?
            """, (limit,))
        except sqlite3.OperationalError:
            cursor.execute("""
                SELECT url, visit_count FROM history_items
                ORDER BY visit_count DESC LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        conn.close()

        print(f"{'Visit Time (UTC)':<25}  {'Visits':>6}  URL")
        print("-" * 110)
        for row in rows:
            print(f"{str(row[1] or 'N/A'):<25}  {str(row[2] if len(row)>2 else ''):>6}  {row[0]}")
        print(f"\n[{len(rows)} entries shown, limit={limit}]")
    finally:
        os.unlink(tmp_path)


def scan_and_read(dfir_dir, limit=100):
    """Find and read all browser history files in a DFIR output directory."""
    found = []
    for root, dirs, files in os.walk(dfir_dir):
        for fname in files:
            lower = fname.lower()
            if 'history' in lower or 'history_file' in lower:
                # Skip .txt files (those are file listings, not databases)
                if fname.endswith('.txt'):
                    continue
                found.append(os.path.join(root, fname))

    if not found:
        print("No browser history database files found.", file=sys.stderr)
        return

    for path in found:
        print(f"\n{'='*80}")
        print(f"FILE: {path}")
        print('='*80)
        lower = os.path.basename(path).lower()
        try:
            if 'safari' in lower:
                read_safari_history(path, limit)
            else:
                read_chrome_history(path, limit)
        except Exception as e:
            print(f"  [Error reading {path}: {e}]")


def main():
    parser = argparse.ArgumentParser(description='Read browser history from DFIR-collected SQLite files')
    parser.add_argument('path', help='History database file OR DFIR output directory (with --scan)')
    parser.add_argument('--limit', type=int, default=300, help='Max entries per file (default: 300)')
    parser.add_argument('--type', choices=['chrome', 'edge', 'safari', 'auto'], default='auto',
                        help='Browser type for single-file mode (default: auto-detect)')
    parser.add_argument('--scan', action='store_true',
                        help='Scan a DFIR output directory for all history files')
    args = parser.parse_args()

    if args.scan or os.path.isdir(args.path):
        scan_and_read(args.path, args.limit)
        return

    if not os.path.exists(args.path):
        print(f"Error: not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    browser_type = args.type
    if browser_type == 'auto':
        lower = args.path.lower()
        browser_type = 'safari' if 'safari' in lower else 'chrome'

    print(f"Reading {browser_type} history: {args.path}\n")
    if browser_type == 'safari':
        read_safari_history(args.path, args.limit)
    else:
        read_chrome_history(args.path, args.limit)


if __name__ == '__main__':
    main()

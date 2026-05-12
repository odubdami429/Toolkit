#!/usr/bin/env python3
"""
Parse Windows Event Log (.evtx) files collected by DFIR_WIN.ps1.
Requires: pip install python-evtx lxml

Usage:
  python3 parse_evtx.py <evtx_file>                           # key security events only
  python3 parse_evtx.py <evtx_file> --event-ids 4624,4625    # specific event IDs
  python3 parse_evtx.py <evtx_file> --all                     # all events (verbose)
  python3 parse_evtx.py <dir>  --scan                         # parse all .evtx in directory
  python3 parse_evtx.py <dir>  --scan --date-range            # date range only (no events)
  python3 parse_evtx.py --list-ids                            # show reference event ID list

Output format (one line per event):
  <Timestamp>            <EventID>  <Description>                      <Key=Value details>
  2026-05-04 19:57:03        7045  New Service Installed                  ServiceName=WSL Service, ImagePath=...
  2026-05-12 09:14:22        4688  Process Created                        SubjectUserName=erming, NewProcessName=...

To grep the saved output for specific event IDs:
  grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}.{14,}\\b(4624|4625|4648|4688|4697|7045|4720|4726|1102)\\b" output.txt
"""
import sys
import os
import argparse

NOTABLE_SECURITY = {
    1102: "Audit Log Cleared",
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4647: "User Initiated Logoff",
    4648: "Explicit Credential Logon (RunAs/Pass-the-Hash)",
    4656: "Object Handle Requested",
    4663: "File Object Access",
    4672: "Special Privileges Assigned",
    4688: "Process Created",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4700: "Scheduled Task Enabled",
    4702: "Scheduled Task Updated",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4724: "Password Reset Attempt",
    4726: "User Account Deleted",
    4728: "Member Added to Security-Enabled Global Group",
    4732: "Member Added to Local Administrators Group",
    4738: "User Account Changed",
    4740: "User Account Locked Out",
    4768: "Kerberos TGT Requested",
    4769: "Kerberos Service Ticket Requested",
    4771: "Kerberos Pre-Authentication Failed",
    4776: "NTLM Authentication Attempt",
    4798: "User's Local Group Membership Enumerated",
    4799: "Local Group Membership Enumerated",
}

NOTABLE_SYSTEM = {
    7034: "Service Crashed Unexpectedly",
    7035: "Service Control Request Sent",
    7036: "Service State Changed",
    7040: "Service Start Type Changed",
    7045: "New Service Installed",
    1074: "System Shutdown/Restart Initiated",
    6005: "Event Log Started (Boot)",
    6006: "Event Log Stopped (Shutdown)",
    6008: "Unexpected Shutdown",
}

DETAIL_FIELDS = [
    'SubjectUserName', 'TargetUserName', 'LogonType', 'LogonTypeName',
    'IpAddress', 'IpPort', 'WorkstationName', 'ProcessName', 'NewProcessName',
    'CommandLine', 'ServiceName', 'ImagePath', 'StartType',
    'TaskName', 'TaskContent',
]

HIGH_VALUE_IDS = set(NOTABLE_SECURITY) | set(NOTABLE_SYSTEM)


def _parse_ts(raw_ts):
    """Normalise a SystemTime string to 'YYYY-MM-DD HH:MM:SS'."""
    if not raw_ts:
        return ''
    return raw_ts.split('.')[0].replace('T', ' ') if 'T' in raw_ts else raw_ts


def parse_evtx_file(evtx_path, event_id_filter=None, limit=1000, show_all=False, date_range_only=False):
    try:
        import Evtx.Evtx as evtx
        from lxml import etree
    except ImportError:
        print("ERROR: python-evtx not installed.", file=sys.stderr)
        print("Install with:  pip install python-evtx lxml", file=sys.stderr)
        sys.exit(1)

    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    all_descriptions = {**NOTABLE_SECURITY, **NOTABLE_SYSTEM}

    shown = 0
    total = 0
    min_ts = None
    max_ts = None

    if not date_range_only:
        print(f"\nParsing: {evtx_path}")
        print(f"{'Timestamp':<22} {'EventID':>7}  {'Description':<38} Details")
        print("-" * 130)

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = etree.fromstring(record.xml().encode('utf-8'))

                ts_el = root.find('.//e:TimeCreated', ns)
                ts = _parse_ts(ts_el.get('SystemTime', '') if ts_el is not None else '')

                if ts:
                    total += 1
                    if min_ts is None or ts < min_ts:
                        min_ts = ts
                    if max_ts is None or ts > max_ts:
                        max_ts = ts

                if date_range_only:
                    continue

                eid_el = root.find('.//e:EventID', ns)
                event_id = int(eid_el.text) if eid_el is not None else 0

                if event_id_filter:
                    if event_id not in event_id_filter:
                        continue
                elif not show_all:
                    if event_id not in HIGH_VALUE_IDS:
                        continue

                if shown >= limit:
                    continue

                description = all_descriptions.get(event_id, '')

                event_data = {}
                for el in root.findall('.//e:Data', ns):
                    name = el.get('Name', '')
                    val = (el.text or '').strip()
                    if name and val and val not in ('-', '%%1833', '%%1832', 'N/A'):
                        event_data[name] = val

                details = ', '.join(
                    f"{k}={event_data[k]}"
                    for k in DETAIL_FIELDS
                    if k in event_data
                )

                print(f"{ts:<22} {event_id:>7}  {description:<38} {details}")
                shown += 1

            except Exception:
                continue

    date_range_str = f"{min_ts} → {max_ts}" if min_ts else "no timestamps found"
    if date_range_only:
        print(f"  {os.path.basename(evtx_path)}: {total} records  |  {date_range_str}")
    else:
        print(f"\n[{shown} matching records shown | {total} total records | {date_range_str} | limit={limit}]")

    return min_ts, max_ts, total


def scan_and_parse(directory, date_range_only=False, **kwargs):
    evtx_files = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if fname.endswith('.evtx'):
                evtx_files.append(os.path.join(root, fname))

    if not evtx_files:
        print("No .evtx files found.", file=sys.stderr)
        return

    if date_range_only:
        print(f"\nDate ranges for .evtx files in: {directory}")
        print("-" * 70)

    overall_min = None
    overall_max = None
    overall_total = 0

    for path in evtx_files:
        if not date_range_only:
            print(f"\n{'='*80}")
            print(f"LOG FILE: {os.path.basename(path)}")
            print('='*80)
        try:
            min_ts, max_ts, total = parse_evtx_file(path, date_range_only=date_range_only, **kwargs)
            overall_total += total
            if min_ts and (overall_min is None or min_ts < overall_min):
                overall_min = min_ts
            if max_ts and (overall_max is None or max_ts > overall_max):
                overall_max = max_ts
        except SystemExit:
            raise
        except Exception as e:
            print(f"  [Error: {e}]")

    if date_range_only:
        print("-" * 70)
        overall_range = f"{overall_min} → {overall_max}" if overall_min else "no timestamps"
        print(f"  Combined:   {overall_total} records  |  {overall_range}")


def main():
    parser = argparse.ArgumentParser(description='Parse Windows .evtx DFIR artifact files')
    parser.add_argument('path', nargs='?', help='Path to .evtx file or directory')
    parser.add_argument('--event-ids', help='Filter: comma-separated event IDs (e.g. 4624,4625,4688)')
    parser.add_argument('--all', action='store_true', help='Show all events, not just notable ones')
    parser.add_argument('--limit', type=int, default=1000, help='Max records per file (default: 1000)')
    parser.add_argument('--scan', action='store_true', help='Scan directory for all .evtx files')
    parser.add_argument('--date-range', action='store_true', help='Show date range covered by each log (no events)')
    parser.add_argument('--list-ids', action='store_true', help='Print reference event ID table and exit')
    args = parser.parse_args()

    if args.list_ids:
        print("Notable Security Event IDs:")
        for eid, desc in sorted(NOTABLE_SECURITY.items()):
            print(f"  {eid:>5}: {desc}")
        print("\nSystem Event IDs:")
        for eid, desc in sorted(NOTABLE_SYSTEM.items()):
            print(f"  {eid:>5}: {desc}")
        return

    if not args.path:
        parser.print_help()
        sys.exit(1)

    event_id_filter = None
    if args.event_ids:
        event_id_filter = set(int(x.strip()) for x in args.event_ids.split(','))

    kwargs = dict(event_id_filter=event_id_filter, limit=args.limit, show_all=args.all)

    if args.scan or os.path.isdir(args.path):
        scan_and_parse(args.path, date_range_only=args.date_range, **kwargs)
    else:
        parse_evtx_file(args.path, date_range_only=args.date_range, **kwargs)


if __name__ == '__main__':
    main()

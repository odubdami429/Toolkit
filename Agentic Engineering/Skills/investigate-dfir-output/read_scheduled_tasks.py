#!/usr/bin/env python3
"""
Parse Windows Scheduled Task XML files and extract the command, arguments, triggers, and
run-as user. Use this to see what a task actually executes — the DFIR scheduled_task.txt
only shows a directory listing (names + timestamps), not the task content.

Task XML files live at C:/Windows/System32/Tasks/<name> (no file extension).
They are plain UTF-16 XML and can be read directly via the Read tool or this script.

Usage:
  # Scan a directory of collected task XML files (e.g., from DFIR artifact)
  python3 read_scheduled_tasks.py <dir>

  # Read a single task XML file
  python3 read_scheduled_tasks.py <task_xml_file>

  # Flag only suspicious tasks (script paths in user dirs, download cradles, etc.)
  python3 read_scheduled_tasks.py <dir> --flagged-only

  # Pull and parse a task from a live machine via PowerShell (print the XML content)
  # Get-Content "C:/Windows/System32/Tasks/<taskname>" | Out-String
"""
import sys
import os
import re
import argparse

try:
    from xml.etree import ElementTree as ET
except ImportError:
    ET = None

# Namespaces used in Windows Task XML
TASK_NS = {
    'ts': 'http://schemas.microsoft.com/windows/2004/02/mit/task',
}

# Patterns that indicate a suspicious task command
SUSPICIOUS_PATTERNS = [
    (r'\\Users\\', "runs from user profile directory"),
    (r'\\AppData\\', "runs from AppData"),
    (r'\\Temp\\', "runs from Temp directory"),
    (r'\\Downloads\\', "runs from Downloads"),
    (r'\\Desktop\\', "runs from Desktop"),
    (r'-[Ee]nc(odedCommand)?', "uses PowerShell encoded command"),
    (r'[Ii]nvoke-[Ee]xpression|IEX\b', "uses Invoke-Expression (IEX)"),
    (r'[Ii]nvoke-[Ww]eb[Rr]equest|wget|curl\.exe', "downloads content from web"),
    (r'[Ww]eb[Cc]lient|[Dd]ownload[Ss]tring|[Dd]ownload[Ff]ile', "uses WebClient download"),
    (r'cmd(?:\.exe)?\s+/[cC]\s', "shells out via cmd /c"),
    (r'[Bb]ase64', "uses Base64 encoding"),
    (r'\.ps1\b', "runs a PowerShell script"),
    (r'\.vbs\b|[Ww]script|[Cc]script', "runs VBScript"),
    (r'mshta\.exe', "uses mshta (HTML Application host)"),
    (r'regsvr32', "uses regsvr32 (LOLBin)"),
    (r'rundll32', "uses rundll32"),
    (r'certutil.*-decode', "uses certutil for decoding"),
]


def _text(el, tag, ns=TASK_NS):
    """Find element by namespaced tag and return its text, or ''."""
    if el is None:
        return ''
    found = el.find(f"ts:{tag}", ns)
    return (found.text or '').strip() if found is not None else ''


def parse_task_xml(path):
    """Parse a single task XML file. Returns a dict of extracted fields."""
    try:
        # Task XMLs are UTF-16; ElementTree handles BOM automatically
        tree = ET.parse(path)
    except ET.ParseError:
        # Some files may be UTF-8 or have encoding issues
        try:
            with open(path, 'r', encoding='utf-16', errors='replace') as f:
                content = f.read()
            tree = ET.ElementTree(ET.fromstring(content.encode('utf-8')))
        except Exception as e:
            return {'name': os.path.basename(path), 'error': str(e)}

    root = tree.getroot()

    # Strip namespace from tag for easier lookup
    def find(tag):
        # Try namespaced first, then bare
        el = root.find(f".//ts:{tag}", TASK_NS)
        if el is None:
            el = root.find(f".//{tag}")
        return el

    def find_text(tag):
        el = find(tag)
        return (el.text or '').strip() if el is not None else ''

    command = find_text('Command')
    arguments = find_text('Arguments')
    working_dir = find_text('WorkingDirectory')
    run_as = find_text('UserId') or find_text('GroupId') or find_text('RunLevel')

    # Triggers: collect type + start boundary
    triggers = []
    triggers_el = find('Triggers')
    if triggers_el is not None:
        for child in triggers_el:
            tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            start = child.findtext('{http://schemas.microsoft.com/windows/2004/02/mit/task}StartBoundary') or ''
            interval = child.findtext('{http://schemas.microsoft.com/windows/2004/02/mit/task}Repetition/{http://schemas.microsoft.com/windows/2004/02/mit/task}Interval') or ''
            delay = child.findtext('{http://schemas.microsoft.com/windows/2004/02/mit/task}Delay') or ''
            entry = tag
            if start:
                entry += f" @ {start}"
            if interval:
                entry += f" every {interval}"
            if delay:
                entry += f" delay {delay}"
            triggers.append(entry)

    full_command = f"{command} {arguments}".strip()

    # Flag check
    flags = []
    for pattern, reason in SUSPICIOUS_PATTERNS:
        if re.search(pattern, full_command, re.IGNORECASE):
            flags.append(reason)

    return {
        'name': os.path.basename(path),
        'command': command,
        'arguments': arguments,
        'working_dir': working_dir,
        'run_as': run_as,
        'triggers': ', '.join(triggers) if triggers else 'none',
        'flagged': bool(flags),
        'flag_reasons': flags,
    }


def print_task(task, verbose=True):
    flag_marker = "  [!] FLAGGED" if task.get('flagged') else ""
    print(f"\n{'─'*70}")
    print(f"Task:        {task['name']}{flag_marker}")
    if task.get('error'):
        print(f"  [Parse error: {task['error']}]")
        return
    print(f"Command:     {task['command']}")
    if task['arguments']:
        print(f"Arguments:   {task['arguments']}")
    if task['working_dir']:
        print(f"WorkingDir:  {task['working_dir']}")
    if task['run_as']:
        print(f"RunAs:       {task['run_as']}")
    print(f"Triggers:    {task['triggers']}")
    if task['flag_reasons']:
        for reason in task['flag_reasons']:
            print(f"  [!] {reason}")


def main():
    parser = argparse.ArgumentParser(description='Parse Windows Scheduled Task XML files')
    parser.add_argument('path', help='Task XML file or directory containing task files')
    parser.add_argument('--flagged-only', action='store_true', help='Only show tasks with suspicious indicators')
    args = parser.parse_args()

    if ET is None:
        print("ERROR: xml.etree.ElementTree not available", file=sys.stderr)
        sys.exit(1)

    paths = []
    if os.path.isdir(args.path):
        for root, dirs, files in os.walk(args.path):
            for fname in files:
                fpath = os.path.join(root, fname)
                # Task files have no extension; skip known non-task files
                if '.' not in fname or fname.endswith('.xml'):
                    paths.append(fpath)
    else:
        paths = [args.path]

    tasks = [parse_task_xml(p) for p in paths]
    shown = 0

    flagged = [t for t in tasks if t.get('flagged')]
    clean = [t for t in tasks if not t.get('flagged') and not t.get('error')]

    print(f"\nScheduled Tasks: {len(tasks)} parsed | {len(flagged)} flagged | {len(clean)} clean")

    if flagged:
        print(f"\n{'='*70}")
        print("FLAGGED TASKS")
        print('='*70)
        for task in flagged:
            print_task(task)
            shown += 1

    if not args.flagged_only and clean:
        print(f"\n{'='*70}")
        print("CLEAN TASKS")
        print('='*70)
        for task in clean:
            print_task(task)
            shown += 1

    if shown == 0:
        print("No tasks to display.")


if __name__ == '__main__':
    main()

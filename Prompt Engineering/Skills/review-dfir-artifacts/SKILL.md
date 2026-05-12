---
name: review-dfir-artifacts
description: Analyze DFIR artifact output collected by DFIR_MAC.sh or DFIR_WIN.ps1 via CrowdStrike RTR. Produces a structured investigation report covering network activity, running processes, persistence, user activity, browser history, and IOCs. Trigger on phrases like "review DFIR output for X", "analyze artifacts from X", "review the DFIR from <hostname>", or when a path to a DFIR output directory is provided with a request to investigate or triage.
---

# Review DFIR Artifacts

Analyzes DFIR output directories produced by `DFIR_MAC.sh` or `DFIR_WIN.ps1` and generates a structured investigation report for a security analyst.

## Helper scripts

All helper scripts live at `~/.claude/skills/review-dfir-artifacts/`:

| Script | Purpose |
|---|---|
| `decode_win_output.py <file>` | Decode Windows UTF-16 LE files to readable text (print to stdout) |
| `decode_win_output.py <dir> --all --inplace` | Decode all .txt/.csv files in a directory tree in-place (idempotent — safe to re-run) |
| `read_browser_history.py <dir> --scan` | Extract URLs from all SQLite browser history files found |
| `read_browser_history.py <file>` | Extract URLs from a single Chrome/Edge/Safari history DB |
| `parse_evtx.py <dir> --scan` | Parse all .evtx Windows Event Log files (requires `pip install python-evtx lxml`) |
| `parse_evtx.py <dir> --scan --date-range` | Show only the date range covered by each .evtx (no events printed) |
| `parse_evtx.py --list-ids` | Print reference table of notable Windows event IDs |
| `read_scheduled_tasks.py <dir>` | Parse task XML files and extract Command/Arguments/Triggers/RunAs |
| `read_scheduled_tasks.py <dir> --flagged-only` | Show only tasks with suspicious command patterns |

## Platform detection

Determine the platform from the directory contents before doing anything else:

- **macOS** if the directory contains: `running_processes.txt`, `mac_login_history.txt`, `system_LaunchAgents.txt`
- **Windows** if the directory contains: `system_info.txt`, `scheduled_task.txt`, `windows_logs/`
- If ambiguous, check for `system_information.txt` (Mac) vs `system_info.txt` (Windows)

## Windows encoding note

All `.txt` and `.csv` files produced by `DFIR_WIN.ps1` are **UTF-16 LE** (PowerShell's default `Out-File` encoding). Reading them with the `Read` tool produces wide-character garbage (every character separated by a space). **Always decode Windows files first:**

```bash
python3 ~/.claude/skills/review-dfir-artifacts/decode_win_output.py <dir> --all --inplace
```

Run this once on the output directory before reading any files. It overwrites files in-place with clean UTF-8.

**The decoder is idempotent and safe to re-run.** It detects encoding via BOM bytes before doing anything: UTF-16 LE files (PowerShell default) start with `\xff\xfe` and are decoded; files with no BOM are assumed already-UTF-8 and left unchanged. Running `--inplace` twice on the same directory will not corrupt files.

## Artifact map

### macOS artifacts

| File | What it contains |
|---|---|
| `system_information.txt` | Hostname, macOS version, hardware (from `system_profiler`) |
| `running_processes.txt` | All processes at time of collection (`ps aux`) |
| `active_network_connections.txt` | Open network sockets (`lsof -i` + `netstat -an`) |
| `firewall_settings.txt` | macOS application firewall settings |
| `installed_apps.txt` | `/Applications` + `/usr/local/bin` listings |
| `installed_apps_history.txt` | Install history (`system_profiler SPInstallHistoryDataType`) |
| `saved_wifi_profiles.txt` | Preferred wireless networks |
| `system_install_logs.txt` | `/var/log/install.log` |
| `system_LaunchAgents.txt` | `/Library/LaunchAgents` + `/System/Library/LaunchAgents` |
| `system_LaunchDaemons.txt` | `/Library/LaunchDaemons` + `/System/Library/LaunchDaemons` |
| `system_cron_jobs.txt` | Root-level crontab |
| `docker_information.txt` | Docker disk usage + container list |
| `mac_login_history.txt` | Login/logout history (`last`) |
| `User_level_files/<user>_files/` | Per-user artifacts (see below) |

**Per-user (macOS):**
- `<user>_cron_jobs.txt` — user's crontab
- `<user>_Documents_files.txt` — recursive listing of ~/Documents
- `<user>_Downloads_files.txt` — recursive listing of ~/Downloads
- `<user>_All_files.txt` — recursive listing of ~/ (full home dir)
- `<user>_LaunchAgents.txt` — ~/Library/LaunchAgents
- `<user>_zsh_history.txt` — ~/.zsh_history
- `<user>_bash_history.txt` — ~/.bash_history
- `<user>_default_chrome_history_file` — SQLite: Chrome Default profile history
- `<user>_profile_N_chrome_history_file` — SQLite: Chrome Profile N history
- `<user>_safari_history_file.db` — SQLite: Safari history

### Windows artifacts

| File | What it contains |
|---|---|
| `system_info.txt` | `systeminfo` output — hostname, OS, hardware, domain |
| `running_processes.txt` | `tasklist /v` — all processes with session and user |
| `scheduled_task.txt` | `Get-ChildItem C:\Windows\System32\Tasks` listing |
| `system_level_installed_apps.csv` | HKLM registry uninstall keys (system-wide apps) |
| `user_level_installed_apps.csv` | HKCU/HKU registry uninstall keys (per-user apps) |
| `tcp_connections.txt` | `Get-NetTCPConnection` with process names |
| `udp_connections.txt` | `Get-NetUDPEndpoint` with process names |
| `firewall_settings.csv` | All Windows Firewall rules |
| `windows_logs/Security.evtx` | Windows Security event log (binary) |
| `windows_logs/System.evtx` | Windows System event log (binary) |
| `windows_logs/Application.evtx` | Windows Application event log (binary) |
| `User_level_files/<user>_files/` | Per-user artifacts (see below) |

**Per-user (Windows):**
- `<user>_All_files.txt` — recursive listing of user's home folder
- `<user>_Documents_files.txt` — recursive listing of Documents
- `<user>_Downloads_files.txt` — recursive listing of Downloads
- `<user>_Chrome_Default_History` — SQLite: Chrome history
- `<user>_Chrome_Profile_N_History` — SQLite: Chrome profile N history
- `<user>_Edge_Default_History` — SQLite: Edge history
- `<user> powershell_logs.txt` — PSReadLine console + VS Code history
- Note: VDI/Amazon EC2 machines have data on D:\ drive, logged under same structure

## Analysis workflow

### Step 1 — Confirm scope

Ask the analyst:
- Is this a targeted investigation (specific alert / IOC to hunt)? Or a general triage?
- Is there a specific user of interest, or review all users?
- Is there a known timeframe for suspicious activity?

If the analyst says just "review it" or "triage it," proceed with a full general review.

### Step 2 — Decode (Windows only)

Run the decoder before reading any files:
```bash
python3 ~/.claude/skills/review-dfir-artifacts/decode_win_output.py "<output_dir>" --all --inplace
```

### Step 3 — System profile

Read the system info file first to anchor the report.

**macOS:** Read `system_information.txt`
- Extract: hostname, macOS version, chip/model, serial number, last boot time, collection timestamp

**Windows:** Read `system_info.txt`
- Extract: hostname, OS version + build, domain membership, last boot time, manufacturer (note if "Amazon EC2" = VDI), collection timestamp

### Step 4 — Network analysis

**macOS** — Read `active_network_connections.txt`:
- Focus on the `lsof -i` section (top half, before the `netstat` section)
- Look for ESTABLISHED connections: extract `RemoteIP:Port → Process(User)` tuples
- Flag: connections by unexpected processes, connections to non-CDN public IPs, high ephemeral remote ports, listening ports that are not standard system services

**Windows** — Read `tcp_connections.txt` and `udp_connections.txt`:
- Look for ESTABLISHED connections with non-private remote addresses
- Flag: processes other than browsers/system services with established external connections
- Flag: listening on 3389 (RDP) — expected if corporate policy, suspicious if unexpected

Red flags for all platforms:
- Any process running from `/tmp`, `/var/folders`, `%TEMP%`, `AppData\Local\Temp`, or user's Downloads folder that has a network connection
- Connections to private VPN ranges that aren't the expected corporate VPN
- Unusually high port numbers being listened on by non-standard processes
- `nc`, `ncat`, `socat`, `chisel`, `ngrok`, or similar tunneling tools with connections

### Step 5 — Process analysis

**macOS** — Read `running_processes.txt` (ps aux format):
Columns: USER, PID, %CPU, %MEM, VSZ, RSS, TT, STAT, STARTED, TIME, COMMAND

**Windows** — Read `running_processes.txt` (tasklist /v format, after decoding):
Columns: Image Name, PID, Session Name, Session#, Mem Usage, Status, User Name, CPU Time, Window Title

Red flags (both platforms):
- Processes running from temp directories, Downloads, or user home root
- Processes with randomized or lookalike names (e.g. `svch0st.exe`, `lssas.exe`)
- Uncommon scripting interpreters (`python`, `perl`, `ruby`, `node`) running user scripts
- Security tools that shouldn't be installed: `nmap`, `masscan`, `mimikatz`, `meterpreter`
- Browsers running with `--headless` or unusual flags in the command line
- `osascript` executing inline AppleScript (Mac)
- `powershell -EncodedCommand` or `cmd /c` with base64-looking arguments (Windows)

### Step 6 — Persistence analysis

**macOS** — Read `system_LaunchAgents.txt`, `system_LaunchDaemons.txt`, `system_cron_jobs.txt`:
- Standard Apple LaunchAgents/Daemons in `/System/Library/` are normal — skip them
- Focus on `/Library/LaunchAgents` and `/Library/LaunchDaemons` (third-party system-level)
- Any entries by non-Apple vendors deserve a note; unknown entries are a red flag

Then check per-user:
- Read `<user>_LaunchAgents.txt` — user-level LaunchAgents in `~/Library/LaunchAgents`
- Read `<user>_cron_jobs.txt` — any scheduled commands?
- Note any non-empty cron jobs or unusual user-level LaunchAgents

**Windows** — Read `scheduled_task.txt`:
- Lists tasks under `C:\Windows\System32\Tasks`
- Standard Microsoft tasks are normal; look for tasks in unexpected subdirectories or with unusual names
- Any task running a script from a user's profile path or temp directory is suspicious

`scheduled_task.txt` is a **directory listing only** — it shows names and timestamps but not what each task actually runs. For any task that is unfamiliar, recently created, or has an unusual name, read its XML content to see the actual command:

```bash
# If task XML files were collected alongside the artifact:
python3 ~/.claude/skills/review-dfir-artifacts/read_scheduled_tasks.py "<artifact_dir>/tasks/" --flagged-only

# Or read a single task XML (these are plain UTF-16 XML files):
python3 ~/.claude/skills/review-dfir-artifacts/read_scheduled_tasks.py "C:\Windows\System32\Tasks\<TaskName>"
```

If the task XMLs are not in the artifact, pull them from the live machine via RTR:
```powershell
# Via CrowdStrike RTR or any live shell:
Get-Content "C:\Windows\System32\Tasks\<TaskName>" | Select-String -Pattern "Command|Arguments|UserId|Triggers" -Context 0,1
```

Key fields to extract from task XML: `<Command>` (the executable), `<Arguments>`, `<WorkingDirectory>`, `<UserId>` (run-as account), and the trigger type (LogonTrigger, TimeTrigger, BootTrigger).

Red flags (both platforms):
- LaunchAgent/Daemon/Task pointing to a script in a user's home, Downloads, or temp directory
- Commands with base64-encoded payloads or piped through `bash -c` / `cmd /c`
- Recently created tasks/agents (compare timestamps to known incident window if provided)
- Tasks running `curl`, `wget`, or PowerShell download cradles

### Step 7 — Installed software

**macOS** — Read `installed_apps.txt` and optionally `installed_apps_history.txt`:
- Flag: unusual dual-use tools (Wireshark, Nmap, ngrok, Metasploit, Burp Suite, etc.)
- Flag: any apps with recent install dates that coincide with the incident window
- Note anything unexpected for a corporate macOS endpoint (e.g. cracked apps, game installers)

**Windows** — Read `system_level_installed_apps.csv` and `user_level_installed_apps.csv`:
- Flag: same categories as above
- Note: InstallDate column helps correlate with incident timeline

### Step 8 — Login history (macOS) / Event logs (Windows)

**macOS** — Read `mac_login_history.txt` (`last` output):
- Note which users have logged in, from where (console vs remote), and session durations
- Flag: `root` console logins (especially unexpected ones), unusually short sessions, logins at unusual hours
- Flag: any unexpected usernames

**Windows** — Parse event logs:
```bash
# Requires: pip install python-evtx lxml
# Step 1: Check date range covered (fast — no events printed)
python3 ~/.claude/skills/review-dfir-artifacts/parse_evtx.py "<output_dir>/windows_logs" --scan --date-range

# Step 2: Parse all key security events and save to file
python3 ~/.claude/skills/review-dfir-artifacts/parse_evtx.py "<output_dir>/windows_logs" --scan > "$env:TEMP\evtx_parsed.txt" 2>&1
```

If `python-evtx` is not installed, note that and tell the analyst: "Windows Event Logs (.evtx) require `pip install python-evtx lxml` to parse. Run that command then retry."

**Output format** — one event per line:
```
Timestamp              EventID  Description                            Key=Value details
2026-05-04 19:57:03       7045  New Service Installed                  ServiceName=WSL Service, ImagePath=C:\Windows\system32\wsl.exe
2026-05-12 09:14:22       4688  Process Created                        SubjectUserName=erming, NewProcessName=C:\Windows\System32\reg.exe
```

**Grep the saved output** for specific event IDs:
```bash
# Windows PowerShell
Select-String -Path "$env:TEMP\evtx_parsed.txt" -Pattern "^\d{4}-\d{2}-\d{2}.{14,}\b(4624|4625|4648|4688|4697|7045|4720|4726|1102)\b"

# Bash / Python (on the evtx_parsed.txt file)
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}.{14,}(4624|4625|4648|4688|4697|7045|4720|4726|1102)" evtx_parsed.txt
```

Key events to highlight:
- 4624 (Logon): note LogonType=3 (network) or LogonType=10 (RemoteInteractive/RDP)
- 4625 (Failed Logon): bursts indicate brute force
- 4648 (Explicit Credential): RunAs or lateral movement indicator
- 4688 (Process Created): high-value if Security auditing was enabled
- 4697/7045 (Service Installed): persistence vector
- 4720/4726 (Account Created/Deleted)
- 1102 (Log Cleared): major red flag

**If 4624/4625/4648 events are absent:** this does not mean no logins occurred — it means the Security audit policy is not configured to log logon events. Note this as a coverage gap in the findings. The policy setting is: `Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Logon/Logoff`.

### Step 9 — User file activity

For each user found in `User_level_files/`:

Read `<user>_Downloads_files.txt`:
- Flag: executables (.exe, .dmg, .pkg, .ps1, .sh, .py, .bat, .vbs, .js), archives (.zip, .7z, .rar, .tar.gz)
- Flag: files with suspicious names or double extensions (e.g. `invoice.pdf.exe`)
- Flag: recently modified files (look at timestamps in the ls -l output)

Read `<user>_Documents_files.txt`:
- Note any large archives, database dumps, or unexpected sensitive-looking file names
- Flag: files with names suggesting exfiltration (backup, export, dump, all-data, etc.)

**Large file fallback:** Directory listing files (`_Downloads_files.txt`, `_All_files.txt`) can exceed 1MB for users with large home directories. If the Read tool errors or the file is clearly too large, use a targeted Python grep instead of attempting a full read:

```python
import re, sys

path = r"<full_path_to_file>"
hits = []
with open(path, encoding='utf-8', errors='replace') as f:
    for line in f:
        # Executables, scripts, archives
        if re.search(r'\.(exe|msi|dmg|pkg|ps1|bat|cmd|vbs|js|py|sh|zip|7z|rar|tar|gz)\b', line, re.IGNORECASE):
            hits.append(line.rstrip())
        # Suspicious name patterns
        elif re.search(r'(backup|export|dump|exfil|harvest|all.?data|loot)', line, re.IGNORECASE):
            hits.append(line.rstrip())

for h in hits:
    print(h)
print(f"\n{len(hits)} matches found")
```

On Windows PowerShell:
```powershell
Select-String -Path "<path>" -Pattern "\.(exe|msi|ps1|bat|vbs|js|py|zip|7z|rar)(\s|$)|backup|export|dump" -CaseSensitive:$false | Select-Object -ExpandProperty Line
```

### Step 10 — Shell / PowerShell history

**macOS** — Read `<user>_zsh_history.txt` and `<user>_bash_history.txt`:
- Look for: `curl`, `wget`, `nc`, `ncat`, `python -c`, `osascript`, `base64 -d`, `chmod +x`
- Look for: commands downloading then executing payloads
- Look for: network scanning commands (`nmap`, `arp`, `ping` sweeps)
- Look for: commands clearing logs (`rm -rf ~/Library/Logs`, `history -c`)
- Look for: data staging/compression commands (`zip`, `tar`, `cp` of sensitive dirs)

**Windows** — Read `<user> powershell_logs.txt` (note the space before powershell):
- Look for: `-EncodedCommand`, `[System.Convert]::FromBase64String`, `IEX`, `Invoke-Expression`
- Look for: `Invoke-WebRequest`, `WebClient.DownloadFile`, `DownloadString` download cradles
- Look for: `net user`, `net localgroup`, `whoami /all`, `Get-LocalGroupMember` (recon)
- Look for: `Add-MpPreference -ExclusionPath` (AV exclusion), `Set-MpPreference -DisableRealtime`
- Look for: `Compress-Archive` or `Copy-Item` targeting sensitive directories

### Step 11 — Browser history

Browser history databases can contain hundreds of URLs. Always save output to a file first, then analyze it in two passes — never read inline and risk truncation.

**Step 11a — Extract to file (per history DB)**

Find all browser history files in the artifact directory, then extract each one:
```bash
# List all history files
find "<output_dir>" -name "*History*" -o -name "*history_file*" -o -name "*safari_history*"

# Extract each file to a dedicated output (repeat for every file found)
python3 ~/.claude/skills/review-dfir-artifacts/read_browser_history.py "<history_file>" > /tmp/browser_<user>_<browser>.txt 2>&1
```

On Windows (PowerShell):
```powershell
python "~/.claude/skills/review-dfir-artifacts/read_browser_history.py" "<history_file>" 2>&1 | Out-File -Encoding utf8 "$env:TEMP\browser_<user>_<browser>.txt"
```

**Step 11b — Red-flag grep (entire file)**

Run this grep against every extracted output file. A clean result is expected; any hit warrants investigation:
```bash
grep -iE "(pastebin|paste\.ee|ghostbin|hastebin|privatebin|rentry\.co|ngrok|localtunnel|serveo|anydesk|teamviewer|\.onion|mega\.nz|transfer\.sh|filebin|anonfiles|gofile|temp\.sh|dropmefiles|raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+\.(ps1|sh|py|bat|vbs|exe)|/download[^?]*\.(exe|msi|ps1|sh|py|bat|vbs|js)|discord(app)?\.com/api/webhooks)" /tmp/browser_*.txt
```

**Step 11c — Domain frequency count (entire file)**

Extract every domain that was actually visited (has a real timestamp, not N/A) and review the full list:
```bash
grep -E "^20[0-9]{2}-" /tmp/browser_<user>_<browser>.txt \
  | grep -oE "https?://[^/ ]+" \
  | sed 's|https\?://||; s|/.*||' \
  | sort | uniq -c | sort -rn
```

Review ALL domains in the output — not just the top ones. Flag anything that is:
- Not a recognized corporate, SaaS, or well-known consumer service
- A file-hosting, paste, or anonymization service
- A remote-access tool vendor
- An IP address (direct IP browsing is unusual)

**Step 11d — Note bookmarks/typed URLs with no visits**

Lines prefixed with `N/A` are saved URLs with zero visits in this history (bookmarks, typed bar history, etc.). Review these separately for internal tool hostnames, IP addresses, or unusual domains that may indicate reconnaissance or saved attacker infrastructure.

### Step 12 — Firewall check

**macOS** — Read `firewall_settings.txt`:
- Note if the firewall is enabled or disabled
- Flag: "Firewall: Off" is a concern on a managed corporate device

**Windows** — Read `firewall_settings.csv`:
- Flag: rules that allow inbound connections for unexpected programs
- Flag: rules allowing inbound on ports like 4444, 1337, 8080, or other common C2 ports
- Flag: rules created very recently (no timestamp in this output; note if the rule names look auto-generated or random)

## Report output — xlsx

After completing the analysis (Steps 3–12), produce the report as an Excel workbook using `generate_report.py`. This involves two sub-steps: write a findings JSON, then run the generator.

### Step A — Write the findings JSON

Write the findings JSON to `<dfir_output_dir>/<hostname>_DFIR_Report/<hostname>_dfir_findings.json` using the Write tool. The subfolder `<hostname>_DFIR_Report/` is created automatically by `generate_report.py`, but the Write tool will also create it if needed. Use exactly this schema (omit sections with no data — empty arrays are fine):

```json
{
  "metadata": {
    "hostname": "<string>",
    "platform": "macOS | Windows",
    "collection_time": "<UTC string from artifact>",
    "analyst": "<string or blank>",
    "incident_context": "<string or 'General triage'>"
  },
  "executive_summary": "<2-4 sentence plain-text summary>",
  "category_verdicts": {
    "network":        "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "processes":      "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "persistence":    "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "software":       "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "logins":         "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "file_activity":  "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "shell_history":  "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "browser_history":"CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "event_logs":     "CLEAN | SUSPICIOUS | NOTABLE | N/A",
    "firewall":       "CLEAN | SUSPICIOUS | NOTABLE | N/A"
  },
  "network": [
    {"process": "", "user_pid": "", "local": "", "remote_ip": "", "remote_port": "", "state": "", "flagged": false, "notes": ""}
  ],
  "processes": [
    {"user": "", "pid": "", "cpu_pct": "", "command": "", "flagged": false, "notes": ""}
  ],
  "persistence": [
    {"type": "LaunchAgent | LaunchDaemon | ScheduledTask | Cron", "name": "", "path_or_command": "", "flagged": false, "notes": ""}
  ],
  "software": [
    {"name": "", "version": "", "publisher": "", "install_date": "", "flagged": false, "notes": ""}
  ],
  "logins": [
    {"user": "", "method": "", "time_in": "", "time_out": "", "duration": "", "flagged": false, "notes": ""}
  ],
  "file_activity": [
    {"user": "", "location": "Downloads | Documents | Other", "filename": "", "modified": "", "flagged": false, "notes": ""}
  ],
  "shell_history": [
    {"user": "", "shell": "zsh | bash | powershell", "command": "", "flagged": false, "notes": ""}
  ],
  "browser_history": [
    {"user": "", "browser": "Chrome | Edge | Safari", "url": "", "visit_count": "", "last_visit": "", "flagged": false, "notes": ""}
  ],
  "event_logs": [
    {"timestamp": "", "event_id": "", "description": "", "details": "", "flagged": false, "notes": ""}
  ],
  "iocs": [
    {"type": "IP | Domain | File Path | Process | Command | Hash", "value": "", "context": "", "confidence": "High | Medium | Low"}
  ],
  "recommendations": [
    {"priority": "1", "action": "", "details": ""}
  ]
}
```

**Schema guidance:**
- `network`: include all ESTABLISHED external connections + any suspicious listeners. Include normal corp traffic (VPN, Zoom, etc.) with `flagged: false` so the analyst has full visibility.
- `processes`: include only notable/suspicious entries — don't list every system process. Flag any process running from temp/user dirs or with suspicious command lines.
- `persistence`: include ALL non-Apple/non-Microsoft entries. Flag unknown or recently added ones.
- `software`: include notable entries — dual-use tools, recently installed apps, anything unusual. Don't list every Microsoft or Apple component.
- `logins`: include all login events from `mac_login_history.txt` or extracted event log logons.
- `file_activity`: include only files worth noting — executables, archives, suspicious names. Not every file.
- `shell_history`: include ALL commands from shell history files, flagging suspicious ones.
- `browser_history`: include only notable URLs — flag paste sites, file downloads, remote access tools, unknown domains.
- `event_logs`: include only notable security events (4624/4625/4648/4688/4697/1102 etc.).
- `iocs`: only include confirmed or high-confidence items.
- `recommendations`: max 5 items, ordered by urgency (priority 1 = most urgent).

### Step B — Generate the xlsx

```bash
python3 ~/.claude/skills/review-dfir-artifacts/generate_report.py "<path_to_findings_json>"
```

This writes `<hostname>_DFIR_Report.xlsx` into `<dfir_output_dir>/<hostname>_DFIR_Report/` — the same subfolder as the JSON. If `openpyxl` is not installed, tell the analyst: "Run `pip install openpyxl` then retry."

### Step C — Report to analyst

Tell the analyst:
1. The full path to the xlsx file
2. The executive summary (2-4 sentences)
3. Any SUSPICIOUS categories by name
4. The IOC count (if any)

Do not reproduce the full report as text — the xlsx is the deliverable.

## Behaviors and caveats

- **Read selectively.** Don't dump entire large files into context. For process lists and connection tables, read the first 100-200 lines and then grep for patterns. For shell history, read the full file (usually small).
- **Browser history must be fully reviewed.** Never read browser history output inline — it will be truncated and you will miss URLs. Always redirect to a temp file (Step 11a) and analyze with grep + domain-frequency count (Steps 11b–11c). A history with 200+ URLs is normal; missing any of them could mean missing an IOC.
- **Mac Chrome history is a SQLite binary.** Never try to read it directly. Always use `read_browser_history.py`.
- **Windows files look garbled until decoded.** If a file looks like `H o s t   N a m e :   P R I C E L I`, run the decoder first. The decoder is BOM-aware and idempotent — it is safe to re-run on already-decoded files.
- **Directory listing files (`_All_files.txt`, `_Downloads_files.txt`) can be 1MB+.** If the Read tool errors or truncates, switch to the Python grep pattern in Step 9 rather than attempting a full read. Never skip these files entirely — they contain the file activity evidence.
- **Stay in scope.** If the analyst mentioned a specific user, focus there first before reviewing other users.
- **Normalize your findings.** Corporate endpoints will have a lot of noise (MDM agents, AV, VPN clients, JAMF, CrowdStrike). Don't flag these. Focus on what shouldn't be there.
- **CrowdStrike RTR shows in ps aux.** The RTR script execution will appear as a `/bin/zsh -c ...` process — that's expected, not suspicious.

## Examples

**"review the DFIR output for the NY-W6F71W71DP machine"**
→ Path is provided or implied. Run full analysis on the Mac output directory.

**"triage the Windows DFIR for DESKTOP-I4ITMFJ, we got an alert for malware"**
→ Decode files first, then focus extra attention on processes, persistence, and shell history.

**"review the DFIR from /Users/analyst/Downloads/DESKTOP-I4ITMFJ, focus on network connections and PowerShell"**
→ Decode, then prioritize Steps 4 and 10. Still produce the full report but go deeper on those two sections.

**"check both DFIR outputs for the same user"**
→ Run full analysis on both directories and compare findings side by side.

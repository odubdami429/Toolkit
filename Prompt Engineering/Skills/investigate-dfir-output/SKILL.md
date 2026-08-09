---
name: investigate-dfir-output
description: >
  Parse and risk-score a Windows OR macOS endpoint DFIR triage collection (the
  InfoSec collector's output) for a single host — auto-detect the platform,
  decode the artifacts, read installed apps / processes / persistence
  (scheduled tasks or LaunchAgents/Daemons/cron) / network connections, scan a
  user's Downloads and All-files listings, command history (PowerShell or
  zsh/bash), Chrome/Edge/Safari browsing + download history, and the collected
  Claude Code .claude folders (hooks, approved permissions, session
  transcripts, custom skills/commands) plus Claude Desktop artifacts (MCP
  servers, installed extensions, relaxed settings, local-agent sessions) for
  exfiltration and departure / insider-risk signals, and produce a
  severity-ranked report. Use whenever an analyst has a laptop/endpoint triage
  package to review. Trigger phrases: "review the DFIR output", "triage this
  endpoint collection", "analyze the laptop artifacts", "what did X do on their
  laptop", "check this triage package for exfil", "investigate the DFIR
  artifacts for host Y", "parse this KAPE/collector output".
---

> **Environment: Claude Code / local only.** Pure Python stdlib (sqlite3, csv,
> re) — no credentials or network. `--xlsx` additionally needs `openpyxl`
> (`uv run --with openpyxl python ...` if it isn't already installed).

# Investigate DFIR Output

Turns a raw Windows or macOS host-triage package into a ranked findings report,
so the per-artifact analysis (encoding fixes, SQLite history queries, keyword
scans) that used to be done by hand is one repeatable command. The platform is
auto-detected from marker files; override with `--platform windows|macos`.

## Scripts

`dfir_triage.py` is the one-command auto-triage (start here). Three focused
helpers give deeper coverage on specific artifacts:

| Script | Purpose |
|---|---|
| `dfir_triage.py <DIR>` | One-shot parse + risk-score of the whole package → console / JSON / XLSX |
| `parse_evtx.py <DIR> --scan` | Full Windows `.evtx` event-log parsing (needs `python-evtx`) |
| `read_scheduled_tasks.py <DIR>` | Parse actual Scheduled-Task **XML** (Command/Args/Triggers/RunAs) + LOLBin flags |
| `decode_win_output.py <DIR> --all --inplace` | Batch-decode UTF-16 artifacts to UTF-8 (idempotent) — optional; `dfir_triage.py` decodes on the fly |

**Canonical run.** `.evtx` logs are now parsed and reviewed **by default** (on
Windows packages), so always run through `uv` with all three deps present —
`python-evtx`+`lxml` for the event logs and `openpyxl` for the XLSX. A `uv` env
contains *only* what you `--with`, so a missing dep silently drops that output
(no openpyxl → `[skip] … --xlsx ignored`; no python-evtx → a loud `[warn]` and
the event logs go unparsed).

```bash
# standard invocation — parses event logs + writes the full workbook
uv run --with python-evtx --with lxml --with openpyxl python \
    ~/.claude/skills/investigate-dfir-output/dfir_triage.py /path/to/HOSTNAME \
    --json ~/Documents/investigations/HOSTNAME_dfir.json \
    --xlsx ~/Documents/investigations/HOSTNAME_dfir.xlsx

# focus on one profile; skip the (slow) event-log parse for a quick pass
uv run --with python-evtx --with lxml --with openpyxl python \
    ~/.claude/skills/investigate-dfir-output/dfir_triage.py /path/to/HOSTNAME \
    --user rmilankov --no-evtx --xlsx ~/Documents/investigations/HOSTNAME_dfir.xlsx

# console-only, no report (macOS packages have no .evtx, so plain python3 is fine)
python3 ~/.claude/skills/investigate-dfir-output/dfir_triage.py /path/to/HOSTNAME
```

Flags: `--user <substr>` (limit to matching profile folder(s)); event-log parsing
is **on by default** — pass `--no-evtx` to skip it (faster; a large `Security.evtx`
takes minutes) and `--evtx` is still accepted as a no-op for back-compat;
`--json <path>`, `--xlsx <path>`, `--note "…"` (analyst context line shown as a
highlighted banner on the XLSX Summary sheet — use it to record why the findings
read the way they do, e.g. "analyst's own machine").

The `--xlsx` workbook has up to ten sheets (the two Windows event-log sheets are
added whenever `.evtx` logs are parsed, which is the default):
- **Summary** — banner (host, severity tally, legend, `--note`) + every finding, colour-coded by severity.
- **Claude Folder Review** — the `claude-*` findings only (Claude Code + Claude Desktop config/sessions/content).
- **Installed Applications** — full app inventory (Scope · Name · Version · Publisher · Install Date). Windows from the two uninstall CSVs; macOS from the `/Applications` + `/usr/local/bin` listing plus Homebrew formulae & casks (`homebrew_packages.txt`, scope `Homebrew formula`/`Homebrew cask`, with versions).
- **Persistence** — every scheduled task (Windows) / LaunchAgent · LaunchDaemon · cron entry (macOS), flagged (non-standard) ones first, with a Flagged column.
- **Network Connections** — every connection at collection (Source · State · Remote · raw line); best-effort structure with the raw record always preserved.
- **Full Browser History** — every Chrome/Edge/Safari URL parsed (Browser · Profile · Timestamp · Title · URL · Visits), newest first — not just the flagged buckets on Summary.
- **Browser Downloads** — the Chrome/Edge downloads table (Browser · Profile · Timestamp · Source URL · Saved To), newest first.
- **Full Command Line History** — every command (Source · Timestamp · Command): PowerShell/zsh/bash history plus every Bash command run via Claude Code sessions.
- **Event Log Summary** *(Windows, when `.evtx` parsed)* — per-(log, EventID) counts (Log · Provider · Event ID · Description · Severity · Count). The **Provider** gives a bare EventID meaning (same number means different things per provider), and rows are sorted so the annotated key security events lead, with the high-volume Application/System noise below.
- **Key Security Events** *(Windows, when `.evtx` parsed)* — one row per occurrence of a key security event (Log · Timestamp · Event ID · Severity · Description · Details), HIGH→INFO then newest first, with account/source/service/task/**command-line/script-block/share-path** fields extracted from EventData. Covers ~25 EventIDs: log-clear (1102) & audit-policy change (4719); account/group changes (4720/4726/4738/4732/4728/4756); persistence/exec (4697/7045/4698/4702, 4104 PowerShell script-block, 4688 process-create w/ command line); credential/lateral (4648/4625/4740/4672/4776/5140/5145); service (7040); and logon/logoff context (4624/4634). High-volume IDs (4688 process-create, 4624/4634 logon/logoff) are LOW/INFO so they sort below the real security events; the sheet is capped at 50k rows. **Note:** 4104 needs the *PowerShell/Operational* log, which the collector does not currently copy (only Security/System/Application) — it will appear only if that log is present in the package.

The two event-log sheets are produced whenever `.evtx` logs are parsed — the **default** now — provided `python-evtx`+`lxml` are available (run via `uv`, see above). Pass `--no-evtx` to skip them; if `python-evtx` is missing they are omitted with a loud `[warn]` and Summary just notes the logs' presence.

Detail sheets are references for manual pivoting (point-in-time dumps / file listings), not scored evidence — scoring stays on Summary. Each detail sheet is capped at 50 000 rows (a trailing row notes any omission).

## Expected package layout

Files are matched by name substring, so minor naming drift is tolerated. The
platform is auto-detected: **Windows** from `system_info.txt` / `scheduled_task.txt`
/ `windows_logs/`; **macOS** from `system_information.txt` / `mac_login_history.txt`
/ `system_LaunchAgents.txt`.

Current collector packages arrive as `DFIR_Output_<HOSTNAME>_<YYYY_MM_DD>.zip`
with the same-named folder inside (older packages: bare `DFIR_Output/`).
Browser-history copies now carry a `.db` suffix; extensionless copies from
older collections still parse.

**Windows:**
```
DFIR_Output_<HOSTNAME>_<YYYY_MM_DD>/
  system_info.txt                       system/user _level_installed_apps.csv
  running_processes.txt  scheduled_task.txt
  tcp_connections.txt    udp_connections.txt   wifi_profiles.txt
  windows_logs/*.evtx
  User_level_files/<User>_files/
      <User> powershell_logs.txt   <User>_All_files.txt   <User>_Downloads_files.txt
      <User>_Chrome_Default_History.db (SQLite)   <User>_Edge_Default_History.db (SQLite)
      <User>_claude_folders/            (only present if the user has .claude folders)
          global_claude/                (copy of C:\Users\<User>\.claude)
          project_<path>_claude/        (each project-level .claude, path flattened)
```

**macOS:**
```
DFIR_Output_<HOSTNAME>_<YYYY_MM_DD>/
  system_information.txt   running_processes.txt   active_network_connections.txt
  installed_apps.txt       installed_apps_history.txt   homebrew_packages.txt
  firewall_settings.txt    mac_login_history.txt
  system_LaunchAgents.txt  system_LaunchDaemons.txt   system_cron_jobs.txt
  User_level_files/<user>_files/
      <user>_zsh_history.txt   <user>_bash_history.txt
      <user>_LaunchAgents.txt  <user>_cron_jobs.txt
      <user>_All_files.txt     <user>_Downloads_files.txt
      <user>_default_chrome_history_file.db (SQLite)   <user>_safari_history_file.db (SQLite)
      <user>_claude_folders/            (only present if the user has .claude folders)
          global_claude/                (copy of ~/.claude)
          project_<path>_claude/        (each project-level .claude, path flattened)
      <user>_claude_desktop/            (only present if Claude Desktop is installed)
          claude_desktop_config.json    (MCP servers)
          config.json                   (app preferences; secret values redacted by collector)
          extensions-installations.json  Claude_Extensions/   (installed DXT extensions)
          local-agent-mode-sessions/  claude-code-sessions/
          logs/*.log                    (mcp.log, coworkd.log, per-MCP-server logs)
```

> **Claude Code vs Claude Desktop.** `<user>_claude_folders/` is **Claude Code**
> (the CLI, `~/.claude`). `<user>_claude_desktop/` is the **Claude Desktop** app
> (`~/Library/Application Support/Claude` on macOS, `%APPDATA%\Claude` on Windows).
> The collector deliberately skips Desktop credential material (`Cookies`,
> `buddy-tokens.json`, `Local State`) and redacts secret values inside
> `config.json` (oauth tokens, keys, session/refresh tokens — at any nesting
> depth), so the package holds config/behavior, not live session secrets.

## What it checks (and the severity it assigns)

Common to both platforms:
- **Host context** (INFO) — hostname, OS/version, model, boot/uptime, (Windows) domain & collection time.
- **Installed apps** — remote-access tools (AnyDesk, TeamViewer…) → MED; file-transfer/SSH (WinSCP, PuTTY, MobaXterm, rclone) and cloud-sync (OneDrive, Google Drive, Dropbox) → LOW; (Windows) privilege-elevation (Make Me Admin, PsExec) → MED; offensive tooling → HIGH. Dual-use — flagged for judgement, not as proof.
- **Network** (INFO) — established external connections at collection time (`tcp_connections.txt` / `active_network_connections.txt`).
- **Downloads & profile file listings** — resume/CV, compensation, offer/severance, PIP, "customer" (HIGH), passports; archives/DB dumps (`.zip/.7z/.sql/.bak/.dump`), with 2024+ archives escalated (recent staging).
- **Browser history (Chrome/Edge/Safari)** — paste/tunnel/anonymizer/webhook infra & raw-GitHub cradles (pastebin, ngrok, transfer.sh, anonfiles, `discord…/api/webhooks`, `raw.githubusercontent.com`) → HIGH; job-search/networking (LinkedIn jobs & messaging, Indeed, Workday careers) → MED; personal cloud / file-transfer (Drive, Dropbox, WeTransfer, Proton, Mega) → MED; employment-legal research → MED; plus browser downloads of interest. (Safari's schema and CFAbsoluteTime timestamps are handled.)
- **Claude Code `.claude` folders** (`<user>_claude_folders/`, when collected):
  - **Settings** (global + per-project `settings.json`/`settings.local.json`) — **hooks** (shell commands auto-run on agent events — a persistence vector) → MED, HIGH when the hook command has download-cradle/covert-channel patterns; **MCP servers** → LOW (HIGH if hot); **approved permission allowlists** containing exfil-capable/destructive patterns (`rm -rf`, `scp`, `aws s3`, `rclone`, DB dumps…) → MED — these were run *and* whitelisted by the user; blanket `Bash(*)` allowlists → LOW; relaxed modes (`bypassPermissions`, `skipAutoPermissionPrompt`, `enableAllProjectMcpServers`) → LOW; custom `apiKeyHelper` → MED.
  - **Session transcripts** (`global_claude/projects/**/*.jsonl`) — every Bash command Claude actually executed is scanned with the same exfil/tamper/tradecraft signatures as shell history (exfil/anti-forensics → HIGH, tradecraft → MED); user-typed prompts are scanned for anonymizer-infra references → MED (harness-injected blocks are excluded). Session count, prompt count, date range, and project paths → INFO.
  - **Custom skills / commands / agents / memory / shell snapshots** — content scan for download-then-execute cradles, anti-forensics commands, and Discord-webhook exfil channels → MED.
  - **Credential material** (`*.env` files in `.claude`) → LOW.
- **Claude Desktop `.claude_desktop` folder** (`<user>_claude_desktop/`, when collected):
  - **MCP servers** (`claude_desktop_config.json`) → LOW, HIGH when a server command has download-cradle/covert-channel patterns.
  - **Relaxed settings** — `bypassPermissionsGateByAccount` enabled or extension allowlist disabled → MED.
  - **Installed DXT extensions** (`extensions-installations.json` / `Claude_Extensions/`) → LOW (code-execution surface; enumerate and eyeball).
  - **Local-agent / cowork session content + extension payloads** — content-scanned for download-exec cradles, anti-forensics, Discord-webhook exfil → MED.
  - **Logs** (`logs/*.log`) → INFO — collected but not keyword-scanned; `mcp.log` / `coworkd.log` are the tool-execution timeline, grep them by hand for a deep-dive.

Windows-specific:
- **Running processes** — offensive tooling (mimikatz, Cobalt Strike, SharpHound…) → HIGH; masquerading/typosquat names (svch0st, lssass, scvhost…) → HIGH; remote/transfer tools running → MED.
- **Scheduled tasks** (MED) — non-Microsoft/vendor tasks in the listing. For the actual task payload, run `read_scheduled_tasks.py` (flags encoded commands, IEX, download cradles, LOLBins).
- **PowerShell history** — exfil/staging commands (`mysqldump`, `pg_dump`, `gsutil`, `aws s3`, `scp`, `rclone`, `Compress-Archive`, `robocopy`, `bitsadmin`, `certutil`, upload cmdlets) → HIGH; LOLBins / tradecraft (encoded commands, IEX, mshta/regsvr32/rundll32, `net user`, Defender-tampering, log-clearing) → MED, escalated to HIGH when Defender-disable or log-clearing is present. The lone official gcloud-SDK `DownloadFile` is auto-excluded.
- **Windows event logs** (with `--evtx`) — key security events: log-clearing 1102 → HIGH; account-create/delete 4720/4726, admin-group-add 4732, service-install 4697/7045, task-create 4698, explicit-cred logon 4648 → MED; failed logon 4625, lockout 4740 → LOW. Also flags **absent** 4624/4625 (audit policy not configured — absence ≠ no logons).

macOS-specific:
- **Running processes** — offensive tooling → HIGH; suspect execution (`/tmp`, `/var/folders`, `--headless`, inline `osascript -e`) → MED.
- **Persistence** — non-Apple/non-vendor LaunchAgents, LaunchDaemons, and cron entries → MED, escalated to HIGH when the entry references user-writable/temp paths, `curl`/`wget`, `base64`, or `osascript` (download cradle / covert persistence). Known vendors (CrowdStrike, JAMF, Zoom, GlobalProtect, 1Password…) are treated as noise.
- **Shell history (zsh/bash)** — exfil/staging (`rsync`, `scp`, `ditto`, `tar -c`, `zip -r`, DB dumps, `aws s3`/`gsutil`/`rclone`) → HIGH; download-then-execute (`curl … | bash`) → HIGH; anti-forensics / security-disable (`history -c`, `rm -rf ~/Library/Logs`, `spctl --master-disable`, `csrutil disable`) → HIGH; tradecraft (`base64 -d`, `osascript -e`, `nc`/`ncat`/`socat`, `dscl … create /Users`) → MED.
- **Login history** (INFO) — `mac_login_history.txt` surfaced for context.

## Interpreting / reporting

- Lead with the **HIGH/MED** count and what drove it. A package with **0 HIGH** and MED findings that are all comp-record/resume/job-search reads as **departure-prep / grievance**, not data theft — say that plainly.
- **Dual-use ≠ guilt.** WinSCP/PuTTY/Google Drive are normal for many roles (esp. DBAs/SREs). Report them as present, and only escalate if paired with staging archives or exfil commands.
- Distinguish **hands-on user actions** from tooling. (Pairs well with `pull-workspace-logs --human-only` on the cloud side.)

## Caveats

- **`.evtx` parsing is on by default and needs `python-evtx`.** Every Windows run now parses the event logs and adds the Event Log Summary / Key Security Events sheets — but that means you must run via `uv run --with python-evtx --with lxml --with openpyxl` (a uv env only has what you `--with`; missing `python-evtx` → loud `[warn]`, logs unparsed; missing `openpyxl` → `--xlsx` silently skipped). Parsing a 190MB+ `Security.evtx` record-by-record takes minutes — pass `--no-evtx` for a quick pass that skips it. `parse_evtx.py` gives full control (`--date-range`, `--event-ids`, `--all`); EvtxECmd / Chainsaw remain good alternatives for deep event work.
- **Platform auto-detected.** Windows and macOS packages are both supported; the platform is inferred from marker files and can be forced with `--platform`. If detection is `unknown` it warns and defaults to Windows. `--evtx` and `read_scheduled_tasks.py` are Windows-only; the macOS path has no event-log equivalent (persistence/login/shell history cover that ground).
- **Multi-user collections:** by default every non-system profile is scanned; use `--user` to target the subject and cut noise.
- **Encoding:** collector text/CSV artifacts are UTF-16LE; `dfir_triage.py` decodes BOM-first on the fly (idempotent). `decode_win_output.py --all --inplace` can batch-decode a package if you want to read files directly. If something still looks garbled, it fell back to best-effort decoding — note it rather than trusting the parse.
- **File listings, not files:** `*_All_files.txt` / `*_Downloads_files.txt` are directory listings (names/sizes/dates), so findings are based on filenames, not content.
- **Dual-use ≠ guilt** (bears repeating): WinSCP/PuTTY/Google Drive/OneDrive are normal for many roles (esp. DBAs/SREs). Report them as present; only escalate when paired with staging archives, exfil commands, or anonymizer infra.
- **`.claude` findings on security-team machines are noisy by design.** An analyst's Claude Code transcripts and custom skills legitimately contain exfil keywords, `osascript`, pastebin/ngrok strings, and even this skill's own indicator lists (`claude-content` will flag `dfir_triage.py` itself). Read the flagged *commands* — a DFIR triage one-liner and a real `rclone` upload look very different. On a non-security employee's machine the same hits deserve full weight.
- **Transcript scan scope:** only Bash `tool_use` commands and user-typed prompt text are keyword-scanned — not tool outputs or assistant prose. Hooks/skills are scanned as *content*; the transcripts are the record of what actually ran. For a deep-dive, the JSONL transcripts under `global_claude/projects/` are plain JSON-per-line and grep well.
- **Claude Desktop extension payloads are bundled deps.** `Claude_Extensions/` includes each extension's `node_modules/`, so the collected folder (and the content scan) can be large/noisy. The extension *count* and *names* are the signal; the bundled JS is scanned only for cradle/tamper/webhook strings. Desktop conversation history is server-side (not in the package) — the local record of behavior is the **logs** (`mcp.log`, `coworkd.log`) and `local-agent-mode-sessions/`, which is why those are collected.

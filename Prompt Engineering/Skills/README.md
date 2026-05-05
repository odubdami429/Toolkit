# Skills — Requirements

This directory contains Claude Code skills for Google Workspace security investigation. The skills orchestrate local Python scripts that pull and analyse Workspace audit logs via the `gws` CLI.

---

## Skills

| Skill | Purpose |
|---|---|
| `pull-workspace-logs` | Pulls Drive, Gmail, Login, OAuth, and IP logs for a user |
| `investigate-workspace-activity` | Correlates logs across sources and produces an investigation report |

---

## Requirements

### 1. Python 3.12+

Most scripts are pure stdlib. The one exception is `md_to_xlsx.py` (Excel export), which requires `openpyxl`.

```
python3 --version   # should be 3.12.x or later
pip install openpyxl
```

### 2. `gws` CLI (Google Workspace CLI)

The scripts invoke `gws admin-reports activities list` to fetch audit logs. The `gws` binary must be on your `PATH` and authenticated before running any skill.

```bash
# Verify the binary is available
gws --version

# Verify authentication
gws auth status
```

If you see an auth error when a skill runs, stop and re-authenticate — the scripts do not attempt to fix auth inline.

### 3. Google Workspace Admin permissions

The account authenticated in `gws` must have **Reports API** read access. At minimum it needs the `Reports > Audit` privilege in the Google Admin console. Without this, all `gws` calls will return a 403.

### 4. openpyxl (for Excel export)

The `investigate-workspace-activity` skill renders investigation reports to Excel using `md_to_xlsx.py`. Install the library before running the skill:

```bash
pip install openpyxl
```

No browser or external binary is required — the script is pure Python.

### 5. ipinfo.io access (optional, for IP enrichment)

`pull-workspace-logs/user_ips.py` calls `https://ipinfo.io` to enrich IP addresses with country, city, and ASN data. This works unauthenticated for low volumes; for higher volumes pass a token via `--token <your_ipinfo_token>`.

To skip enrichment entirely: `python3 user_ips.py <email> --no-enrich`

Results are cached at `~/Documents/WorkspaceLogs/.ipinfo_cache.json` to avoid redundant lookups.

---

## Output location

All scripts write to:

```
~/Documents/WorkspaceLogs/<first>_<last>_G_Logs/
```

The directory is created automatically on the first run.

---

## Quick setup checklist

- [ ] Python 3.12+ installed and `python3` resolves to it
- [ ] `gws` CLI installed and on `PATH`
- [ ] `gws auth status` returns a valid session
- [ ] Authenticated account has Reports API / Audit read access in Google Admin
- [ ] `openpyxl` installed (`pip install openpyxl`) for Excel report export
- [ ] (Optional) ipinfo.io token ready if pulling logs for many users

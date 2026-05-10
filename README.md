# Toolkit

A personal collection of scripts and configurations for IT security, endpoint management, and incident response. The repo is organized by language or tool category.

---

## Contents

### Bash
Scripts for macOS endpoints.

| File | Description |
|------|-------------|
| `DFIR_MAC.sh` | Collects DFIR artifacts from a macOS endpoint (running processes, network connections, logs, etc.) and writes output to `/tmp/DFIR_Output`. |

### PowerShell
Scripts for Windows environments and Microsoft 365 administration.

| File | Description |
|------|-------------|
| `DFIR_WIN.ps1` | Collects DFIR artifacts from a Windows endpoint and writes output to `C:\Temp\DFIR_Output`. |
| `Connect-ExchangeOnline.ps1` | Connects to Exchange Online via PowerShell. |
| `ConnectToAzure.ps1` | Authenticates to Azure via PowerShell. |
| `RegisterDeviceToAutoPilot.ps1` | Registers a device in Microsoft Autopilot. |
| `UserCSV.ps1` | Exports user data to a CSV. |
| `1Password_audit_scripts/Export-1P-Groups.ps1` | Exports 1Password group membership. |
| `1Password_audit_scripts/Export-1P-Vaults.ps1` | Exports 1Password vault list. |

### Jamf Extension Attributes
Custom extension attributes for Jamf Pro.

| File | Description |
|------|-------------|
| `icloud_check.sh` | Reports the iCloud account currently signed in on a managed Mac. |

### Browser Configs
| File | Description |
|------|-------------|
| `Firefox_Config.xml` | Firefox configuration template. |

### Prompt Engineering
AI prompts and Claude Code skills used for security and IT operations.

| File | Description |
|------|-------------|
| `Incident Response AI Agent.txt` | System prompt for an AI-assisted incident response agent. |
| `Skills/investigate-workspace-activity` | Claude Code skill for investigating Google Workspace activity. |
| `Skills/pull-workspace-logs` | Claude Code skill for pulling Google Workspace logs. |
| `Skills/recent-breach-tracker` | Claude Code skill for compiling a roundup of recent cybersecurity breaches. |
| `Skills/security-breach-intel` | Claude Code skill for producing a deep-dive intelligence report on a specific breach. |
| `Skills/eml-security-analyzer` | Claude Code skill for analyzing `.eml` files, raw headers, or Proofpoint TAP JSON for phishing indicators. |

### Python
Placeholder for future Python scripts.

---

## Usage

Most scripts are standalone — clone the repo and run the relevant script for your platform. Scripts that interact with cloud services (Azure, Exchange Online, 1Password) require appropriate credentials and permissions to be configured beforehand.

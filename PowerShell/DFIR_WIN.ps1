#======================================================================================
#This script collects various DFIR artifact from a Windows Endpoint by saving the output of various commands to a txt file
#Once the the script is done the output files will be placed in $outputDir
#======================================================================================

#Errors are handled per-operation (see Invoke-Section / Copy-Artifact / collection_log.csv)
#instead of being blanket-suppressed. Stop preference makes try/catch reliable; genuinely
#best-effort inner calls carry an explicit -ErrorAction SilentlyContinue.
$ErrorActionPreference = 'Stop'


#Recursively redact any property whose NAME looks like a credential (oauth token,
#secret, api key, cookie, password, bearer, session/refresh token) at any nesting
#depth. Non-secret fields (account UUID, timestamps, version, settings) are kept.
function Redact-Secrets {
    param($obj)
    $pattern = '(?i)token|secret|api[_-]?key|apikey|cookie|password|passwd|bearer|credential|oauth|refresh|session'
    if ($obj -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in @($obj.PSObject.Properties)) {
            if ($prop.Name -match $pattern) {
                $prop.Value = "<REDACTED>"
            }
            elseif ($prop.Value -is [System.Management.Automation.PSCustomObject] -or $prop.Value -is [System.Object[]]) {
                Redact-Secrets $prop.Value
            }
        }
    }
    elseif ($obj -is [System.Object[]]) {
        foreach ($item in $obj) { Redact-Secrets $item }
    }
}


#--------------------------------------------------------------------------------------
# Instrumentation + per-operation logging helpers
#--------------------------------------------------------------------------------------

#collection_log.csv rows (item 8) and per-section timings (item 11)
$script:CollectionLog = New-Object System.Collections.ArrayList
$script:Timings       = New-Object System.Collections.ArrayList

#Record the outcome of an individual artifact. Status is one of:
#  Collected  - artifact existed and was copied/exported
#  NotPresent - source did not exist (absent, distinct from failed)
#  Failed     - source existed but the operation errored (Detail carries the message)
function Add-LogEntry {
    param([string]$Artifact, [string]$Status, [string]$Detail = '')
    $null = $script:CollectionLog.Add([PSCustomObject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Artifact     = $Artifact
        Status       = $Status
        Detail       = $Detail
    })
}

#Time a named section. A throwing section is logged Failed and does NOT abort the run
#(this replaces the old blanket SilentlyContinue's "keep going" behaviour, at section grain).
function Invoke-Section {
    param([string]$Name, [scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
    } catch {
        Add-LogEntry $Name 'Failed' $_.Exception.Message
        Write-Host "[FAILED] $Name : $($_.Exception.Message)"
    } finally {
        $sw.Stop()
        $null = $script:Timings.Add([PSCustomObject]@{
            Section = $Name
            Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        })
    }
}

#Test-Path -> NotPresent; copy -> Collected/Failed. Never throws.
function Copy-Artifact {
    param([string]$Source, [string]$Destination, [string]$Label, [switch]$Recurse)
    if (-not (Test-Path -LiteralPath $Source)) {
        Add-LogEntry $Label 'NotPresent' $Source
        return $false
    }
    try {
        if ($Recurse) {
            Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force -ErrorAction Stop
        } else {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
        }
        Add-LogEntry $Label 'Collected' $Source
        return $true
    } catch {
        Add-LogEntry $Label 'Failed' "$Source :: $($_.Exception.Message)"
        return $false
    }
}

#Stream-copy a file that may be exclusively locked (SQLite History, live .evtx). Opening
#with FileShare::ReadWrite lets us read a file another process holds open. Also captures the
#-wal / -journal / -shm siblings when present. Locked/failed copies are logged and echoed.
function Copy-LockedFile {
    param([string]$Source, [string]$Destination, [string]$Label)
    if (-not (Test-Path -LiteralPath $Source)) {
        Add-LogEntry $Label 'NotPresent' $Source
        return
    }
    try {
        $src = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $dst = [System.IO.File]::Create($Destination)
            try { $src.CopyTo($dst) } finally { $dst.Dispose() }
        } finally { $src.Dispose() }
        Add-LogEntry $Label 'Collected' $Source
    } catch {
        Add-LogEntry $Label 'Failed' "$Source :: $($_.Exception.Message)"
        Write-Host "[LOCKED/FAILED] $Label could not be copied: $Source ($($_.Exception.Message))"
    }
    #Capture the SQLite write-ahead / rollback siblings alongside the main DB
    foreach ($ext in '-wal', '-journal', '-shm') {
        $sib = "$Source$ext"
        if (Test-Path -LiteralPath $sib) {
            try {
                $s = [System.IO.File]::Open($sib, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                try {
                    $d = [System.IO.File]::Create("$Destination$ext")
                    try { $s.CopyTo($d) } finally { $d.Dispose() }
                } finally { $s.Dispose() }
                Add-LogEntry "$Label$ext" 'Collected' $sib
            } catch {
                Add-LogEntry "$Label$ext" 'Failed' "$sib :: $($_.Exception.Message)"
            }
        }
    }
}

#Single depth-unbounded but PRUNED walk of a profile. Prunes AppData / node_modules / .git /
#.nuget / .gradle by name DURING descent and skips reparse points (junctions, OneDrive
#placeholders) so we never follow them. Returns the file records (item 1) and the set of
#.claude directories seen along the way (item 3) so Documents/Downloads (item 2) and the
#.claude discovery are all derived from this one traversal.
function Invoke-PrunedWalk {
    param([string]$Root)
    $pruneNames = @{ 'appdata' = $true; 'node_modules' = $true; '.git' = $true; '.nuget' = $true; '.gradle' = $true }
    $files      = New-Object System.Collections.ArrayList
    $claudeDirs = New-Object System.Collections.ArrayList
    $result = [PSCustomObject]@{ Files = $files; ClaudeDirs = $claudeDirs }

    $rootInfo = New-Object System.IO.DirectoryInfo($Root)
    if (-not $rootInfo.Exists) { return $result }

    $stack = New-Object System.Collections.Stack
    $stack.Push($rootInfo)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($f in $dir.EnumerateFiles()) {
                $null = $files.Add([PSCustomObject]@{
                    FullName         = $f.FullName
                    Length           = $f.Length
                    CreationTimeUtc  = $f.CreationTimeUtc.ToString('o')
                    LastWriteTimeUtc = $f.LastWriteTimeUtc.ToString('o')
                })
            }
        } catch {}
        try {
            foreach ($sub in $dir.EnumerateDirectories()) {
                if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                $name = $sub.Name.ToLowerInvariant()
                if ($name -eq '.claude') {
                    $null = $claudeDirs.Add($sub.FullName)   #record but do not descend; copied wholesale later
                    continue
                }
                if ($pruneNames.ContainsKey($name)) { continue }
                $stack.Push($sub)
            }
        } catch {}
    }
    return $result
}

#Enumerate the real Chromium "Default" + "Profile N" folders under a User Data root
#(item 4) instead of blindly probing Profile 1..100.
function Get-BrowserProfiles {
    param([string]$UserDataRoot)
    $profiles = @()
    if (Test-Path -LiteralPath "$UserDataRoot\Default") { $profiles += 'Default' }
    if (Test-Path -LiteralPath $UserDataRoot) {
        Get-ChildItem -LiteralPath $UserDataRoot -Directory -Filter 'Profile *' -ErrorAction SilentlyContinue |
            ForEach-Object { $profiles += $_.Name }
    }
    return $profiles
}

#Remove any .credentials.json that a recursive .claude copy may have picked up (item 9).
function Remove-CredentialFiles {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Recurse -Force -Filter '.credentials.json' -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                Write-Host "[EXCLUDED] removed credential file: $($_.FullName)"
            } catch {
                Write-Host "[WARN] could not remove credential file $($_.FullName): $($_.Exception.Message)"
            }
        }
}

#Redact secret-looking values from an already-copied directory tree (item 9). JSON is parsed
#and run through Redact-Secrets; JSONL is redacted line-by-line; anything else (logs) gets a
#best-effort regex pass over key:value / key=value assignments.
function Invoke-RedactionPass {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $secretRegex = '(?i)(["'']?\w*(?:token|secret|api[_-]?key|apikey|cookie|password|passwd|bearer|credential|oauth|refresh|session)\w*["'']?\s*[:=]\s*)("[^"]*"|[^\s,}\]]+)'
    Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_.FullName
        $ext  = $_.Extension.ToLowerInvariant()
        try {
            if ($ext -eq '.json') {
                $raw = Get-Content -LiteralPath $file -Raw
                try {
                    $obj = $raw | ConvertFrom-Json
                    Redact-Secrets $obj
                    $obj | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $file -Encoding UTF8
                } catch {
                    ($raw -replace $secretRegex, '$1"<REDACTED>"') | Set-Content -LiteralPath $file -Encoding UTF8
                }
            }
            elseif ($ext -eq '.jsonl') {
                $out = New-Object System.Collections.ArrayList
                foreach ($line in [System.IO.File]::ReadAllLines($file)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { $null = $out.Add($line); continue }
                    try {
                        $o = $line | ConvertFrom-Json
                        Redact-Secrets $o
                        $null = $out.Add(($o | ConvertTo-Json -Depth 30 -Compress))
                    } catch {
                        $null = $out.Add(($line -replace $secretRegex, '$1"<REDACTED>"'))
                    }
                }
                [System.IO.File]::WriteAllLines($file, $out)
            }
            else {
                $raw = Get-Content -LiteralPath $file -Raw
                ($raw -replace $secretRegex, '$1"<REDACTED>"') | Set-Content -LiteralPath $file -Encoding UTF8
            }
        } catch {
            Write-Host "[REDACT] could not process $file : $($_.Exception.Message)"
        }
    }
}

#Per-user artifact collection body. Kept as an inline block invoked from both the VM (D:) and
#laptop (C:) branches via dot-sourced scriptblock so the two branches stay independent while
#the collection logic is written once. $u = user name, $root = profile root.
$UserCollectionBlock = {
    $root = "$driveRoot\$u"
    $dest = "$outputDir\User_level_files\${u}_files"
    New-Item -Path $dest -ItemType "directory" -Force | Out-Null

    #---- Single pruned walk feeds All_files, Documents, Downloads, and .claude discovery ----
    $walk = Invoke-PrunedWalk -Root $root
    $walk.Files | Export-Csv -Path "$dest\${u}_All_files.txt" -NoTypeInformation
    Add-LogEntry "$u All_files" 'Collected' "$($walk.Files.Count) files"

    #Documents / Downloads are FILTERED from the single pass (item 2), not re-walked
    ($walk.Files | Where-Object { $_.FullName -like "$root\Documents\*" }) |
        Export-Csv -Path "$dest\${u}_Documents_files.txt" -NoTypeInformation
    ($walk.Files | Where-Object { $_.FullName -like "$root\Downloads\*" }) |
        Export-Csv -Path "$dest\${u}_Downloads_files.txt" -NoTypeInformation

    #---- Chrome / Edge history (locked-file aware, real profiles only) ----
    $chromeUD = "$root\AppData\Local\Google\Chrome\User Data"
    foreach ($p in (Get-BrowserProfiles $chromeUD)) {
        $safe = $p -replace '\s', '_'
        Copy-LockedFile -Source "$chromeUD\$p\History" -Destination "$dest\${u}_Chrome_${safe}_History.db" -Label "$u Chrome/$p History"
    }
    $edgeUD = "$root\AppData\Local\Microsoft\Edge\User Data"
    foreach ($p in (Get-BrowserProfiles $edgeUD)) {
        $safe = $p -replace '\s', '_'
        Copy-LockedFile -Source "$edgeUD\$p\History" -Destination "$dest\${u}_Edge_${safe}_History.db" -Label "$u Edge/$p History"
    }

    #---- PowerShell console history ----
    Copy-Artifact -Source "$root\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
                  -Destination "$dest\${u} powershell_logs.txt" -Label "$u ConsoleHost_history" | Out-Null
    #Distinct destination so the VS Code host history no longer overwrites the console history
    Copy-Artifact -Source "$root\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt" `
                  -Destination "$dest\${u} vscode_powershell_logs.txt" -Label "$u VSCodeHost_history" | Out-Null

    #---- Global + project .claude folders (from the single walk; .credentials.json excluded) ----
    $claudeDest   = "$dest\${u}_claude_folders"
    $globalClaude = "$root\.claude"
    if (Test-Path -LiteralPath $globalClaude) {
        New-Item -Path $claudeDest -ItemType "directory" -Force | Out-Null
        if (Copy-Artifact -Source $globalClaude -Destination "$claudeDest\global_claude" -Label "$u global .claude" -Recurse) {
            Remove-CredentialFiles "$claudeDest\global_claude"
        }
    } else {
        Add-LogEntry "$u global .claude" 'NotPresent' $globalClaude
    }
    foreach ($cd in $walk.ClaudeDirs) {
        if ($cd -ieq $globalClaude) { continue }
        if ($cd -like "$globalClaude\*") { continue }
        New-Item -Path $claudeDest -ItemType "directory" -Force | Out-Null
        $projectName = (Split-Path $cd -Parent) -replace [regex]::Escape("$root\"), '' -replace '\\', '_'
        $target = "$claudeDest\project_${projectName}_claude"
        if (Copy-Artifact -Source $cd -Destination $target -Label "$u project .claude ($projectName)" -Recurse) {
            Remove-CredentialFiles $target
        }
    }

    #---- Claude Desktop artifacts (credential material still deliberately NOT collected) ----
    $claudeDesktopSrc = "$root\AppData\Roaming\Claude"
    if (Test-Path -LiteralPath $claudeDesktopSrc) {
        $cdDest = "$dest\${u}_claude_desktop"
        New-Item -Path $cdDest -ItemType "directory" -Force | Out-Null

        #MCP server config (no secrets)
        Copy-Artifact -Source "$claudeDesktopSrc\claude_desktop_config.json" -Destination "$cdDest\claude_desktop_config.json" -Label "$u claude_desktop_config.json" | Out-Null

        #App preferences - copied, then oauth/token/secret values redacted at any depth
        if (Test-Path -LiteralPath "$claudeDesktopSrc\config.json") {
            try {
                $cfg = Get-Content -LiteralPath "$claudeDesktopSrc\config.json" -Raw | ConvertFrom-Json
                Redact-Secrets $cfg
                $cfg | ConvertTo-Json -Depth 20 | Out-File "$cdDest\config.json"
                Add-LogEntry "$u claude desktop config.json" 'Collected' "$claudeDesktopSrc\config.json"
            } catch {
                #If parsing fails, skip config.json rather than risk copying tokens
                Add-LogEntry "$u claude desktop config.json" 'Failed' $_.Exception.Message
            }
        } else {
            Add-LogEntry "$u claude desktop config.json" 'NotPresent' "$claudeDesktopSrc\config.json"
        }

        #Installed desktop extensions metadata + payloads
        Copy-Artifact -Source "$claudeDesktopSrc\extensions-installations.json" -Destination "$cdDest\extensions-installations.json" -Label "$u extensions-installations.json" | Out-Null
        Copy-Artifact -Source "$claudeDesktopSrc\extensions-blocklist.json" -Destination "$cdDest\extensions-blocklist.json" -Label "$u extensions-blocklist.json" | Out-Null
        Copy-Artifact -Source "$claudeDesktopSrc\Claude Extensions" -Destination "$cdDest\Claude_Extensions" -Label "$u Claude Extensions" -Recurse | Out-Null
        Copy-Artifact -Source "$claudeDesktopSrc\Claude Extensions Settings" -Destination "$cdDest\Claude_Extensions_Settings" -Label "$u Claude Extensions Settings" -Recurse | Out-Null

        #Local agent / cowork + claude-code session history - copied then redacted (item 9)
        if (Copy-Artifact -Source "$claudeDesktopSrc\local-agent-mode-sessions" -Destination "$cdDest\local-agent-mode-sessions" -Label "$u local-agent-mode-sessions" -Recurse) {
            Invoke-RedactionPass "$cdDest\local-agent-mode-sessions"
        }
        if (Copy-Artifact -Source "$claudeDesktopSrc\claude-code-sessions" -Destination "$cdDest\claude-code-sessions" -Label "$u claude-code-sessions" -Recurse) {
            Invoke-RedactionPass "$cdDest\claude-code-sessions"
        }

        #Application + MCP server logs - copied then redacted (item 9)
        if (Copy-Artifact -Source "$claudeDesktopSrc\logs" -Destination "$cdDest\logs" -Label "$u claude desktop logs" -Recurse) {
            Invoke-RedactionPass "$cdDest\logs"
        }
    } else {
        Add-LogEntry "$u claude desktop" 'NotPresent' $claudeDesktopSrc
    }
}


#--------------------------------------------------------------------------------------
# Setup
#--------------------------------------------------------------------------------------

#Output folder named after the endpoint and the UTC date of collection
$dateStamp = (Get-Date).ToUniversalTime().ToString("yyyy_MM_dd")
$outputDir = "C:\Temp\DFIR_Output_$($env:COMPUTERNAME)_$dateStamp"

#Creates a folder that will contain all the artifacts
New-Item -Path $outputDir -ItemType "directory" -Force | Out-Null


#==========================================
#Collecting System Information
#==========================================

Invoke-Section 'system_info' {
    #Collect User and System information
    systeminfo | Out-File "$outputDir\system_info.txt"
    "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\system_info.txt"
    (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\system_info.txt"
    Add-LogEntry 'system_info' 'Collected' "$outputDir\system_info.txt"
}

Invoke-Section 'running_processes' {
    #Collect list of Running Processes
    tasklist /v | Out-File "$outputDir\running_processes.txt"
    "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\running_processes.txt"
    (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\running_processes.txt"
    Add-LogEntry 'running_processes' 'Collected' "$outputDir\running_processes.txt"
}

Invoke-Section 'scheduled_task' {
    #Collect list of scheduled task
    Get-ChildItem C:\Windows\System32\Tasks | Out-File "$outputDir\scheduled_task.txt"
    "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\scheduled_task.txt"
    (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\scheduled_task.txt"
    Add-LogEntry 'scheduled_task' 'Collected' "$outputDir\scheduled_task.txt"
}

Invoke-Section 'system_level_installed_apps' {
    #Collect list of system-level installed apps.
    #-ErrorAction SilentlyContinue: under SYSTEM (and often otherwise) the HKCU Uninstall key
    #does not exist. A missing hive is expected, not a section failure - skip it and keep the
    #HKLM/Wow6432 results rather than letting the throw abort the whole export.
    Get-ItemProperty -ErrorAction SilentlyContinue `
      HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
      HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, `
      HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* `
    | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate `
    | Export-Csv -Path "$outputDir\system_level_installed_apps.csv" -NoTypeInformation
    Add-LogEntry 'system_level_installed_apps' 'Collected' "$outputDir\system_level_installed_apps.csv"
}

Invoke-Section 'user_level_installed_apps' {
    #Collect list of user-level installed apps
    # Gather all user SIDs from HKEY_USERS except .DEFAULT and *_Classes
    $allUserSIDs = Get-ChildItem 'Registry::HKEY_USERS' `
      | Where-Object { $_.Name -notmatch "(_Classes$|\.DEFAULT$)" }

    # Initialize a list to hold all uninstall entries
    $allUninstalls = @()

    foreach ($sid in $allUserSIDs) {
        $uninstallPath = "$($sid.Name)\Software\Microsoft\Windows\CurrentVersion\Uninstall"

        if (Test-Path "Registry::$uninstallPath") {
            Get-ChildItem "Registry::$uninstallPath" -ErrorAction SilentlyContinue |
            ForEach-Object {
                # Grab the uninstall properties for each subkey
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue

                # Create a new object including the SID as a field
                $allUninstalls += [PSCustomObject]@{
                    UserSID       = $sid.Name
                    PSChildName   = $props.PSChildName
                    DisplayName   = $props.DisplayName
                    DisplayVersion= $props.DisplayVersion
                    Publisher     = $props.Publisher
                    InstallDate   = $props.InstallDate
                }
            }
        }
    }

    # Now export all collected entries to CSV
    $allUninstalls | Export-Csv -Path "$outputDir\user_level_installed_apps.csv" -NoTypeInformation
    Add-LogEntry 'user_level_installed_apps' 'Collected' "$outputDir\user_level_installed_apps.csv"
}


#==========================================
#Collecting Networking Information
#==========================================

Invoke-Section 'udp_connections' {
    #Collect list of UDP connections
    Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,CreationTime,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -auto | Out-File "$outputDir\udp_connections.txt"
    "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\udp_connections.txt"
    (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\udp_connections.txt"
    Add-LogEntry 'udp_connections' 'Collected' "$outputDir\udp_connections.txt"
}

Invoke-Section 'tcp_connections' {
    #Collect list of TCP connections
    Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,CreationTime,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -auto | Out-File "$outputDir\tcp_connections.txt"
    "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\tcp_connections.txt"
    (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\tcp_connections.txt"
    Add-LogEntry 'tcp_connections' 'Collected' "$outputDir\tcp_connections.txt"
}

Invoke-Section 'firewall_settings' {
    #Collect list of all firewall rules on the system.
    #Fetch rules + port filters + address filters ONCE each and join on InstanceID,
    #instead of two CIM round-trips per rule (item 5).
    $rules = Get-NetFirewallRule
    $ports = Get-NetFirewallPortFilter -All
    $addrs = Get-NetFirewallAddressFilter -All

    $portByID = @{}
    foreach ($p in $ports) { $portByID[$p.InstanceID] = $p }
    $addrByID = @{}
    foreach ($a in $addrs) { $addrByID[$a.InstanceID] = $a }

    $fwRules = foreach ($r in $rules) {
        $pf = $portByID[$r.InstanceID]
        $af = $addrByID[$r.InstanceID]
        [PSCustomObject]@{
            Name          = $r.Name
            DisplayName   = $r.DisplayName
            DisplayGroup  = $r.DisplayGroup
            Protocol      = $pf.Protocol
            LocalPort     = ($pf.LocalPort  -join ';')
            RemotePort    = ($pf.RemotePort -join ';')
            RemoteAddress = ($af.RemoteAddress -join ';')
            Enabled       = $r.Enabled
            Profile       = $r.Profile
            Direction     = $r.Direction
            Action        = $r.Action
        }
    }

    $fwRules | Export-Csv -Path "$outputDir\firewall_settings.csv" -NoTypeInformation
    Add-LogEntry 'firewall_settings' 'Collected' "$outputDir\firewall_settings.csv"
}


#==========================================
# Getting Windows and Browser History log files
#==========================================

Invoke-Section 'windows_event_logs' {
    #Creates a folder that will contain all copied windows event logs
    New-Item -Path "$outputDir\" -Name "windows_logs" -ItemType "directory" -Force | Out-Null

    #Copy over the Security, Systems and Application windows event logs.
    #These are held open by the EventLog service, so use the locked-file copy (item 7 helper).
    Copy-LockedFile -Source "C:\Windows\System32\winevt\Logs\Security.evtx"    -Destination "$outputDir\windows_logs\Security.evtx"    -Label 'Security.evtx'
    Copy-LockedFile -Source "C:\Windows\System32\winevt\Logs\System.evtx"      -Destination "$outputDir\windows_logs\System.evtx"      -Label 'System.evtx'
    Copy-LockedFile -Source "C:\Windows\System32\winevt\Logs\Application.evtx" -Destination "$outputDir\windows_logs\Application.evtx" -Label 'Application.evtx'
}

#Creates a folder that will contain all copied per-user files
New-Item -Path "$outputDir\" -Name "User_level_files" -ItemType "directory" -Force | Out-Null

#Adding the manufacturer of a device to a variable. This sits between wrapped sections, so
#guard it: a CIM hiccup must not abort the whole run - default to the laptop (C:) path.
try {
    $Manufacturer = (Get-CimInstance win32_computersystem -Property Manufacturer).Manufacturer
} catch {
    $Manufacturer = ''
    Add-LogEntry 'manufacturer_detection' 'Failed' $_.Exception.Message
    Write-Host "[WARN] manufacturer detection failed, defaulting to laptop path: $($_.Exception.Message)"
}
Write-Host $Manufacturer

#Check if the device in question is a VM because the user app data and files are stored in the D-Drive for VM users
if ($Manufacturer -like "*Amazon EC2*") {

    Write-Host "Windows VDI Detected"

    $driveRoot = "D:\Users"
    $d_drive_users = (Get-ChildItem D:\Users).Name

    foreach ($d_drive_users in $d_drive_users) {
        $u = $d_drive_users
        Invoke-Section "user_files:$u" $UserCollectionBlock
    }

}
else {

    Write-Host "Windows Laptop/Desktop Detected"

    $driveRoot = "C:\Users"

    Invoke-Section 'wifi_profiles' {
        #Collect list of Wifi Profiles
        netsh wlan show profiles | Out-File "$outputDir\wifi_profiles.txt"
        "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\wifi_profiles.txt"
        (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\wifi_profiles.txt"
        Add-LogEntry 'wifi_profiles' 'Collected' "$outputDir\wifi_profiles.txt"
    }

    #Copy over the Powershell history log file and chrome history file for all user profiles on the endpoint
    $c_drive_users = (Get-ChildItem C:\Users).Name
    foreach ($c_drive_users in $c_drive_users) {
        $u = $c_drive_users
        Invoke-Section "user_files:$u" $UserCollectionBlock
    }

}

#==========================================
# Zipping up the output folder
#==========================================

#Write the per-artifact collection log INTO the output folder so it travels inside the zip (item 8)
try {
    $script:CollectionLog | Export-Csv -Path "$outputDir\collection_log.csv" -NoTypeInformation
} catch {
    Write-Host "[WARN] could not write collection_log.csv: $($_.Exception.Message)"
}

Invoke-Section 'zip_and_manifest' {
    #Zip up the output folder so it is easier to collect off the endpoint
    #Uses the .NET zip API instead of Compress-Archive because Compress-Archive writes backslash
    #path separators into the archive, which extracts as flat files on Mac/Linux
    $zipPath = "${outputDir}.zip"
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    #Fastest compression (item 6) - trades archive size for CPU time to help beat the 600s cap
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outputDir, $zipPath, [System.IO.Compression.CompressionLevel]::Fastest, $true)

    #Delete the unzipped output folder, but only if the zip was created successfully
    if (Test-Path $zipPath) {
        #Compute SHA256 + size and write a manifest NEXT TO the archive (survives the folder delete),
        #then echo it so it lands in the RTR command output (item 10)
        $hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
        $size = (Get-Item $zipPath).Length
        $manifestPath = "${zipPath}.manifest.txt"
        @(
            "ZipFile   : $(Split-Path $zipPath -Leaf)"
            "SizeBytes : $size"
            "SHA256    : $hash"
            "CreatedUtc: $((Get-Date).ToUniversalTime().ToString('o'))"
        ) | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        Write-Host "==== DFIR ARCHIVE MANIFEST ===="
        Write-Host "ZipFile  : $zipPath"
        Write-Host "SizeBytes: $size"
        Write-Host "SHA256   : $hash"
        Write-Host "==============================="

        Remove-Item $outputDir -Recurse -Force
        Write-Host "Collection complete. Zipped output: $zipPath"
    }
    else {
        Write-Host "Zipping failed - unzipped output left in: $outputDir"
    }
}

#==========================================
# Timings + collection summary (stdout only) - item 11
#==========================================
Write-Host "`n==== TIMINGS (seconds, slowest first) ===="
$script:Timings | Sort-Object Seconds -Descending | ForEach-Object {
    Write-Host ("{0,-40} {1,8}" -f $_.Section, $_.Seconds)
}
$totalSecs = ($script:Timings | Measure-Object -Property Seconds -Sum).Sum
Write-Host ("{0,-40} {1,8}" -f 'TOTAL', [math]::Round($totalSecs, 2))

$counts = $script:CollectionLog | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host ("`nCollection log summary: " + ($counts -join '  '))

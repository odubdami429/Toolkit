#======================================================================================
#This script collects various DFIR artifact from a Windows Endpoint by saving the output of various commands to a txt file
#Once the the script is done the output files will be placed in $outputDir
#======================================================================================

#Allows the script to continue even if there are errors
$ErrorActionPreference = 'SilentlyContinue'


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



#Output folder named after the endpoint and the UTC date of collection
$dateStamp = (Get-Date).ToUniversalTime().ToString("yyyy_MM_dd")
$outputDir = "C:\Temp\DFIR_Output_$($env:COMPUTERNAME)_$dateStamp"

#Creates a folder that will contain all the artifacts
New-Item -Path $outputDir -ItemType "directory";
 

#==========================================
#Collecting System Information
#==========================================

#Collect User and System information
systeminfo | Out-File "$outputDir\system_info.txt";
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\system_info.txt";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\system_info.txt";

#Collect list of Running Processes
tasklist /v | Out-File "$outputDir\running_processes.txt";
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\running_processes.txt";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\running_processes.txt"


#Collect list of scheduled task
Get-ChildItem C:\Windows\System32\Tasks | Out-File "$outputDir\scheduled_task.txt";
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\scheduled_task.txt";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\scheduled_task.txt"


#Collect list of system-level installed apps 
Get-ItemProperty `
  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
  HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, `
  HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* `
| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate `
| Export-Csv -Path "$outputDir\system_level_installed_apps.csv" -NoTypeInformation
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\system_level_installed_apps.csv";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\system_level_installed_apps.csv"


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
            $props = Get-ItemProperty $_.PSPath
            
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
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\user_level_installed_apps.csv";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\user_level_installed_apps.csv"


#==========================================
#Collecting Networking Information
#==========================================

#Collect list of UDP connections
Get-NetUDPEndpoint  | Select-Object LocalAddress,LocalPort,CreationTime,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | ft -auto | Out-File "$outputDir\udp_connections.txt";
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\udp_connections.txt";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\udp_connections.txt"


#Collect list of TCP connections
Get-NetTCPConnection |  select-object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,CreationTime,OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | ft -auto | Out-File "$outputDir\tcp_connections.txt";
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\tcp_connections.txt";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\tcp_connections.txt"


#Collect list of all firewall rules on the system
$fwRules = Get-NetFirewallRule | ForEach-Object {
    # Collect the port filter (protocol, local port, remote port)
    $portFilter = $_ | Get-NetFirewallPortFilter
    # Collect the address filter (remote address)
    $addrFilter = $_ | Get-NetFirewallAddressFilter

    # Return a custom object with all the relevant fields
    [PSCustomObject]@{
        Name           = $_.Name
        DisplayName    = $_.DisplayName
        DisplayGroup   = $_.DisplayGroup
        Protocol       = $portFilter.Protocol
        LocalPort      = $portFilter.LocalPort
        RemotePort     = $portFilter.RemotePort
        RemoteAddress  = $addrFilter.RemoteAddress
        Enabled        = $_.Enabled
        Profile        = $_.Profile
        Direction      = $_.Direction
        Action         = $_.Action
    }
}

# Export firewall rules to a CSV file
$fwRules | Export-Csv -Path "$outputDir\firewall_settings.csv" -NoTypeInformation
"`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\firewall_settings.csv";
(Get-Date).ToUniversalTime() | Out-File -append "$outputDir\firewall_settings.csv"


#==========================================
# Getting Windows and Browser History log files
#==========================================

#Creates a folder that will contain all copied windows event logs
New-Item -Path "$outputDir\" -Name "windows_logs" -ItemType "directory";

#Copy over the Security, Systems and Application windows event logs 
Copy-Item "C:\Windows\System32\winevt\Logs\Security.evtx" -Destination "$outputDir\windows_logs"
Copy-Item "C:\Windows\System32\winevt\Logs\System.evtx" -Destination "$outputDir\windows_logs"
Copy-Item "C:\Windows\System32\winevt\Logs\Application.evtx" -Destination "$outputDir\windows_logs"



#Creates a folder that will contain all copied browser history files
New-Item -Path "$outputDir\" -Name "User_level_files" -ItemType "directory";

$Manufacturer = (Get-CimInstance win32_computersystem -Property Manufacturer).Manufacturer #Addding the manufacturer of a device to a variable
Write-Host $Manufacturer

#Check if the device in question is a VM because the user app data and files are stored in the D-Drive for VM users
if ($Manufacturer -like "*Amazon EC2*") {


    Write-Host "Windows VDI Detected"


    $d_drive_users = (Get-ChildItem D:\Users).Name

    foreach ($d_drive_users in $d_drive_users) {

        #Creates a user folder that will contain all copied powershell and browser history files
        New-Item -Path "$outputDir\User_level_files\" -Name "${d_drive_users}_files" -ItemType "directory";

        #Collect list of all files and folders in the user folder
        Get-ChildItem D:\Users\$d_drive_users -Recurse | Out-File "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_All_files.txt";

         #Collect list of all files and folders in the user's documents folder
        Get-ChildItem D:\Users\$d_drive_users\Documents -Recurse | Out-File "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_Documents_files.txt";

        #Collect list of all files and folders in the user's downloads folder
        Get-ChildItem D:\Users\$d_drive_users\Downloads -Recurse | Out-File "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_Downloads_files.txt";

         #Grab the Chrome and Edge history files for D drive users
        Copy-Item "D:\Users\${d_drive_users}\AppData\Local\Google\Chrome\User Data\Default\History" "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_Chrome_Default_History.db"
        Copy-Item "D:\Users\${d_drive_users}\AppData\Local\Microsoft\Edge\User Data\Default\History" "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_Edge_Default_History.db"
        for ($profileNumber = 1; $profileNumber -le 100; $profileNumber++) {

            Copy-Item "D:\Users\${d_drive_users}\AppData\Local\Google\Chrome\User Data\Profile ${profileNumber}\History" "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_Chrome_Profile_${profileNumber}_History.db"
            Copy-Item "D:\Users\${d_drive_users}\AppData\Local\Microsoft\Edge\User Data\Profile ${profileNumber}\History" "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_Edge_Profile_${profileNumber}_History.db"
        }


        #Grab the PowerShell logs for the user
        Copy-Item "D:\Users\${d_drive_users}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users} powershell_logs.txt"
        Copy-Item "D:\Users\${d_drive_users}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt" "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users} powershell_logs.txt"

        #Copy over the global .claude folder (Claude Code config, session history, etc.)
        #The claude_folders directory is only created if the user actually has .claude folders
        $claudeDest = "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_claude_folders"
        if (Test-Path "D:\Users\${d_drive_users}\.claude") {
            New-Item -Path $claudeDest -ItemType "directory" -Force;
            Copy-Item "D:\Users\${d_drive_users}\.claude" -Destination "$claudeDest\global_claude" -Recurse -Force
        }

        #Find and copy over any project-level .claude folders in the user's folder
        Get-ChildItem "D:\Users\${d_drive_users}" -Recurse -Directory -Filter ".claude" -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne "D:\Users\${d_drive_users}\.claude" -and $_.FullName -notmatch '\\(AppData|node_modules)\\' } |
            ForEach-Object {
                $projectName = ($_.Parent.FullName -replace "^D:\\Users\\${d_drive_users}\\", '' -replace '\\', '_')
                New-Item -Path $claudeDest -ItemType "directory" -Force;
                Copy-Item $_.FullName -Destination "$claudeDest\project_${projectName}_claude" -Recurse -Force
            }

        #Copy over Claude Desktop artifacts (config, extensions, logs, local-agent sessions).
        #Credential material (Cookies, buddy-tokens.json, Local State) is deliberately NOT
        #collected; oauth/token/secret values inside config.json are redacted on the way out.
        $claudeDesktopSrc = "D:\Users\${d_drive_users}\AppData\Roaming\Claude"
        if (Test-Path $claudeDesktopSrc) {
            $cdDest = "$outputDir\User_level_files\${d_drive_users}_files\${d_drive_users}_claude_desktop"
            New-Item -Path $cdDest -ItemType "directory" -Force;

            #MCP server config (no secrets)
            Copy-Item "$claudeDesktopSrc\claude_desktop_config.json" "$cdDest\claude_desktop_config.json" -Force

            #App preferences - copied, then oauth/token/secret values redacted at any depth
            if (Test-Path "$claudeDesktopSrc\config.json") {
                try {
                    $cfg = Get-Content "$claudeDesktopSrc\config.json" -Raw | ConvertFrom-Json
                    Redact-Secrets $cfg
                    $cfg | ConvertTo-Json -Depth 20 | Out-File "$cdDest\config.json"
                } catch {
                    #If parsing fails, skip config.json rather than risk copying tokens
                }
            }

            #Installed desktop extensions metadata + payloads
            Copy-Item "$claudeDesktopSrc\extensions-installations.json" "$cdDest\" -Force
            Copy-Item "$claudeDesktopSrc\extensions-blocklist.json" "$cdDest\" -Force
            Copy-Item "$claudeDesktopSrc\Claude Extensions" "$cdDest\Claude_Extensions" -Recurse -Force
            Copy-Item "$claudeDesktopSrc\Claude Extensions Settings" "$cdDest\Claude_Extensions_Settings" -Recurse -Force

            #Local agent / cowork session history
            Copy-Item "$claudeDesktopSrc\local-agent-mode-sessions" "$cdDest\local-agent-mode-sessions" -Recurse -Force
            Copy-Item "$claudeDesktopSrc\claude-code-sessions" "$cdDest\claude-code-sessions" -Recurse -Force

            #Application + MCP server logs
            if (Test-Path "$claudeDesktopSrc\logs") {
                Copy-Item "$claudeDesktopSrc\logs" "$cdDest\logs" -Recurse -Force
            }
        }
    }

}
else {

    Write-Host "Windows Laptop/Desktop Detected"

    #Collect list of Wifi Profiles
    netsh wlan show profiles | Out-File "$outputDir\wifi_profiles.txt";
    "`n`nDate of Artifact Collection in UTC Time:" | Out-File -append "$outputDir\wifi_profiles.txt"
    (Get-Date).ToUniversalTime() | Out-File -append "$outputDir\wifi_profiles.txt"
        
    #Copy over the Powershell history log file and chrome history file for all user profiles on the endpoint
    $c_drive_users = (Get-ChildItem C:\Users).Name
    foreach ($c_drive_users in $c_drive_users) {

        #Creates a user folder that will contain all copied powershell and browser history files
        New-Item -Path "$outputDir\User_level_files\" -Name "${c_drive_users}_files" -ItemType "directory";

        #Collect list of all files and folders in the user folder
        Get-ChildItem C:\Users\$c_drive_users -Recurse | Out-File "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_All_files.txt";

        #Collect list of all files and folders in the user's documents folder
        Get-ChildItem C:\Users\$c_drive_users\Documents -Recurse | Out-File "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_Documents_files.txt";

        #Collect list of all files and folders in the user's downloads folder
        Get-ChildItem C:\Users\$c_drive_users\Downloads -Recurse | Out-File "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_Downloads_files.txt";

         #Grab the Chrome and Edge history files for C drive users
        Copy-Item "C:\Users\${c_drive_users}\AppData\Local\Google\Chrome\User Data\Default\History" "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_Chrome_Default_History.db"
        Copy-Item "C:\Users\${c_drive_users}\AppData\Local\Microsoft\Edge\User Data\Default\History" "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_Edge_Default_History.db"
        for ($profileNumber = 1; $profileNumber -le 100; $profileNumber++) {

            Copy-Item "C:\Users\${c_drive_users}\AppData\Local\Google\Chrome\User Data\Profile ${profileNumber}\History" "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_Chrome_Profile_${profileNumber}_History.db"
            Copy-Item "C:\Users\${c_drive_users}\AppData\Local\Microsoft\Edge\User Data\Profile ${profileNumber}\History" "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_Edge_Profile_${profileNumber}_History.db"
        }


        #Grab the PowerShell logs for the user
        Copy-Item "C:\Users\${c_drive_users}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users} powershell_logs.txt"
        Copy-Item "C:\Users\${c_drive_users}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt" "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users} powershell_logs.txt"

        #Copy over the global .claude folder (Claude Code config, session history, etc.)
        #The claude_folders directory is only created if the user actually has .claude folders
        $claudeDest = "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_claude_folders"
        if (Test-Path "C:\Users\${c_drive_users}\.claude") {
            New-Item -Path $claudeDest -ItemType "directory" -Force;
            Copy-Item "C:\Users\${c_drive_users}\.claude" -Destination "$claudeDest\global_claude" -Recurse -Force
        }

        #Find and copy over any project-level .claude folders in the user's folder
        Get-ChildItem "C:\Users\${c_drive_users}" -Recurse -Directory -Filter ".claude" -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne "C:\Users\${c_drive_users}\.claude" -and $_.FullName -notmatch '\\(AppData|node_modules)\\' } |
            ForEach-Object {
                $projectName = ($_.Parent.FullName -replace "^C:\\Users\\${c_drive_users}\\", '' -replace '\\', '_')
                New-Item -Path $claudeDest -ItemType "directory" -Force;
                Copy-Item $_.FullName -Destination "$claudeDest\project_${projectName}_claude" -Recurse -Force
            }

        #Copy over Claude Desktop artifacts (config, extensions, logs, local-agent sessions).
        #Credential material (Cookies, buddy-tokens.json, Local State) is deliberately NOT
        #collected; oauth/token/secret values inside config.json are redacted on the way out.
        $claudeDesktopSrc = "C:\Users\${c_drive_users}\AppData\Roaming\Claude"
        if (Test-Path $claudeDesktopSrc) {
            $cdDest = "$outputDir\User_level_files\${c_drive_users}_files\${c_drive_users}_claude_desktop"
            New-Item -Path $cdDest -ItemType "directory" -Force;

            #MCP server config (no secrets)
            Copy-Item "$claudeDesktopSrc\claude_desktop_config.json" "$cdDest\claude_desktop_config.json" -Force

            #App preferences - copied, then oauth/token/secret values redacted at any depth
            if (Test-Path "$claudeDesktopSrc\config.json") {
                try {
                    $cfg = Get-Content "$claudeDesktopSrc\config.json" -Raw | ConvertFrom-Json
                    Redact-Secrets $cfg
                    $cfg | ConvertTo-Json -Depth 20 | Out-File "$cdDest\config.json"
                } catch {
                    #If parsing fails, skip config.json rather than risk copying tokens
                }
            }

            #Installed desktop extensions metadata + payloads
            Copy-Item "$claudeDesktopSrc\extensions-installations.json" "$cdDest\" -Force
            Copy-Item "$claudeDesktopSrc\extensions-blocklist.json" "$cdDest\" -Force
            Copy-Item "$claudeDesktopSrc\Claude Extensions" "$cdDest\Claude_Extensions" -Recurse -Force
            Copy-Item "$claudeDesktopSrc\Claude Extensions Settings" "$cdDest\Claude_Extensions_Settings" -Recurse -Force

            #Local agent / cowork session history
            Copy-Item "$claudeDesktopSrc\local-agent-mode-sessions" "$cdDest\local-agent-mode-sessions" -Recurse -Force
            Copy-Item "$claudeDesktopSrc\claude-code-sessions" "$cdDest\claude-code-sessions" -Recurse -Force

            #Application + MCP server logs
            if (Test-Path "$claudeDesktopSrc\logs") {
                Copy-Item "$claudeDesktopSrc\logs" "$cdDest\logs" -Recurse -Force
            }
        }
    }

  }

#==========================================
# Zipping up the output folder
#==========================================

#Zip up the output folder so it is easier to collect off the endpoint
#Uses the .NET zip API instead of Compress-Archive because Compress-Archive writes backslash
#path separators into the archive, which extracts as flat files on Mac/Linux
$zipPath = "${outputDir}.zip"
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($outputDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)

#Delete the unzipped output folder, but only if the zip was created successfully
if (Test-Path $zipPath) {
    Remove-Item $outputDir -Recurse -Force
    Write-Host "Collection complete. Zipped output: $zipPath"
}
else {
    Write-Host "Zipping failed - unzipped output left in: $outputDir"
}

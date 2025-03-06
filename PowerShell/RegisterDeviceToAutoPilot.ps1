#Run this line 1st
#------------------------------------------
Set-ExecutionPolicy Unrestricted
#------------------------------------------

#Run this block 2nd
#-------------------------------------------------------------------------------------------
# Check if AutoPilotScript is installed
$InstalledScripts = Get-InstalledScript
If ($InstalledScripts.name -notcontains "Upload-WindowsAutopilotDeviceInfo") {
    Install-Script -Name Upload-WindowsAutopilotDeviceInfo -force
}

# collect Windows Autopilot info and Upload it to Azure
Upload-WindowsAutopilotDeviceInfo.ps1 -TenantName "peninsulaca.onmicrosoft.com" -Verbose
#-------------------------------------------------------------------------------------------
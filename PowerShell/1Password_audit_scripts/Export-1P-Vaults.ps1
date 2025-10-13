<#
.SYNOPSIS
    Exports all 1Password vaults and their access details to CSV files.
.DESCRIPTION
    Uses the 1Password CLI ('op') to fetch all vaults and who has access to each vault.
    Outputs:
      - vaults.csv: List of all vaults.
      - vault_access.csv: List of all vault access details (who has access to each vault).
.REQUIREMENTS
    - 1Password CLI (op.exe) installed and in PATH.
    - Signed in to 1Password CLI (run 'op signin' first).
#>

$vaultsOutputFile = "./Outputs/vaults.csv"
$accessOutputFile = "./Outputs/vault_access.csv"

# Check for 1Password CLI
if (-not (Get-Command op -ErrorAction SilentlyContinue)) {
    Write-Error "1Password CLI ('op') not found. Please install and add to PATH."
    return
}

# Check sign-in status
try {
    op account list --format json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Not signed in to 1Password CLI." }
} catch {
    Write-Error "Not signed in. Run 'op signin' and try again."
    return
}

# Fetch all vaults
Write-Host "Fetching all vaults..."
$allVaults = op vault list --format json | ConvertFrom-Json -ErrorAction Stop

if ($allVaults -and $allVaults.Count -gt 0) {
    $allVaults | Select-Object id, name, description, type, created_at | Export-Csv -Path $vaultsOutputFile -NoTypeInformation
    Write-Host "Exported $($allVaults.Count) vaults to '$vaultsOutputFile'"
} else {
    Write-Warning "No vaults found."
    return
}

# Fetch vault access details
Write-Host "Fetching vault access details..."
$accessRecords = @()

foreach ($vault in $allVaults) {
    try {
        $vaultUsers = op user list --vault $vault.id --format json | ConvertFrom-Json -ErrorAction Stop
        if ($vaultUsers) {
            foreach ($user in $vaultUsers) {
                $accessRecords += [PSCustomObject]@{
                    VaultId   = $vault.id
                    VaultName = $vault.name
                    MemberType = "User"
                    MemberId    = $user.id
                    MemberName  = $user.name
                    MemberEmail = $user.email
                    MemberState = $user.state
                }
            }
        }
        $vaultGroups = op group list --vault $vault.id --format json | ConvertFrom-Json -ErrorAction Stop
        if ($vaultGroups) {
            foreach ($group in $vaultGroups) {
                $accessRecords += [PSCustomObject]@{
                    VaultId    = $vault.id
                    VaultName  = $vault.name
                    MemberType = "Group"
                    MemberId   = $group.id
                    MemberName = $group.name
                    MemberEmail = $null
                    MemberState = $group.state
                }
            }
        }
    } catch {
        Write-Warning "Could not get members for vault '$($vault.name)'."
    }
}

if ($accessRecords.Count -gt 0) {
    $accessRecords | Export-Csv -Path $accessOutputFile -NoTypeInformation
    Write-Host "Exported $($accessRecords.Count) vault access records to '$accessOutputFile'"
} else {
    Write-Warning "No vault access records found."
}

Write-Host "Done."

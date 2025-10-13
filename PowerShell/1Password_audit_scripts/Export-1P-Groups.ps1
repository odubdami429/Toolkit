<#
.SYNOPSIS
    Extracts all 1Password Groups and Group memberships into two separate CSV files.

.DESCRIPTION
    Uses the 1Password CLI ('op') to fetch all groups and their memberships.
    Outputs:
      - groups.csv: List of all groups.
      - group_memberships.csv: List of all group memberships.

.REQUIREMENTS
    - 1Password CLI (op.exe) installed and in PATH.
    - Signed in to 1Password CLI (run 'op signin' first).
#>

$groupsOutputFile = "./Outputs/groups.csv"
$groupUsersOutputFile = "./Outputs/group_users.csv"

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

# Fetch all groups
Write-Host "Fetching all groups..."
$allGroups = op group list --format json | ConvertFrom-Json -ErrorAction Stop

if ($allGroups -and $allGroups.Count -gt 0) {
    $allGroups | Select-Object id, name, description, state, created_at | Export-Csv -Path $groupsOutputFile -NoTypeInformation
    Write-Host "Exported $($allGroups.Count) groups to '$groupsOutputFile'"
} else {
    Write-Warning "No groups found."
    return
}

# Fetch users in each group using 'op group member list'
Write-Host "Fetching users in each group..."
$groupUserRecords = @()

foreach ($group in $allGroups) {
    try {
        $groupUsers = op group user list "$($group.name)" --format json | ConvertFrom-Json -ErrorAction Stop
        if ($groupUsers) {
            foreach ($user in $groupUsers) {
                $groupUserRecords += [PSCustomObject]@{
                    GroupId   = $group.id
                    GroupName = $group.name
                    UserId    = $user.id
                    UserName  = $user.name
                    UserEmail = $user.email
                    UserState = $user.state
                }
            }
        }
    } catch {
        Write-Warning "Could not get users for group '$($group.name)'."
    }
}

if ($groupUserRecords.Count -gt 0) {
    $groupUserRecords | Export-Csv -Path $groupUsersOutputFile -NoTypeInformation
    Write-Host "Exported $($groupUserRecords.Count) group users to '$groupUsersOutputFile'"
} else {
    Write-Warning "No users found in any group."
}

Write-Host "Done."
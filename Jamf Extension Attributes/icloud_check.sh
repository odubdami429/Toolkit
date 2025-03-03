#!/bin/bash

##################################################
# Jamf Pro Extension Attribute:
# Shows the iCloud account signed in for the
# currently logged-in user (if any).
##################################################

# 1. Get the currently logged-in GUI user
loggedInUser=$(stat -f%Su /dev/console)

# 2. Initialize the iCloud status
iCloudStatus="Disabled"

# 3. Build the plist path
plistFile="/Users/$loggedInUser/Library/Preferences/MobileMeAccounts.plist"

# 4. Only proceed if the user folder and plist exist
if [[ -n "$loggedInUser" && "$loggedInUser" != "root" && -f "$plistFile" ]]; then

    # Read the iCloud info
    iCloudOutput=$(defaults read "$plistFile" Accounts 2> /dev/null)

    # Check for an AccountID key
    if echo "$iCloudOutput" | grep -q "AccountID"; then

        # Extract AccountID
        AccountID=$(echo "$iCloudOutput" \
          | grep "AccountID" \
          | sed -E 's/.*"AccountID" = "([^"]+)".*/\1/')

        # Extract DisplayName
        DisplayName=$(echo "$iCloudOutput" \
          | grep "DisplayName" \
          | sed -E 's/.*"DisplayName" = "([^"]+)".*/\1/')

        # If DisplayName is missing, set a default
        if [[ -z "$DisplayName" ]]; then
          DisplayName="UnknownName"
        fi

        # Combine DisplayName and AccountID (no extra space after comma)
        iCloudStatus="${AccountID}"
    fi
fi

# 5. Echo the final result in Jamf-friendly format
echo "<result>$iCloudStatus</result>"

exit 0

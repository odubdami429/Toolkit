#!/bin/bash

# Identify the currently logged-in user:
loggedInUser=$(stat -f%Su /dev/console)

# Initialize the iCloudStatus variable
iCloudStatus="Disabled"

plistFile="/Users/$loggedInUser/Library/Preferences/MobileMeAccounts.plist"

if [[ -f "$plistFile" ]]; then

    # Read the entire Accounts array from the plist
    iCloudOutput=$(defaults read "$plistFile" Accounts 2> /dev/null)

    # Check if the output actually has an AccountID line
    if echo "$iCloudOutput" | grep -q "AccountID"; then

        # Extract AccountID from the line(s)
        # Typically looks like: "AccountID" = "firstName.lastName@domain.com";
        AccountID=$(echo "$iCloudOutput" \
          | grep "AccountID" \
          | sed -E 's/.*"AccountID" = "([^"]+)".*/\1/')

        # Extract DisplayName if present
        # Typically looks like: "DisplayName" = "Full Name";
        DisplayName=$(echo "$iCloudOutput" \
          | grep "DisplayName" \
          | sed -E 's/.*"DisplayName" = "([^"]+)".*/\1/')

        # If the DisplayName wasn't found for some reason, default to blank
        if [[ -z "$DisplayName" ]]; then
          DisplayName="Unknown Name"
        fi

        # Build the final status string
        iCloudStatus="${DisplayName}, ${AccountID}"
    fi
fi

echo "iCloudStatus: $iCloudStatus"

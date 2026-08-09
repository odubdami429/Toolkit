#!/bin/bash

#======================================================================================
#This script collects various DFIR artifact from a Mac Endpoint by saving the output of various commands to a txt file 
#Once the the script is done the output files will be placed in $outputDir
#======================================================================================

timeZone=Etc/UTC

#Output folder named after the endpoint and the UTC date of collection
outputDir="//tmp/DFIR_Output_$(hostname -s)_$(TZ=$timeZone date +%Y_%m_%d)"

#Creates a folder that will contain all the artifacts
mkdir $outputDir

#Collect information on the system
system_profiler SPSoftwareDataType SPHardwareDataType > $outputDir/system_information.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/system_information.txt
TZ=$timeZone Date >> $outputDir/system_information.txt

#Collect list of Running Processes
ps aux > $outputDir/running_processes.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/running_processes.txt
TZ=$timeZone Date >> $outputDir/running_processes.txt

#Collect list of Active network connections
lsof -i > $outputDir/active_network_connections.txt
echo -e "\n\n\n" >> $outputDir/active_network_connections.txt
netstat -an >> $outputDir/active_network_connections.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/active_network_connections.txt
TZ=$timeZone Date >> $outputDir/active_network_connections.txt

#Collect firewall info
system_profiler SPFirewallDataType > $outputDir/firewall_settings.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/firewall_settings.txt
TZ=$timeZone Date >> $outputDir/firewall_settings.txt

#Collect list of installed Applications
ls -l /Applications > $outputDir/installed_apps.txt
ls -l /usr/local/bin >> $outputDir/installed_apps.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/installed_apps.txt
TZ=$timeZone Date >> $outputDir/installed_apps.txt

#Collect a full application inventory with version, code-signing publisher and
#last-modified date (JSON). The ls listing above only has bundle names; this is
#what fills the Version/Publisher/Date columns in the report.
system_profiler -json SPApplicationsDataType > $outputDir/installed_apps_full.json 2>/dev/null

#Collect Homebrew packages (formulae + casks) if Homebrew is installed.
#Homebrew lives outside /Applications (usually /opt/homebrew), so it is missed by
#the listing above. brew refuses to run as root, so when the script runs under
#sudo we run brew as the owner of the Homebrew prefix instead.
brewBin=""
for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$candidate" ]; then brewBin="$candidate"; break; fi
done
if [ -n "$brewBin" ]; then
    brewOwner=$(stat -f '%Su' "$brewBin")
    brewHome=$(eval echo "~$brewOwner")   # owner's home; brew needs a writable HOME
    #HOME must point at the brew owner's home. Under sudo it defaults to /var/root,
    #which brew cannot write its cache to, so the listing comes back empty.
    if [ "$(id -u)" -eq 0 ] && [ "$brewOwner" != "root" ]; then
        runBrew() { sudo -u "$brewOwner" env HOME="$brewHome" "$brewBin" "$@"; }
    else
        runBrew() { env HOME="$brewHome" "$brewBin" "$@"; }
    fi
    echo "==> Formulae" > $outputDir/homebrew_packages.txt
    runBrew list --formula --versions >> $outputDir/homebrew_packages.txt 2>/dev/null
    echo "==> Casks" >> $outputDir/homebrew_packages.txt
    runBrew list --cask --versions >> $outputDir/homebrew_packages.txt 2>/dev/null
    echo -e "\nDate of Artifact Collection:" >> $outputDir/homebrew_packages.txt
    TZ=$timeZone Date >> $outputDir/homebrew_packages.txt
fi

#Collect Application install history
system_profiler SPInstallHistoryDataType > $outputDir/installed_apps_history.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/installed_apps_history.txt
TZ=$timeZone Date >> $outputDir/installed_apps_history.txt

#Collect list of preferred wireless networks on the mac
networksetup -listpreferredwirelessnetworks en0 > $outputDir/saved_wifi_profiles.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/saved_wifi_profiles.txt
TZ=$timeZone Date >> $outputDir/saved_wifi_profiles.txt

#Collect system install logs
cat //var/log/install.log > $outputDir/system_install_logs.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/system_install_logs.txt
TZ=$timeZone Date >> $outputDir/system_install_logs.txt

#List of all System-level LaunchAgents
ls -l //Library/LaunchAgents > "$outputDir/system_LaunchAgents.txt"
ls -l //System/Library/LaunchAgents >> "$outputDir/system_LaunchAgents.txt"
echo -e "\nDate of Artifact Collection:" >> $outputDir/system_LaunchAgents.txt
TZ=$timeZone Date >> $outputDir/system_LaunchAgents.txt

#List of all System-level LaunchDaemons
ls -l //Library/LaunchDaemons > "$outputDir/system_LaunchDaemons.txt"
ls -l //System/Library/LaunchDaemons >> "$outputDir/system_LaunchDaemons.txt"
echo -e "\nDate of Artifact Collection:" >> $outputDir/system_LaunchDaemons.txt
TZ=$timeZone Date >> $outputDir/system_LaunchDaemons.txt

#List all System-level cron jobs
sudo crontab -l > "$outputDir/system_cron_jobs.txt"
echo -e "\nDate of Artifact Collection:" >> "$outputDir/system_cron_jobs.txt"
TZ=$timeZone Date >> "$outputDir/system_cron_jobs.txt"

#Get Docker information
docker system df > "$outputDir/docker_information.txt"
echo -e "\n--------------------------------------" >> "$outputDir/docker_information.txt"
docker ps -a >> "$outputDir/docker_information.txt"
echo -e "\nDate of Artifact Collection:" >> "$outputDir/docker_information.txt"
TZ=$timeZone Date >> "$outputDir/docker_information.txt"



#Create a folder that will contain all the copied files
mkdir "$outputDir/User_level_files"

listOfUsers=$(ls //Users) #Get list of users into a variable

#Collect mac login history
last > $outputDir/mac_login_history.txt
echo -e "\nDate of Artifact Collection:" >> $outputDir/mac_login_history.txt
TZ=$timeZone Date >> $outputDir/mac_login_history.txt


#Get list of users into an array
listOfUsersArray=()
while IFS= read -r line; do
  listOfUsersArray+=("$line")
done < <(ls -1 //Users)

#For loop to iterate through the array and create a directory for each item found
for user in "${listOfUsersArray[@]}"; do 

    echo ""$user" user account found";
    mkdir "$outputDir/User_level_files/"$user"_files" 


    #List all user-level cron jobs
    sudo crontab -l -u $user > "$outputDir/User_level_files/"$user"_files/"$user"_cron_jobs.txt"
    echo -e "\nDate of Artifact Collection:" >> "$outputDir/User_level_files/"$user"_files/"$user"_cron_jobs.txt"
    TZ=$timeZone Date >> "$outputDir/User_level_files/"$user"_files/"$user"_cron_jobs.txt"

    #List all files in the Documents folder
    ls -l -R "//Users/"$user"/Documents" > "$outputDir/User_level_files/"$user"_files/"$user"_Documents_files.txt"
    echo -e "\nDate of Artifact Collection:" >> "$outputDir/User_level_files/"$user"_files/"$user"_Documents_files.txt"
    TZ=$timeZone Date >> "$outputDir/User_level_files/"$user"_files/"$user"_Documents_files.txt"

    #List all files in the Downloads folder
    ls -l -R "//Users/"$user"/Downloads" > "$outputDir/User_level_files/"$user"_files/"$user"_Downloads_files.txt"
    echo -e "\nDate of Artifact Collection:" >> "$outputDir/User_level_files/"$user"_files/"$user"_Downloads_files.txt"
    TZ=$timeZone Date >> "$outputDir/User_level_files/"$user"_files/"$user"_Downloads_files.txt"

    #List all files in the User folder
    ls -l -R "//Users/"$user"" > "$outputDir/User_level_files/"$user"_files/"$user"_All_files.txt"
    echo -e "\nDate of Artifact Collection:" >> "$outputDir/User_level_files/"$user"_files/"$user"_All_files.txt"
    TZ=$timeZone Date >> "$outputDir/User_level_files/"$user"_files/"$user"_All_files.txt"

    #List of all User-level LaunchAgents
    ls -l "//Users/"$user"/Library/LaunchAgents" > "$outputDir/User_level_files/"$user"_files/"$user"_LaunchAgents.txt"

    #Copy over ZSH history files
    cp "//Users/"$user"/.zsh_history" "$outputDir/User_level_files/"$user"_files/"$user"_zsh_history.txt" #copy over the zsh history file
    echo -e "\nDate of Artifact Collection:" >> "$outputDir/User_level_files/"$user"_files/"$user"_zsh_history.txt"
    TZ=$timeZone Date >> "$outputDir/User_level_files/"$user"_files/"$user"_zsh_history.txt"
    #Copy over Bash history files
    cp "//Users/"$user"/.bash_history" "$outputDir/User_level_files/"$user"_files/"$user"_bash_history.txt" #copy over the bash history file
    echo -e "\nDate of Artifact Collection:" >> "$outputDir/User_level_files/"$user"_files/"$user"_bash_history.txt"
    TZ=$timeZone Date >> "$outputDir/User_level_files/"$user"_files/"$user"_bash_history.txt"


    #Copy over Chrome history files
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Default/History" "$outputDir/User_level_files/"$user"_files/"$user"_default_chrome_history_file.db" 


  
    #profileNumber=0 Variable for number of profiles to looks for

    for ((profileNumber=0; profileNumber<100; profileNumber++))
    do
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Profile "$profileNumber"/History" "$outputDir/User_level_files/"$user"_files/"$user"_profile_"$profileNumber"_chrome_history_file.db" 
    done

    #Copy over Safari history files
    cp "//Users/"$user"/Library/Safari/History.db" "$outputDir/User_level_files/"$user"_files/"$user"_safari_history_file.db"

    #Copy over the global .claude folder (Claude Code config, session history, etc.)
    #The claude_folders directory is only created if the user actually has .claude folders
    claudeDest="$outputDir/User_level_files/"$user"_files/"$user"_claude_folders"
    if [ -d "//Users/"$user"/.claude" ]; then
        mkdir -p "$claudeDest"
        cp -R "//Users/"$user"/.claude" "$claudeDest/global_claude"
    fi

    #Find and copy over any project-level .claude folders in the user's home folder
    while IFS= read -r claudeDir; do
        projectName=$(echo "$claudeDir" | sed "s|^//Users/$user/||; s|/\.claude$||; s|/|_|g")
        mkdir -p "$claudeDest"
        cp -R "$claudeDir" "$claudeDest/project_"$projectName"_claude"
    done < <(find "//Users/$user" -maxdepth 6 -type d -name ".claude" -not -path "//Users/$user/.claude" -not -path "*/Library/*" -not -path "*/node_modules/*" -not -path "*/.Trash/*" 2>/dev/null)

    #Copy over Claude Desktop artifacts (config, extensions, logs, local-agent sessions).
    #Credential material (Cookies, buddy-tokens.json, Local State) is deliberately NOT
    #collected; oauth/token/secret values inside config.json are redacted on the way out.
    claudeDesktopSrc="//Users/"$user"/Library/Application Support/Claude"
    if [ -d "$claudeDesktopSrc" ]; then
        cdDest="$outputDir/User_level_files/"$user"_files/"$user"_claude_desktop"
        mkdir -p "$cdDest"

        #MCP server config (no secrets) - copied as-is
        cp "$claudeDesktopSrc/claude_desktop_config.json" "$cdDest/claude_desktop_config.json" 2>/dev/null

        #App preferences - copied, then any oauth/token/secret value redacted in place.
        #The regex is key-name driven so it redacts at any nesting depth, preserving
        #non-secret fields (account UUID, timestamps, version, settings).
        if [ -f "$claudeDesktopSrc/config.json" ]; then
            cp "$claudeDesktopSrc/config.json" "$cdDest/config.json"
            perl -0777 -i -pe 's/("[^"]*(?:token|secret|api[_-]?key|apikey|cookie|password|passwd|bearer|credential|oauth|refresh|session)[^"]*"\s*:\s*)"[^"]*"/$1"<REDACTED>"/ig' "$cdDest/config.json" 2>/dev/null
        fi

        #Installed desktop extensions (DXT) metadata + payloads
        cp "$claudeDesktopSrc/extensions-installations.json" "$cdDest/" 2>/dev/null
        cp "$claudeDesktopSrc/extensions-blocklist.json" "$cdDest/" 2>/dev/null
        cp -R "$claudeDesktopSrc/Claude Extensions" "$cdDest/Claude_Extensions" 2>/dev/null
        cp -R "$claudeDesktopSrc/Claude Extensions Settings" "$cdDest/Claude_Extensions_Settings" 2>/dev/null

        #Local agent / cowork session history
        cp -R "$claudeDesktopSrc/local-agent-mode-sessions" "$cdDest/local-agent-mode-sessions" 2>/dev/null
        cp -R "$claudeDesktopSrc/claude-code-sessions" "$cdDest/claude-code-sessions" 2>/dev/null

        #Application + MCP server logs
        if [ -d "//Users/"$user"/Library/Logs/Claude" ]; then
            mkdir -p "$cdDest/logs"
            cp -R "//Users/"$user"/Library/Logs/Claude/" "$cdDest/logs/" 2>/dev/null
        fi
    fi

done

#Zip up the output folder so it is easier to collect off the endpoint
cd //tmp
zip -r -q "${outputDir}.zip" "$(basename $outputDir)"

#Delete the unzipped output folder, but only if the zip was created successfully
if [ -s "${outputDir}.zip" ]; then
    rm -rf "$outputDir"
    echo "Collection complete. Zipped output: ${outputDir}.zip"
else
    echo "Zipping failed - unzipped output left in: ${outputDir}"
fi
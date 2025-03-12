#!/bin/bash

#======================================================================================
#This script collects various DFIR artifact from a Windows Endpoint by saving the output of various commands to a txt file 
#Once the the script is done the output files will be placed in //tmp/DFIR_Output
#======================================================================================

timeZone=America/New_York

#Creates a folder that will contain all the artifacts
mkdir //tmp/DFIR_Output

#Collect information on the system
system_profiler SPSoftwareDataType SPHardwareDataType > //tmp/DFIR_Output/system_information.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/system_information.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/system_information.txt

#Collect list of Running Processes
ps aux > //tmp/DFIR_Output/running_processes.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/running_processes.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/running_processes.txt

#Collect list of Active network connections
lsof -i > //tmp/DFIR_Output/active_network_connections.txt
echo -e "\n\n\n" >> //tmp/DFIR_Output/active_network_connections.txt
netstat -an >> //tmp/DFIR_Output/active_network_connections.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/active_network_connections.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/active_network_connections.txt

#Collect firewall info
system_profiler SPFirewallDataType > //tmp/DFIR_Output/firewall_settings.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/firewall_settings.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/firewall_settings.txt

#Collect list of installed Applications
ls -l /Applications > //tmp/DFIR_Output/installed_apps.txt
ls -l /usr/local/bin >> //tmp/DFIR_Output/installed_apps.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/installed_apps.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/installed_apps.txt

#Collect Application install history
system_profiler SPInstallHistoryDataType > //tmp/DFIR_Output/installed_apps_history.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/installed_apps_history.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/installed_apps_history.txt

#Collect list of preferred wireless networks on the mac
networksetup -listpreferredwirelessnetworks en0 > //tmp/DFIR_Output/saved_wifi_profiles.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/saved_wifi_profiles.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/saved_wifi_profiles.txt

#Collect system install logs
cat //var/log/install.log > //tmp/DFIR_Output/system_install_logs.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/system_install_logs.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/system_install_logs.txt

#List of all System-level LaunchAgents
ls -l //Library/LaunchAgents > "//tmp/DFIR_Output/system_LaunchAgents.txt"
ls -l //System/Library/LaunchAgents >> "//tmp/DFIR_Output/system_LaunchAgents.txt"
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/system_LaunchAgents.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/system_LaunchAgents.txt

#List of all System-level LaunchDaemons
ls -l //Library/LaunchDaemons > "//tmp/DFIR_Output/system_LaunchDaemons.txt"
ls -l //System/Library/LaunchDaemons >> "//tmp/DFIR_Output/system_LaunchDaemons.txt"
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/system_LaunchDaemons.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/system_LaunchDaemons.txt

#List all System-level cron jobs
sudo crontab -l > "//tmp/DFIR_Output/system_cron_jobs.txt"
echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/system_cron_jobs.txt"
TZ=$timeZone Date >> "//tmp/DFIR_Output/system_cron_jobs.txt"

#Get Docker information
docker system df > "//tmp/DFIR_Output/docker_information.txt"
echo -e "\n--------------------------------------" >> "//tmp/DFIR_Output/docker_information.txt"
docker ps -a >> "//tmp/DFIR_Output/docker_information.txt"
echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/docker_information.txt"
TZ=$timeZone Date >> "//tmp/DFIR_Output/docker_information.txt"



#Create a folder that will contain all the copied files
mkdir "//tmp/DFIR_Output/User_level_files"

listOfUsers=$(ls //Users) #Get list of users into a variable

#Collect mac login history
last > //tmp/DFIR_Output/mac_login_history.txt
echo -e "\nDate of Artifact Collection:" >> //tmp/DFIR_Output/mac_login_history.txt
TZ=$timeZone Date >> //tmp/DFIR_Output/mac_login_history.txt


#Get list of users into an array
listOfUsersArray=()
while IFS= read -r line; do
  listOfUsersArray+=("$line")
done < <(ls -1 //Users)

#For loop to iterate through the array and create a directory for each item found
for user in "${listOfUsersArray[@]}"; do 

    echo ""$user" user account found";
    mkdir "//tmp/DFIR_Output/User_level_files/"$user"_files" 


    #List all user-level cron jobs
    sudo crontab -l -u $user > "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_cron_jobs.txt"
    echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_cron_jobs.txt"
    TZ=$timeZone Date >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_cron_jobs.txt"

    #List all files in the Documents folder
    ls -l -R "//Users/"$user"/Documents" > "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_Documents_files.txt"
    echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_Documents_files.txt"
    TZ=$timeZone Date >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_Documents_files.txt"

    #List all files in the Downloads folder
    ls -l -R "//Users/"$user"/Downloads" > "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_Downloads_files.txt"
    echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_Downloads_files.txt"
    TZ=$timeZone Date >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_Downloads_files.txt"

    #List of all User-level LaunchAgents
    ls -l "//Users/"$user"/Library/LaunchAgents" > "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_LaunchAgents.txt"

    #Copy over ZSH history files
    cp "//Users/"$user"/.zsh_history" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_zsh_history.txt" #copy over the zsh history file
    echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_zsh_history.txt"
    TZ=$timeZone Date >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_zsh_history.txt"
    #Copy over Bash history files
    cp "//Users/"$user"/.bash_history" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_bash_history.txt" #copy over the bash history file
    echo -e "\nDate of Artifact Collection:" >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_bash_history.txt"
    TZ=$timeZone Date >> "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_bash_history.txt"

    #Copy over Chrome history files
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Default/History" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_default_chrome_history_file" 
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Profile 1/History" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_profile_1_chrome_history_file" 
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Profile 2/History" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_profile_2_chrome_history_file"
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Profile 3/History" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_profile_3_chrome_history_file" 
    cp "//Users/"$user"/Library/Application Support/Google/Chrome/Profile 4/History" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_profile_4_chrome_history_file"

    #Copy over Safari history files
    cp "//Users/"$user"/Library/Safari/History.db" "//tmp/DFIR_Output/User_level_files/"$user"_files/"$user"_safari_history_file.db"

    

done
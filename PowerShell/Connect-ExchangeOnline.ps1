#Install PowerShellGet Module. To install the ExchangeOnlineManagement module, you need PowerShellGet 2.0 or later version
Install-Module PowerShellGet -Force

#Run below cmdlet to install Exchange Online PowerShell V2 Module
Install-Module –Name ExchangeOnlineManagement

#Run below cmdlet to connect Exchange Online PowerShell with/without MFA 
Connect-ExchangeOnline
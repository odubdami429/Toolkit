#$header = ‘Username’, 'First name', 'Last name', 'Display name', 'Job title', 'Department', 'Office number', 'Mobile phone', 'Fax', 'Alternate email address', 'Address', 'City', 'State or province', 'Country or region'

function create-user{

$UserName
$FirstName = Read-Host -Prompt 'Enter First Name'
$LastName = Read-Host -Prompt 'Enter Last Name'
$DisplayName = $FirstName + " " + $LastName
$JobTitle = Read-Host -Prompt 'Enter Job Title'
$Department = Read-Host -Prompt 'Enter Department'
$ProvinceInput = Read-Host -Prompt 'Enter Province (ON or BC)'
$Province
$City
$Address
$PostalCode

if($Department -eq "BrightHR") {

   $UserName = $FirstName + "." + $LastName + "@******.ca"
}else {

   $UserName = $FirstName + "." + $LastName + "@*******.com"
}

if($ProvinceInput -eq "ON") {

   $Province = "Placeholder"
   $City = "Placeholder"
   $Address = "123 Placeholder"
   $PostalCode = "123 456"

}elseif ($ProvinceInput -eq "BC") {

   $Province = "Placeholder"
   $City = "Placeholder"
   $Address = "123 Placeholder"
   $PostalCode = "123 456"
}

$User = [PSCustomObject]@{
    UserName = $UserName
    FirstName = $FirstName
    LastName = $LastName
    DisplayName = $DisplayName
    JobTitle = $JobTitle
    Department = $Department
    OfficeNumber = ""
    OfficePhone = ""
    MobliePhone = ""
    FaxNumber = ""
    AlternateEmailAddress = ""
    Address = $Address
    City = $City
    Province = $Province
    PostalCode = $PostalCode
    Country = "Canada"
}


$User | Export-Csv -NoTypeInformation -Append -Path "C:\UserAccounts.csv"
Write-Output "User added to file" 

}



function change-header {

$tempCSV = Import-Csv C:\UserAccounts.csv -Header "Username", "First name", "Last name", "Display name", "Job title", "Department", "Office number", "Office phone", "Mobile phone", "Fax", "Alternate email address", "Address", "City", "State or province", "ZIP or postal code", "Country or region" | select -skip 1
$tempCSV | Export-Csv -NoTypeInformation -Path "C:\UserAccounts.csv"


#Get-Content C:\UserAccounts.csv -Encoding Default | 
#Select-Object -Skip 1 |
#ConvertFrom-CSV -UseCulture -Header $header


}

#create-user
change-header
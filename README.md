# Perfect-Ldap

## Retrieve the machine account quota for the domain
### Method 1. Using LDAP:
```powershell
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
$ldapPath = "LDAP://$domain"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]$ldapPath
$searcher.Filter = "(objectClass=domainDNS)"
$searcher.PropertiesToLoad.Add("ms-DS-MachineAccountQuota") | Out-Null
$result = $searcher.FindOne()
$quota = $result.Properties["ms-DS-MachineAccountQuota"]
Write-Output "Machine Account Quota: $quota"
```

## Check if LLMNR (Link-Local Multicast Name Resolution) is disabled or not
### Method 1. Using LDAP:
```powershell
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
$ldapPath = "LDAP://CN=Policies,CN=System,DC=$($domain -replace '\.', ',DC=')"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]$ldapPath
$searcher.Filter = "(cn=*)"
$searcher.PropertiesToLoad.Add("gPCUserExtensionNames") | Out-Null
$searcher.PropertiesToLoad.Add("gPCMachineExtensionNames") | Out-Null
$result = $searcher.FindAll()

# Flag to track if the LLMNR policy is found
$llmnrPolicyFound = $false

foreach ($policy in $result) {
    if ($policy.Properties["gPCUserExtensionNames"] -match "EnableMulticast" -or $policy.Properties["gPCMachineExtensionNames"] -match "EnableMulticast") {
        Write-Output "LLMNR policy is configured in Group Policy."
        $llmnrPolicyFound = $true
    }
}

# If the LLMNR policy was not found, output a message
if (-not $llmnrPolicyFound) {
    Write-Output "LLMNR policy is not configured in Group Policy."
}
```
### Method 2. Check LLMNR Status via Local Group Policy:
```powershell
$llmnrStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue

if ($llmnrStatus -eq $null) {
    Write-Output "LLMNR policy not configured (enabled by default)."
} elseif ($llmnrStatus.EnableMulticast -eq 0) {
    Write-Output "LLMNR is disabled via Group Policy."
} else {
    Write-Output "LLMNR is enabled."
}
```
### Method 3. Check from registry :
```powershell
$(Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast).EnableMulticast
```
### Method 4. Using gpresult to Check Applied Policies:
```cmd
gpresult /h C:\temp\gpo_report.html
```
Open the generated gpo_report.html and search for "EnableMulticast" under "Applied GPOs."
If found and set to 0, LLMNR is disabled.

## Check Certificate Authority (CA) server is installed or not
### Method 1. Using LDAP:
```powershell
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
$configDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$ldapPath = "LDAP://CN=Certification Authorities,CN=Public Key Services,CN=Services,$configDN"

$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]$ldapPath
$searcher.Filter = "(objectClass=pKIEnrollmentService)"
$searcher.PropertiesToLoad.Add("cn") | Out-Null

$result = $searcher.FindAll()

if ($result.Count -gt 0) {
    Write-Output "Certificate Authority (CA) server is installed in the domain."
    foreach ($ca in $result) {
        Write-Output "CA Name: $($ca.Properties['cn'])"
    }
} else {
    Write-Output "No Certificate Authority (CA) server found in the domain."
}
```
### Method 2. Using certutil:
```
certutil -config - -ping
```
### Method 3. Search for published certificates in Active Directory:
```powershell
$ldapPath = "LDAP://CN=AIA,CN=Public Key Services,CN=Services,$configDN"
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]$ldapPath
$searcher.Filter = "(objectClass=certificationAuthority)"
$searcher.PropertiesToLoad.Add("cn") | Out-Null

$result = $searcher.FindAll()
if ($result.Count -gt 0) {
    Write-Output "A CA certificate is published in Active Directory."
} else {
    Write-Output "No CA certificates found in AD."
}
```

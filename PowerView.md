1- Enumerate computers
```powershell
Get-DomainComputer
```

2- Enumerate a user property like logoncount, badpasswordtime and ...
```powershell
Get-DomainUser -Identity username
```

3- Find Groups for a Specific User
```powershell  
Get-DomainGroup -MemberIdentity username
Get-DomainGroup -MemberIdentity username | select samaccountname
```

4- Enumerate domain admin and enterprise admin accounts:
```powershell
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" | select MemberName
Get-DomainGroupMember -Identity "Enterprise Admins"
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins" -Server lab.local # if there is a child DC and we are in that.
```

4- Enumerate domain OUs:
```powershell
Get-DomainOU
Get-DomainOU | ? { $_.ou -like "*laps*" } # Enumerate OU's that have "LAPS" in the name
```

5- Return all Group Policy Objects:
```powershell
Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl # Enumerate domain GPOs that have "LAPS" in the name

Get-DomainGPO | ? { $_.DisplayName -like "*password solution*" } | select DisplayName, Name, GPCFileSysPath | fl # Enumerate domain GPOs that have "LAPS" in the name
```
5.1- Enumerate all GPOs that are applied to a particular machine
```powershell
Get-DomainGPO -ComputerIdentity pc1 -Properties DisplayName | sort -Property DisplayName
```

6- Enumerate Computers in OU
```powershell
Get-DomainOU | Select-Object Name, DistinguishedName # find domain OUs
Get-DomainGPO | Select-Object gplink # find domain GPOs
$ouDN = (Get-DomainOU -Identity "Domain Controllers").DistinguishedName
Write-host $ouDN
Get-DomainComputer -SearchBase $ouDN | Select-Object Name, OperatingSystem, IPv4Address
```
5- Enumerate 

6- Enumerate local admins on a computer
```powershell
Get-DomainComputer | Select-Object dnshostname
Get-NetLocalGroupMember -Computer DESKTOP-S95DUHA -GroupName Administrators
```

7- Enumerate ACLs in domain
```powershell
Get-DomainObjectACl # find all ACLs
Find-InterestingDomainAcl # find interesting ACLs and convert SID to distinguished name automatic
Get-DomainObjectACl -identity "Domain Admins" # find ACLs for "Domain Admins" object
Convert-SidToName -SID S-1-5-21-154859305-3651822756-1843101964-512 # Convert SID to name
```

8- Check for the specific object attribute and properties
```powershell
Get-ADObject 'CN=aryan,CN=Users,DC=lab,DC=local'
```

9- Discovering LAPS with check for the LAPS password attribute ms-mcs-admpwd in Active Directory
```powershell
Get-ADObject 'CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=lab,DC=local'
```

10- Discovering LAPS with check for the LAPS password attribute ms-mcs-admpwd in specific computer
```powershell
Get-DomainComputer DESKTOP-S95DUHA -Properties ms-mcs-AdmPwd,ComputerName,ms-mcs-AdmPwdExpirationTime
```

11- get all users with passwords changed > 1 year ago, returning sam account names and password last set times
```powershell
$Date = (Get-Date).AddYears(-1).ToFileTime()
Get-DomainUser -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset
```

12- all enabled users, returning distinguishednames
```powershell
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
```

13- all disabled users
```powershell
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)" | select name
Get-DomainUser -UACFilter ACCOUNTDISABLE | select name
```

14- find all users with an SPN set (likely service accounts)
```powershell
Get-DomainUser -SPN
```

15- find all service accounts in "Domain Admins"
```powershell
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}
```

16- return the local groups of a remote server
```powershell
Get-NetLocalGroup SERVER.domain.local
```

17- Finds domain machines where specific users are logged into.

18- Finds domain machines where those users are logged in (default domain admin)
```powershell
Find-DomainUserLocation
Find-DomainUserLocation -ComputerName DESKTOP-S95DUHA
Find-DomainUserLocation | select UserName, SessionFromName
```

19- Find SMB shares in a domain and -CheckShareAccess will only display those that the executing principal has access to.
```powershell
Find-DomainShare -CheckShareAccess
```

20- Finds all LAPS-enabled machines
```powershell
Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)'
Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)' | select cn
```

21- Enumerates all users/groups who can view LAPS password on specified LAPSCLIENT.test.local machine
```powershell
Get-DomainComputer LAPSCLIENT.test.local | 
	Select-Object -ExpandProperty distinguishedname | 
	ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object { 
		Get-DomainObjectAcl -ResolveGUIDs $_.ObjectDN 
	} | Where-Object { 
		($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and 
		($_.ActiveDirectoryRights -match 'ReadProperty')
	} | Select-Object -ExpandProperty SecurityIdentifier | Get-DomainObject | select samaccountname
```
22- Enumerate Principals that can read the 'ms-Mcs-AdmPwd' (Same as 21)
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_ } | select IdentityName
```

23- Read instances of ms-mcs-admpwd where it is not empty
```powershell
Get-DomainComputer | Select-Object 'dnshostname','ms-mcs-admpwd' | Where-Object {$_."ms-mcs-admpwd" -ne $null}

([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { Write-Host "" ; $_.properties.cn ; $_.properties.'ms-mcs-admpwd'}   # native method
```

24- Retrieves Group Policy Objects (GPOs) that add users or groups to the local Administrators group on domain-joined computers.
```powershell
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName
```

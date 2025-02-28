### Active Directory Enumeration from Non-Joined Domain Workstation
- Add Domain DNS server for Non-Joined Workstation setting.
- Run Following commands:
```cmd
runas /netonly /user:lab.local\user 'powershell -ep bypass'

Import-Module PowerView.ps1

Get-NetDomain
```

### Enumerate current user's domain
```powershell
Get-NetDomain
```

### Enumerate DC computers
```powershell
Get-DomainController
```

### Enumerate computers
```powershell
Get-DomainComputer
```

### Enumerate a user property like logoncount, badpasswordtime and ...
```powershell
Get-DomainUser -Identity username
```

### Find Groups for a Specific User
```powershell  
Get-DomainGroup -MemberIdentity username
Get-DomainGroup -MemberIdentity username | select samaccountname
```

### Enumerate domain admin and enterprise admin accounts:
```powershell
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" | select MemberName
Get-DomainGroupMember -Identity "Enterprise Admins"
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins" -Server lab.local # if there is a child DC and we are in that.
```

### Enumerate domain OUs:
```powershell
Get-DomainOU
Get-DomainOU | ? { $_.ou -like "*laps*" } # Enumerate OU's that have "LAPS" in the name
```

### Return all Group Policy Objects:
```powershell
Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl # Enumerate domain GPOs that have "LAPS" in the name

Get-DomainGPO | ? { $_.DisplayName -like "*password solution*" } | select DisplayName, Name, GPCFileSysPath | fl # Enumerate domain GPOs that have "LAPS" in the name
```
### Enumerate all GPOs that are applied to a particular machine
```powershell
Get-DomainGPO -ComputerIdentity pc1 -Properties DisplayName | sort -Property DisplayName
```

### Enumerate Computers in OU
```powershell
Get-DomainOU | Select-Object Name, DistinguishedName # find domain OUs
Get-DomainGPO | Select-Object gplink # find domain GPOs
$ouDN = (Get-DomainOU -Identity "Domain Controllers").DistinguishedName
Write-host $ouDN
Get-DomainComputer -SearchBase $ouDN | Select-Object Name, OperatingSystem, IPv4Address
```
### Enumerate local admins on a computer
```powershell
Get-DomainComputer | Select-Object dnshostname
Get-NetLocalGroupMember -Computer DESKTOP-S95DUHA -GroupName Administrators
```

### Enumerate ACLs in domain
```powershell
Get-DomainObjectACl # find all ACLs
Find-InterestingDomainAcl # find interesting ACLs and convert SID to distinguished name automatic
Get-DomainObjectACl -identity "Domain Admins" # find ACLs for "Domain Admins" object
Convert-SidToName -SID S-1-5-21-154859305-3651822756-1843101964-512 # Convert SID to name
```
### Enumerate ACLs for specific object ("Domain Admins" and "Enterprise Admins")
```powershell
Get-DomainObjectAcl -identity "Domain Admins","Enterprise Admins" | ForEach-Object {
    $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier) -Force
    $_ | Add-Member NoteProperty 'SIDName' $(if ($_.ObjectSID) { Convert-SidToName $_.ObjectSID } else { "NULL" }) -Force
    $_
} | select IdentityName,ActiveDirectoryRights,SIDName -unique
```
- This is how we read below output: `Authenticated Users` have `GenericRead` permission on `LAB\Domain Admins`.
```
IdentityName                       ActiveDirectoryRights SIDName
------------                       --------------------- -------
Authenticated Users                GenericRead 		LAB\Domain Admins
```


### Find ACLs where a user named Bob has GenericAll, GenericRead, GenericWrite, WriteOwner or WriteDacl permissions
- Method1: (Duplicate)
```powershell
Get-DomainObjectAcl -ResolveGUIDs | ForEach-Object {
    # Always add IdentityName (converted from SecurityIdentifier)
    $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_
    
    # Add ObjectName (converted from ObjectSID) only if ObjectSID is not null
    if ($_.ObjectSID -ne $null) {
        try {
            $ObjectName = Convert-SidToName $_.ObjectSID -Force
        } catch {
            $ObjectName = "Unknown"
        }
        $_ | Add-Member NoteProperty 'ObjectName' $ObjectName; $_
    } else {
        # If ObjectSID is null, set ObjectName to "N/A" or similar
        $_ | Add-Member NoteProperty 'ObjectName' "N/A"; $_
    }
} | Where-Object {
    $_.IdentityName -match 'bob' -and (
        $_.ActiveDirectoryRights -match 'GenericAll' -or
        $_.ActiveDirectoryRights -match 'GenericRead' -or
        $_.ActiveDirectoryRights -match 'GenericWrite' -or
        $_.ActiveDirectoryRights -match 'WriteOwner' -or
        $_.ActiveDirectoryRights -match 'WriteDacl'
    )
} | Select-Object SecurityIdentifier, IdentityName, ActiveDirectoryRights, ObjectName, ObjectSID
```
- Method2: (Remove Duplicate)
```powershell
Get-DomainObjectAcl -ResolveGUIDs | ForEach-Object {
    $_ | Add-Member -Force NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier)
    $ObjectName = "N/A"  
    if ($_.ObjectSID -ne $null -and $_.ObjectSID -ne "") {
        try {
            $ResolvedName = Convert-SidToName -SID $_.ObjectSID -ErrorAction Stop
            if ($ResolvedName) {
                $ObjectName = $ResolvedName
            } else {
                $ObjectName = "Unknown"
            }
        } catch {
            $ObjectName = "Unknown"
        }
    }
    $_ | Add-Member -Force NoteProperty 'ObjectName' $ObjectName
    $_  
} | Where-Object {
    $_.IdentityName -match 'bob' -and (
        $_.ActiveDirectoryRights -match 'GenericAll' -or
        $_.ActiveDirectoryRights -match 'GenericRead' -or
        $_.ActiveDirectoryRights -match 'GenericWrite' -or
        $_.ActiveDirectoryRights -match 'WriteOwner' -or
        $_.ActiveDirectoryRights -match 'WriteDacl'
    )
} | Select-Object SecurityIdentifier, IdentityName, ActiveDirectoryRights, ObjectName, ObjectSID
```



- This is how we read below output: `LAB\bob` have `ExtendedRight, GenericRead` permission on `S-1-5-21-154859305-3651822756-1843101964-1157` SID with `Unknown` name.
```
SecurityIdentifier    : S-1-5-21-154859305-3651822756-1843101964-1107
IdentityName          : LAB\bob
ActiveDirectoryRights : ExtendedRight, GenericRead
ObjectName            : Unknown
ObjectSID             : S-1-5-21-154859305-3651822756-1843101964-1157
```

### Check for the specific object attribute and properties
```powershell
Get-ADObject 'CN=aryan,CN=Users,DC=lab,DC=local'
```

### Discovering LAPS with check for the LAPS password attribute ms-mcs-admpwd in Active Directory
```powershell
Get-ADObject 'CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=lab,DC=local'
```

### Discovering LAPS with check for the LAPS password attribute ms-mcs-admpwd in specific computer
```powershell
Get-DomainComputer DESKTOP-S95DUHA -Properties ms-mcs-AdmPwd,ComputerName,ms-mcs-AdmPwdExpirationTime
```

### Get all users with passwords changed > 1 year ago, returning sam account names and password last set times
```powershell
$Date = (Get-Date).AddYears(-1).ToFileTime()
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset
```

### All enabled users
```powershell
Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties samaccountname
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties samaccountname
```

### All disabled users
```powershell
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2)" | select name
Get-DomainUser -UACFilter ACCOUNTDISABLE | select name
```

### Find all users with an SPN set (likely service accounts)
```powershell
Get-DomainUser -SPN
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
Get-DomainComputer | select samaccountname,serviceprincipalname
```

### Find all service accounts in "Domain Admins"
```powershell
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}
```

### Return the local groups of a remote server
```powershell
Get-NetLocalGroup SERVER.domain.local
```

### Finds domain machines where specific users are logged into.

### Finds domain machines where those users are logged in (default domain admin)
```powershell
Find-DomainUserLocation
Find-DomainUserLocation -ComputerName DESKTOP-S95DUHA
Find-DomainUserLocation | select UserName, SessionFromName
```

### Find SMB shares in a domain and -CheckShareAccess will only display those that the executing principal has access to.
```powershell
Find-DomainShare -CheckShareAccess
```

### Finds all LAPS-enabled machines
```powershell
Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)'
Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)' | select samaccountname
```

### Enumerates all users/groups who can view LAPS password on specified LAPSCLIENT.test.local machine
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
### Enumerate Principals that can read the 'ms-Mcs-AdmPwd' (Same as 21)
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_ } | select IdentityName
```

### Read instances of ms-mcs-admpwd where it is not empty
```powershell
Get-DomainComputer | Select-Object 'dnshostname','ms-mcs-admpwd' | Where-Object {$_."ms-mcs-admpwd" -ne $null}

([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { Write-Host "" ; $_.properties.cn ; $_.properties.'ms-mcs-admpwd'}   # native method
```

### Retrieves Group Policy Objects (GPOs) that add users or groups to the local Administrators group on domain-joined computers.
```powershell
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName
```

### Identify the LAPS Account Username
```powershell
Get-DomainGPO -ComputerIdentity pc1 -Properties DisplayName | sort -Property DisplayName
```

### Identifying computers that are configured for Unconstrained Delegation
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description

Get-ADComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```
### Identifying users that are configured for Unconstrained Delegation
```powershell
Get-DomainUser | Where-Object { ($_."userAccountControl" -band 0x80000) -ne 0 } | select samaccountname,serviceprincipalname

Get-DomainUser -ldapfilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```

### Find roastable accounts (AS-REP Roasting Attack)
```powershell
Get-DomainUser -PreauthNotRequired -Properties samaccountname,memberof
```

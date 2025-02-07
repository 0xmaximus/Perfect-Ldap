1- Enumerate computers
```powershell
Get-DomainComputer
```
2- Enumerate domain admin and enterprise admin:
```powershell
Get-DomainGroup
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Enterprise Admins"
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins" -Server lab.local # if there is a child DC and we are in that.
```
3- Enumerate domain OUs:
```powershell
Get-DomainOU
```

4- Enumerate Computers in OU
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

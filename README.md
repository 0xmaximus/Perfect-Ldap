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
### Method 1. Check LLMNR Status via Local Group Policy:
```powershell
$(Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast).EnableMulticast
```
We can confirm that we have disabled LLMNR by running the above command in PowerShell and receiving a ‘0’ in return.
### Method 2. Alternative Method
```powershell
$llmnrStatus = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
if ($llmnrStatus -eq $null) {
    Write-Output "LLMNR policy not configured (enabled by default)."
} elseif ($llmnrStatus.EnableMulticast -eq 0) {
    Write-Output "LLMNR is disabled via Group Policy."
} else {
    Write-Output "LLMNR is enabled."
}
```
### Method 3. Using gpresult to Check Applied Policies:
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
## connection security rules are configured or not
### Method 1. Using PowerShell
```powershell
Get-NetIPsecRule -PolicyStore ActiveStore | Format-Table -Property DisplayName, Enabled, Action, Profile
```
### Method 2. Using netsh
```powershell
netsh advfirewall consec show rule name=all
```
```
# deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted

# deb http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted
# deb http://security.ubuntu.com/ubuntu bionic-security main restricted

# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://us.archive.ubuntu.com/ubuntu/ bionic main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic main restricted

## Major bug fix updates produced after the final release of the
## distribution.
deb http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic-updates main restricted

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu
## team. Also, please note that software in universe WILL NOT receive any
## review or updates from the Ubuntu security team.
deb http://us.archive.ubuntu.com/ubuntu/ bionic universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic universe
deb http://us.archive.ubuntu.com/ubuntu/ bionic-updates universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic-updates universe

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu 
## team, and may not be under a free licence. Please satisfy yourself as to 
## your rights to use the software. Also, please note that software in 
## multiverse WILL NOT receive any review or updates from the Ubuntu
## security team.
deb http://us.archive.ubuntu.com/ubuntu/ bionic multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic multiverse
deb http://us.archive.ubuntu.com/ubuntu/ bionic-updates multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic-updates multiverse

## N.B. software from this repository may not have been tested as
## extensively as that contained in the main release, although it includes
## newer versions of some applications which may provide useful features.
## Also, please note that software in backports WILL NOT receive any review
## or updates from the Ubuntu security team.
deb http://us.archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse

## Uncomment the following two lines to add software from Canonical's
## 'partner' repository.
## This software is not part of Ubuntu, but is offered by Canonical and the
## respective vendors as a service to Ubuntu users.
# deb http://archive.canonical.com/ubuntu bionic partner
# deb-src http://archive.canonical.com/ubuntu bionic partner

deb http://security.ubuntu.com/ubuntu bionic-security main restricted
# deb-src http://security.ubuntu.com/ubuntu bionic-security main restricted
deb http://security.ubuntu.com/ubuntu bionic-security universe
# deb-src http://security.ubuntu.com/ubuntu bionic-security universe
deb http://security.ubuntu.com/ubuntu bionic-security multiverse
# deb-src http://security.ubuntu.com/ubuntu bionic-security multiverse

```
kali-linux-2024.4-vmware-amd64.ovf
```
<?xml version="1.0" encoding="UTF-8"?>
<!--Generated by VMware ovftool 4.6.3 (build-24031167), UTC time: 2025-02-03T07:47:22.044294Z-->
<Envelope vmw:buildId="build-24031167" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="kali-linux-2024.4-vmware-amd64-disk1.vmdk" ovf:id="file1" ovf:size="9601684480"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="86000000000" ovf:capacityAllocationUnits="byte" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" ovf:populatedSize="24033287168"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="nat">
      <Description>The nat network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="vm">
    <Info>A virtual machine</Info>
    <Name>kali-linux-2024.4-vmware-amd64</Name>
    <OperatingSystemSection ovf:id="96" ovf:version="10" vmw:osType="debian10_64Guest">
      <Info>The kind of installed guest operating system</Info>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>kali-linux-2024.4-vmware-amd64</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-08</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>4 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>4</rasd:VirtualQuantity>
        <vmw:CoresPerSocket ovf:required="false">2</vmw:CoresPerSocket>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>2048MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>2048</rasd:VirtualQuantity>
      </Item>
      <Item ovf:required="false">
        <rasd:Address>0</rasd:Address>
        <rasd:Description>USB Controller (EHCI)</rasd:Description>
        <rasd:ElementName>usb</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>vmware.usb.ehci</rasd:ResourceSubType>
        <rasd:ResourceType>23</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="ehciEnabled" vmw:value="true"/>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>scsiController0</rasd:ElementName>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>disk0</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:Parent>4</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>2</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>nat</rasd:Connection>
        <rasd:Description>E1000 ethernet adapter on &quot;nat&quot;</rasd:Description>
        <rasd:ElementName>ethernet0</rasd:ElementName>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="slotInfo.pciSlotNumber" vmw:value="33"/>
        <vmw:Config ovf:required="false" vmw:key="connectable.allowGuestControl" vmw:value="false"/>
      </Item>
      <Item ovf:required="false">
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>sound</rasd:ElementName>
        <rasd:InstanceID>7</rasd:InstanceID>
        <rasd:ResourceSubType>vmware.soundcard.ensoniq1371</rasd:ResourceSubType>
        <rasd:ResourceType>1</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="slotInfo.pciSlotNumber" vmw:value="34"/>
      </Item>
      <Item ovf:required="false">
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>video</rasd:ElementName>
        <rasd:InstanceID>8</rasd:InstanceID>
        <rasd:ResourceType>24</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="videoRamSizeInKB" vmw:value="131072"/>
      </Item>
      <Item ovf:required="false">
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>vmci</rasd:ElementName>
        <rasd:InstanceID>9</rasd:InstanceID>
        <rasd:ResourceSubType>vmware.vmci</rasd:ResourceSubType>
        <rasd:ResourceType>1</rasd:ResourceType>
      </Item>
      <vmw:Config ovf:required="false" vmw:key="cpuHotAddEnabled" vmw:value="true"/>
      <vmw:Config ovf:required="false" vmw:key="simultaneousThreads" vmw:value="1"/>
      <vmw:Config ovf:required="false" vmw:key="virtualNuma.coresPerNumaNode" vmw:value="0"/>
      <vmw:Config ovf:required="false" vmw:key="tools.syncTimeWithHost" vmw:value="true"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.powerOffType" vmw:value="soft"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.resetType" vmw:value="soft"/>
      <vmw:Config ovf:required="false" vmw:key="powerOpInfo.suspendType" vmw:value="soft"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="chipset.useAcpiBattery" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="chipset.useApmBattery" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="cpuid.coresPerSocket" vmw:value="2"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="ehci.pciSlotNumber" vmw:value="35"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="ethernet0.pciSlotNumber" vmw:value="33"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="guestInfo.detailed.data" vmw:value="architecture=&apos;X86&apos; bitness=&apos;64&apos; distroAddlVersion=&apos;2024.4&apos; distroName=&apos;Kali GNU/Linux&apos; distroVersion=&apos;2024.4&apos; familyName=&apos;Linux&apos; kernelVersion=&apos;6.11.2-amd64&apos; prettyName=&apos;Kali GNU/Linux Rolling&apos;"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="hpet0.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="isolation.tools.hgfs.disable" vmw:value="FALSE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="keyboard.allowBothIRQs" vmw:value="FALSE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="keyboard.vusb.enable" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="monitor.phys_bits_used" vmw:value="40"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="nvram" vmw:value="kali-linux-2024.4-vmware-amd64.nvram"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge0.pciSlotNumber" vmw:value="17"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge0.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge4.functions" vmw:value="8"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge4.pciSlotNumber" vmw:value="21"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge4.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge4.virtualDev" vmw:value="pcieRootPort"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge5.functions" vmw:value="8"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge5.pciSlotNumber" vmw:value="22"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge5.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge5.virtualDev" vmw:value="pcieRootPort"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge6.functions" vmw:value="8"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge6.pciSlotNumber" vmw:value="23"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge6.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge6.virtualDev" vmw:value="pcieRootPort"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge7.functions" vmw:value="8"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge7.pciSlotNumber" vmw:value="24"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge7.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="pciBridge7.virtualDev" vmw:value="pcieRootPort"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="scsi0.pciSlotNumber" vmw:value="16"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="softPowerOff" vmw:value="FALSE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="sound.pciSlotNumber" vmw:value="34"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="tools.capability.verifiedSamlToken" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb.generic.allowHID" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb.pciSlotNumber" vmw:value="32"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb.vbluetooth.startConnected" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:0.deviceType" vmw:value="hid"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:0.parent" vmw:value="-1"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:0.port" vmw:value="0"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:0.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:1.deviceType" vmw:value="hub"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:1.parent" vmw:value="-1"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:1.port" vmw:value="1"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:1.present" vmw:value="TRUE"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="usb:1.speed" vmw:value="2"/>
      
      <vmw:ExtraConfig ovf:required="false" vmw:key="virtualHW.productCompatibility" vmw:value="hosted"/>
      <vmw:ExtraConfig ovf:required="false" vmw:key="vmxstats.filename" vmw:value="kali-linux-2024.4-vmware-amd64.scoreboard"/>
    </VirtualHardwareSection>
    <AnnotationSection ovf:required="false">
      <Info>A human-readable annotation</Info>
      <Annotation>Kali Rolling (2024.4) x64
2024-11-30

- - - - - - - - - - - - - - - - - -

Username: kali
Password: kali
(US keyboard layout)

- - - - - - - - - - - - - - - - - -

* Kali Homepage:
https://www.kali.org/

* Kali Documentation:
https://www.kali.org/docs/

* Kali Tools:
https://www.kali.org/tools/

* Forum/Community Support:
https://forums.kali.org/

* Community Chat:
https://discord.kali.org</Annotation>
    </AnnotationSection>
  </VirtualSystem>
</Envelope>

```

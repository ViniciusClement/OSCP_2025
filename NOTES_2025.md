# OSCP 2025

* https://github.com/n0veride/pwk/tree/main
* https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide
* https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767

```

stand-alone -> 10 local -> 10 proof (WEB) - Serviço senha fraca (FTP)
stand-alone -> 10 local -> 10 proof (WEB) - Serviço senha fraca (postgree)
stand-alone -> 10 local -> 10 proof (WEB) - WEB (path traversal, SQL Injection)

AD -> User comum
MAq01 -> 10 proof
MAq02 -> 10 proof
MAq03 -> 20 proof

## Pivoting ##
Chisel ->

## Privelege Scalation ##
Linux: 
-->(sudo -l)
   https://gtfobins.github.io
--> file com crontab
--> serviço vulneravel

## ultimo caso reverse shell ##
--> passwd ou net use troca senha de admin

## Windows ##
--> whoami /priv (SeImpersonate)(GODPotato, Juice Potate etc)
--> file com Task Manager (C:)
--> serviço vulneravel (PowerUP.ps1)
--> mimikatz (hash)

## Acesso as maquinas ##
evil-winrm
rdp

## Ativar RDP ##
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
sc stop TermService
sc start TermService


## Em todas máquinas ##
whoami
ipconfig
hostname
flag

mysql -> (OS Injection)

postgree -> (OS Injection)
```

## MSSQL Injetion

* https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/
* https://medium.com/@oumasydney2000/mssql-enumeration-1433-1ee5fa6ac5d3
* https://gist.github.com/simran-sankhala/03c5c20078466f2bd29bac840ab3a5cf
```
mssql -> xp_cmdshell (OS Injection)
```
```
EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
go
xp_cmdshell 'whoami';
go
```


# Tools to Practical

* Ffuf
* Dirbuster
* PowerUp
* BloodHound (Legacy and Community Edition only)
* SharpHound
* Rubeus
* Mimikatz
* winPEAS / linpeas
* Chisel
* Responder (Poisoning and spoofing are not allowed in the challenges or on the exam)
* Netexec
* Impacket
* evil-winrm

# Official Guide

* https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide-Newly-Updated
* https://dev-angelist.gitbook.io/crtp-notes
* https://github.com/rodolfomarianocy/Tricks-Pentest-Active-Directory
* https://github.com/rodolfomarianocy/OSCP-Tricks-2023/tree/main

# Paths TryHackMe

* https://tryhackme.com/r/path/outline/jrpenetrationtester (Easy)
* https://tryhackme.com/r/path/outline/pentesting (Intermediate)
* https://tryhackme.com/r/path/outline/redteaming (Hard)

# Pivoting
* https://anishmi123.gitbooks.io/oscp-my-journey/content/proxychains.html
* https://medium.com/@tinopreter/pivoting-with-socks-and-proxychains-e9df908bacaa
* https://medium.com/@Fanicia/oscp-quick-hacktricks-windows-seimpersonateprivilege-cbb392030b14
* https://systemweakness.com/everything-about-pivoting-oscp-active-directory-lateral-movement-6ed34faa08a2
* https://medium.com/@saintlafi/pivoting-and-tunneling-for-oscp-and-beyond-cheat-sheet-3435d1d6022
* https://sushant747.gitbooks.io/total-oscp-guide/content/port_forwarding_and_tunneling.html
* https://medium.com/@frankyyano/pivoting-tunneling-for-oscp-and-beyond-33a57dd6dc69
* https://systemweakness.com/everything-about-pivoting-oscp-active-directory-lateral-movement-6ed34faa08a2

# Machines

* https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#
* https://github.com/HavocFramework/Havoc)
* https://www.offsec.com/labs/enterprise/)
* https://github.com/nicocha30/ligolo-ng
* https://www.offensivethink.com/oscp.html
* https://medium.com/@TheMsterDoctor1/welcome-to-the-linux-privilege-escalation-guide-within-my-oscp-offensive-security-certified-88bc5d167330
* https://johnjhacking.com/blog/oscp-reborn-2023/
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
* https://lnkd.in/dCjZGXPq
* https://lnkd.in/dfmqy7wd
* https://lnkd.in/dfGCpV4Z
* https://lnkd.in/dEvfjCxu
* https://lnkd.in/d3bv3JKk
* https://lnkd.in/eBee79k
* https://lnkd.in/e__s4AH
* https://lnkd.in/ev4B-ZF
* https://lnkd.in/euApgZ8
* https://lnkd.in/eKimv9k
* https://lnkd.in/eNXxRUy
* https://lnkd.in/eJNZ64U
* https://lnkd.in/e_Hw2fK
* https://lnkd.in/e6V2VE6
* https://lnkd.in/eUa7m6y
* https://lnkd.in/eWhpmU9
* https://lnkd.in/eJCfshN
* https://lnkd.in/d_U9SQ9
* https://lnkd.in/dPPtpejv
* https://lnkd.in/drKhHYfd
* https://lnkd.in/dmvipXdp
* https://lnkd.in/dW_29vyQ
* https://lnkd.in/dV7SUxbx
* https://lnkd.in/dKmvdTNj


# Links

[NetSecFocus Trophy Room - Google Drive](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#)

[Lainkusanagi OSCP Like.xlsx - Google Sheets](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/edit?gid=487240997#gid=487240997)

https://www.hack-notes.pro/your-path-to-the-oscp+

[HavocFramework/Havoc: The Havoc Framework](https://github.com/HavocFramework/Havoc)

[OffSec Enterprise Labs: Advanced Cyber Ranges for Offensive & Defensive Teams | OffSec](https://www.offsec.com/labs/enterprise/)

[nicocha30/ligolo-ng: An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface.](https://github.com/nicocha30/ligolo-ng)

https://www.offensivethink.com/oscp.html

https://medium.com/@TheMsterDoctor1/welcome-to-the-linux-privilege-escalation-guide-within-my-oscp-offensive-security-certified-88bc5d167330

https://blog.leonardotamiano.xyz/tech/oscp-technical-guide/

[Windows and Linux Privilege Escalation | OSCP Video Course Prep](https://www.youtube.com/watch?v=WKmbIhH9Wv8&t=11s)

[Solving Penetration Testing and CTF Challenge for OSCP - Photographer Vulnhub Walkthrough](https://www.youtube.com/watch?v=oiCw2Wh0KrM&t=757s)

[0x4D31/awesome-oscp: A curated list of awesome OSCP resources](https://github.com/0x4D31/awesome-oscp)

[anilp7688/Offensive-Security-Certified-Professional-OSCP-: To learn more information about Offensive Security Certified Professional (OSCP)](https://github.com/anilp7688/Offensive-Security-Certified-Professional-OSCP-)

[Master the Linux ‘mkfifo’ Command: A Comprehensive Guide | by Peter Hou | Medium](https://hopeness.medium.com/master-the-linux-mkfifo-command-a-comprehensive-guide-7e64ac926228)


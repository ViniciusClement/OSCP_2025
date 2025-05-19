# Initial Enumeration
## System Enumeration
* systeminfo
* systeminfo | findstr /b /c:"OS Name" /c:"OS Versoin" /c:"System Type"
* wmic qfe
* wmic qfe Caption,Description,HotFixID,InstalledOn
* wmic logicaldisk
* wmic logicaldisk get caption,description,providername
* wmic logicaldisk get caption

## User Enumeration
* whoami /priv
* whoami /groups
* net user
* net user Administrador
* net localgroup
* net localgroup administradores
* net user /domain
* net accounts

## Network Enumeration
* ipconfig
* ipconfig /all
* arp -a
* route print
* netstat -ano
* Password Hunting
* findstr /si password *.txt
* findstr /si password *.txt *.ini *.config

## AV Enumartaion
* sc query windefend
* sc queryex type= service
* netsh advfirewall firewall dump
* netsh firewall show state
* netsh firewall show config

## Commands Users and S.O
* whoami
* whoami /all
* systeminfo /all
* gethotfix

## Add user and change group
* net user hackudao 132456 /add
* net localgroup administradores hackudao /add
* dir /b
* dir /s
* type text.txt
* sort text.txt
* set
* set | findstr TEMP


## ADS - Alternate Data Stream







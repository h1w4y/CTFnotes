## Vulnhub - Lord Of The Root
<!-- TOC -->

- [Vulnhub - Lord Of The Root](#vulnhub---lord-of-the-root)
    - [YouTube](#youtube)
    - [Lessons Learned](#lessons-learned)
    - [VM ToDos](#vm-todos)
    - [Port Knocking](#port-knocking)
    - [Speculations and Hints](#speculations-and-hints)
    - [Network Discovery](#network-discovery)
    - [Metasploit Work](#metasploit-work)
    - [SSH Service](#ssh-service)
    - [Ubuntu Console Login](#ubuntu-console-login)
    - [Got Shell](#got-shell)
        - [Kernel](#kernel)
        - [Processes](#processes)

<!-- /TOC -->
***
### YouTube

***
### Lessons Learned
* [ ] do more reading on dirtycow

***
### VM ToDos
* [x] port scan  
* [x] port knocking 
* [ ] port knocking clients or `scapy` for port knocking

***
### Port Knocking
- using standard `knockd`  
- `/etc/knockd.conf` only readable by root
- <https://github.com/jvinet/knock>
- port knocking clients
- scapy <http://secdev.org/projects/scapy/>
- sequence is probably something to do with 1 2 3 from the banner-hint

***
### Speculations and Hints
* smeagol is the default login from the vm's GUI console
* the word "knock" is used in the `ssh` banner.  possibly a hint to try port knocking


***
### Network Discovery
sweeping no-ping scan of subnet to find target
```
nmap -Pn 192.168.86.0/24

Nmap scan report for 192.168.86.144
Host is up (0.00045s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:0C:29:19:9B:E6 (VMware)
```
TCP Syn Scan with light service detection
```
root@kali:~/LordOfTheRoot# nmap -sS 192.168.86.144 -p- -oA outputfile.out -v -sV --version-intensity 2
```
UDP Scan
```
nmap 192.168.86.144 -sU -oA udpscan.out
```
nmap with vuln scripts: (this is crap don’t even do it)
```
nmap -sS 192.168.86.144 -p- -oA outputfile.out -v -sV --script vuln
```

***
### Metasploit Work
add a workspace  
load all the nmap output  
```
msf > workspace -a LordOfTheRoot
msf > db_load ~/LordOfTheRoot *.xml
```
check hosts and services found by `nmap`
```
msf > hosts

Hosts
=====

address         mac                name  os_name  os_flavor  os_sp  purpose  info  comments
-------         ---                ----  -------  ---------  -----  -------  ----  --------
192.168.86.144  00:0c:29:19:9b:e6        Unknown                    device         

msf > services

Services
========

host            port  proto  name  state  info
----            ----  -----  ----  -----  ----
192.168.86.144  22    tcp    ssh   open   OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 Ubuntu Linux; protocol 2.0
***
### SSH Service
only service running on tcp/udp is SSH

```

OpenSSH 6.6.1p1
[CVEDetails]( https://www.cvedetails.com/vulnerability-list/vendor_id-97/product_id-585/version_id-188831/Openbsd-Openssh-6.6.html)   
nothing too interesting for getting access

```
root@kali:~/LordOfTheRoot# ssh 192.168.86.144
The authenticity of host '192.168.86.144 (192.168.86.144)' can't be established.
ECDSA key fingerprint is SHA256:XzDLUMxo8ifHi4SciYJYj702X3PfFwaXyKOS07b6xd8.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.86.144' (ECDSA) to the list of known hosts.


                                                  .____    _____________________________
                                                  |    |   \_____  \__    ___/\______   \
                                                  |    |    /   |   \|    |    |       _/
                                                  |    |___/    |    \    |    |    |   \
                                                  |_______ \_______  /____|    |____|_  /
                                                          \/       \/                 \/
 ____  __.                     __     ___________      .__                   .___ ___________      ___________       __
|    |/ _| ____   ____   ____ |  | __ \_   _____/______|__| ____   ____    __| _/ \__    ___/___   \_   _____/ _____/  |_  ___________
|      <  /    \ /  _ \_/ ___\|  |/ /  |    __) \_  __ \  |/ __ \ /    \  / __ |    |    | /  _ \   |    __)_ /    \   __\/ __ \_  __ \
|    |  \|   |  (  <_> )  \___|    <   |     \   |  | \/  \  ___/|   |  \/ /_/ |    |    |(  <_> )  |        \   |  \  | \  ___/|  | \/
|____|__ \___|  /\____/ \___  >__|_ \  \___  /   |__|  |__|\___  >___|  /\____ |    |____| \____/  /_______  /___|  /__|  \___  >__|
        \/    \/            \/     \/      \/                  \/     \/      \/                           \/     \/          \/

Easy as 1,2,3
root@192.168.86.144's password: 


```

the word "knock" in this banner makes me think
* subdomain enumeration - but this isn't going to be it for a single vm
* port knocking 

Also tried a few wild guesses: user root, passwords “” “knock” “knockfriend” “KnockFriend”  

Next thing is it’s possibly some LOTR reference, so google around for possible username/passwords related to that passage in the books  

***
### SSH Service

when the vm booted, `smeagol` was set as the default login user…

```
hydra options
-l single username
-P password list
-o output file
-t1 one thread
-v verbose
-f exit when login pair is found

root@kali:~/LordOfTheRoot# hydra -l smeagol -P ~/SecLists/Passwords/10k_most_common.txt ssh://192.168.86.144 -o hydra.out -t1 -v -f
Hydra v8.3 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2017-04-17 23:09:02
[DATA] max 1 task per 1 server, overall 64 tasks, 10000 login tries (l:1/p:10000), ~156 tries per task
[DATA] attacking service ssh on port 22
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://192.168.86.144:22
[ERROR] target ssh://192.168.86.144:22/ does not support password authentication.
```

***
### Ubuntu Console Login
from Ubuntu login screen a guest session can log in

### Got Shell

#### Kernel
`uname -r` shows  
3.19.0-25-generic

some googling suggests that 3.19 might be vulnerable to dirtycow
<https://github.com/dirtycow/dirtycow.github.io/wiki/Patched-Kernel-Versions>

I downloaded/compiled/ran a couple dirtycow exploits, but didn't have any success.  It's possible even though the docs suggest kernel 3.19 is vulnerable, that i'm misreading or this is a patched version of 3.19  
Need to do more reading on dirtycow...

#### Processes
with guess access from the ubuntu console, i'm able to run `ps`
```
$ ps aux | less
```
interesting processes running 
- rsyslogd - not going to be listening on a port, but should check the version for CVEs
- sshd running (we knew that from our port scan)
- mysqld - juicy
- knockd - the port knock server
    - next step is to knock some ports to get network access
- apache2 - really juicy
   - 6 apache processes running  
   - 1 running as root - i'm assuming this is an apache init process, been a while since I've done any web admin
   - 5 running as additional workers - possibly supporting multiple sites/ports?


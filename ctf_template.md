## Vulnhub - VMName
<!-- TOC -->

- [Vulnhub - VMName](#vulnhub---vmname)
    - [YouTube](#youtube)
    - [Lessons Learned](#lessons-learned)
    - [VM ToDos](#vm-todos)
    - [Speculations and Hints](#speculations-and-hints)
    - [Network Discovery](#network-discovery)
    - [Metasploit Work](#metasploit-work)
    - [Service Details 1](#service-details-1)
    - [Service Details 2](#service-details-2)
    - [Direct Console Access](#direct-console-access)
    - [Shell Access](#shell-access)
        - [Interesting Processes](#interesting-processes)
        - [Sudo Capabilities](#sudo-capabilities)
        - [Homedir Search](#homedir-search)

<!-- /TOC -->
***
### YouTube

***
### Lessons Learned

***
### VM ToDos

***
### Speculations and Hints

***
### Network Discovery
sweeping no-ping scan of subnet to find target
```
nmap -Pn 192.168.xxx.0/24
```
TCP Syn Scan with light service detection
```
nmap -sS 192.168.xxx.xxx -p- -oA synscan.out -v -sV --version-intensity 2
```
UDP Scan
```
nmap 192.168.xxx.xxx -sU -oA udpscan.out
```
nmap with vuln scripts: (this is crap don’t even do it)
```
nmap -sS 192.168.xxx.xxx -p- -oA vulnscriptsscan.out -v -sV --script vuln
```

***
### Metasploit Work
add a workspace  
load all the nmap output  
```
msf > workspace -a VulnHubVmName
msf > db_load ~/VulnHubVmName *.xml
```
check hosts and services found by `nmap`
```
msf > hosts

msf > services
```

***
### Service Details 1

***
### Service Details 2

***
### Direct Console Access

***
### Shell Access

#### Interesting Processes

#### Sudo Capabilities

#### Homedir Search
`find /home`
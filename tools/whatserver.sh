#! /usr/bin/env bash

# Script to quickly display essential server information. Qualtiy, not quantity.
# - Extracts FQDN from certificates, nginx & apache conf
# - Most recent activities / uses.
#
#   curl -kfsSL https://thc.org/ws | bash | less -R
#   curl -kfsSL https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/whatserver.sh | bash | less -R
#
# The Source Code is available at:
#   https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/tree/master/tools
#
# Often used in combination with gsexecio to retrieve information from all hosts:
#   cat secrets.txt | parallel -j50 'cat whatserver.sh | exec gsexecio {} >whatserver-{}.log'
#
# Use `command less -R whatserver.log` to display the log files with color.
# Use `cat whatserver.log | sed -e 's/\x1b\[[0-9;]*m//g'` to remove colors.

# NOCOLOR=1  # un-comment this line to disable colors

# Some ideas by slav and from virt-what

: <<-'COMMENT'

# Extracting all domain names from all log files and displaying them with
# GeoLocation and AS information (and converted to UTF-8)
# This will only work on segfault.net (as it needs geoip and idn2)

find . -name 'whatserver*.log' | while read fn; do
        s=$(grep -F '  "org": ' "$fn")
        s=${s##*: \"}
        s=${s%\"*}
        as=${s%% *}
        name=${s#* }
        name=${name//\\}
        name=${name:0:32}
        ip=$(grep -F '  "ip": ' "$fn")
        ip=${ip##*: \"}
        ip=${ip%\"*}
        unset geoip
        [[ -n "$ip" ]] && geoip=$(geoip "${ip}")
        grep ^DOMAIN "$fn" | while read x; do
	        x=${x//|}
	        x=${x//$'\r'}
	        unset origcn
	        [[ "$x" == *"xn--"* ]] && {
		        origcn=" [${x:7:40}]"
		        x="DOMAIN $(idn2 -d "${x:7}" 2>/dev/null)"
	        }
	       echo "$as|${geoip:-N/A}|${ip:-N/A}|${x:7:64}${origcn}"
	    done
done | anew | column -t -s'|' -o' | '
COMMENT

[[ -z "$NOCOLOR" ]] && {
    CY="\e[1;33m" # yellow
    CG="\e[1;32m" # green
    CR="\e[1;31m" # red
    CC="\e[1;36m" # cyan
    # CM="\e[1;35m" # magenta
    CW="\e[1;37m" # white
    CB="\e[1;34m" # blue
    CF="\e[2m"    # faint
    CN="\e[0m"    # none
    # CBG="\e[42;1m" # Background Green
    # night-mode
    CDR="\e[0;31m" # red
    CDG="\e[0;32m" # green
    CDY="\e[0;33m" # yellow
    CDB="\e[0;34m" # blue
    CDM="\e[0;35m" # magenta
    CDC="\e[0;36m" # cyan
    CUL="\e[4m"
}

### Certificates
addcn() {
    local IFS=" "
    local str="${1,,}"
    local regex="[^-a-z0-9.\*]"
    local tld
    str="${str//\"}"
    str="${str// }"
    str="${str//$'\r'}"
    [[ -z "$str" ]] && return
    tld="${str##*.}"
    # [[ ${#tld} -gt 3 ]] && return # .blog,.agency,.social, ...
    [[ ${#tld} -le 1 ]] && return # Not interested in .* .a and .x
    [[ "$str" != *"."* ]] && return  # Not containing any .
    [[ "$str" == *"@"* ]] && return  # Is an email
    [[ "$str" == *"example.org" ]] && return
    [[ "$str" == *"example.com" ]] && return
    [[ "$str" == "entrust.netsecureservercertificationauthority" ]] && return # "Entrust.net Secure Server Certification Authority"
    [[ "$str" == *".tld" ]] && return
    [[ "$str" == *".wtf" ]] && return
    # [[ "$str" == *".alias" ]] && return
    [[ "$str" == *".if" ]] && return
    # [[ "$str" == *".local" ]] && return
    # [[ "$str" == *".headers" ]] && return
    [[ "$str" == *"foo."* ]] && return
    [[ "$str" == *"localhost"* ]] && return  # also localhost4.localdomain4
    [[ "$str" == *"domain.com" ]] && return
    [[ "$str" == *"domain1.com" ]] && return
    [[ "$str" == *"domain2.com" ]] && return
    [[ "$str" == *"site.com" ]] && return
    [[ "$str" == *".host.org" ]] && return
    [[ "$str" == *".nginx.org" ]] && return
    [[ "$str" == *"server-1.biz" ]] && return
    [[ "myforums.com headers.com isnot.org one.org two.org" == *"$str"* ]] && return
    [[ "$str" =~ $regex ]] && return
    [[ " ${arr[*]} " == *" $str "* ]] && return  # Already inside array
    arr+=("$str")
}

# Line with multiple domain names
addline() {
    local IFS
    local str="$1"
    local names
    local n
    IFS=$'\t'" " read -r -a names <<<"$str"
    for n in "${names[@]}"; do
        addcn "$n"
    done
}

addcertfn() {
    local fn="$1"
    local str
    [[ ! -f "$fn" ]] && return
    [[ "$fn" == *_csr-* ]] && return  # Skip certificate requests
    [[ "$(openssl x509 -noout -in "$fn" -ext basicConstraints 2>/dev/null)" == *"CA:TRUE"* ]] && return
    str="$(openssl x509 -noout -in "$fn" -subject 2>/dev/null)"
    [[ "$str" != "subject"* ]] && return
    [[ "$str" != *"/CN"* ]] && return
    str="$(echo "$str" | sed '/^subject/s/^.*CN.*=[ ]*//g')"
    addcn "$str" "$fn"
}

# Return <Virtualization>/<Container> or EMPTY if baremetal. Mostly stolen from:
#   virt-what
#   systemd-detect-virt --vm
#   systemd-detect-virt --container
get_virt() {
    local str
    local cont
    local str_suffix
    local os
    local os_prefix

    # old way: grep -sqF " /docker/" "/proc/self/mountinfo"
    if grep -sqF docker "/proc/1/cgroup" &>/dev/null || grep -F -m1 ' / / r' "/proc/self/mountinfo" | grep -sqF "docker"; then
        cont="Docker"
    elif tr '\000' '\n' <"/proc/1/environ" | grep -Eiq '^container=podman' || grep -sqF /libpod- "/proc/self/cgroup"; then
        cont="Podman"
    elif [[ -d /proc/vz ]]; then
        cont="Virtuozzo" # OpenVZ
    elif tr '\000' '\n' <"/proc/1/environ" | grep -Eiq '^container=lxc'; then
        cont="LXC"
    elif [ -e /proc/cpuinfo ] && grep -q 'UML' "/proc/cpuinfo"; then
        cont="User Mode Linux"
    elif [[ "$(ls -di / | cut -f1 -d' ')" -gt 2 ]]; then
        cont="chroot"
    fi
    [[ -n "$cont" ]] && str_suffix="/${cont}"

    [[ -d /proc/bc ]] && { echo "OpenVZ${str_suffix}"; return; }

    str=$(uname -r)
    { [[ $str == *"microsoft"* ]] || [[ $str == *"WSL"* ]]; } && { echo "Microsoft WSL${str_suffix}"; return; }
    # Show if this is grsecurity (ohh theOwl strikes again)
    [[ $str == *"grsec"* ]] && { os="Linux-grsec"; os_prefix="${os}/"; }

    str="$(cat /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/board_vendor /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/product_version 2>/dev/null)"
    [[ -n "$str" ]] && {
        [[ "$str" == *"VirtualBox"* ]]               && { echo "${os_prefix}VirtualBox${str_suffix}"; return; }
        [[ "$str" == *"innotek GmbH"* ]]             && { echo "${os_prefix}VirtualBox${str_suffix}"; return; }
        [[ "$str" == *"VMware"* ]]                   && { echo "${os_prefix}VMware${str_suffix}"; return; }
        [[ "$str" == *"KubeVirt"* ]]                 && { echo "${os_prefix}KubeVirt${str_suffix}"; return; }
        [[ "$str" == *"QEMU"* ]]                     && { echo "${os_prefix}QEMU${str_suffix}"; return; }
        [[ "$str" == *"OpenStack"* ]]                && { echo "${os_prefix}OpenStack${str_suffix}"; return; }
        [[ "$str" == *"Amazon "* ]]                  && { echo "${os_prefix}Amazon EC2${str_suffix}"; return; }
        [[ "$str" == *"KVM"* ]]                      && { echo "${os_prefix}KVM${str_suffix}"; return; }
        [[ "$str" == *"VMW"* ]]                      && { echo "${os_prefix}VMW${str_suffix}"; return; }
        [[ "$str" == *"Xen"* ]]                      && { echo "${os_prefix}Amazon Xen${str_suffix}"; return; }
        [[ "$str" == *"Bochs"* ]]                    && { echo "${os_prefix}Bochs${str_suffix}"; return; }
        [[ "$str" == *"Parallels"* ]]                && { echo "${os_prefix}Parallels${str_suffix}"; return; }
        [[ "$str" == *"BHYVE"* ]]                    && { echo "${os_prefix}BHYVE${str_suffix}"; return; }
        [[ "$str" == *"Hyper-V"* ]]                  && { echo "${os_prefix}Microsoft Hyper-V${str_suffix}"; return; }
        [[ "$str" == *"Virtual Machine"* ]] && [[ "$str" == *"Microsoft"* ]] && { echo "${os_prefix}Microsoft Hyper-V${str_suffix}"; return; }
        [[ "$str" == *"Apple Virtualization"* ]]     && { echo "${os_prefix}Apple Virtualization${str_suffix}"; return; }
    }

    # No Virtualization but inside a container or chroot()-type
    [[ -n "$cont" ]] && { echo "${os}$cont"; return; }

    # Inside gs-security or other OS worth mentioning
    [[ -n "$os" ]] && { echo "${os}"; return; }

    return 255
}

HTTPS_curl() { curl -m 10 -fksSL "$*"; }
HTTPS_wget() { wget -qO- "--connect-timeout=7" "--dns-timeout=7" "--no-check-certificate" "$*"; }

COL_column() { column -t; }

if command -v curl >/dev/null; then
    HTTPS() { HTTPS_curl "$@"; }
elif command -v wget >/dev/null; then
    HTTPS() { HTTPS_wget "$@"; }
else
    HTTPS() { :; }
fi

if command -v column >/dev/null; then
    COL() { COL_column; }
else
    COL() { cat; }
fi

PATH="/usr/sbin:$PATH"
IFS=$'\n'
# Close STDERR to supress error for "tr ... <FILE" when FILE can not be read
exec 2>&-

unset inet
command -v ip >/dev/null && inet="$(ip a show 2>/dev/null)"
[[ -z "$inet" ]] && command -v ifconfig >/dev/null && inet="$(ifconfig 2>/dev/null)"
[[ -n "$inet" ]] && inet=$(echo "$inet" | grep inet | grep -vF 'inet 127.' | grep -vF 'inet6 ::1' | awk '{print $2;}' | sort -rn)

echo -e "${CW}>>>>> Info${CN}"
uname -a 2>/dev/null || cat /proc/version 2>/dev/null
# Retrieve virtualization method
str="$(get_virt)" && echo "Virtualization: $str"
ncpu=$(nproc 2>/dev/null)
[[ -e /proc/cpuinfo ]] && {
    [[ -z "$ncpu" ]] && ncpu=$(grep -c '^processor' /proc/cpuinfo)
    cpu=$(grep -m1 '^model name' /proc/cpuinfo | cut -f2 -d:)
    [[ -z "$cpu" ]] && cpu=$(grep -m1 '^cpu model' /proc/cpuinfo | cut -f2 -d:)
    [[ -z "$cpu" ]] && cpu=$(grep -m1 '^Hardware' /proc/cpuinfo | cut -f2 -d:)
}
# Apple
[[ -z "$cpu" ]] && command -v sysctl >/dev/null && cpu=$(sysctl -a machdep.cpu.brand_string 2>/dev/null| head -n1 | grep '^machdep.cpu' | sed -e 's/[^:]*[: \t]*//')
[[ -z "$cpu" ]] && command -v lscpu >/dev/null && {
    cpu=$(lscpu 2>/dev/null | grep -m1 -F 'Model name:' | sed -e 's/[^:]*[: \t]*//')
    [[ -z "$cpu" ]] && cpu=$(lscpu 2>/dev/null | grep -m1 '^Vendor ID' | sed -e 's/[^:]*[: \t]*//')
}

command -v free >/dev/null && {
    mem=$(free -h 2>/dev/null | grep -m1 ^Mem | awk '{print $2;}')
}
command -v top >/dev/null && [[ -z "$mem" ]] && {
    mem=$(top -l1 -s0 2>/dev/null | grep -m1 PhysMem | cut -f2- -d' ')
}
echo "CPU           : ${ncpu:-0}x${cpu:-???} / ${mem:-???} RAM"
unset mem cpu ncpu

hostnamectl 2>/dev/null || lsb_release -a 2>/dev/null
# || cat /etc/banner 2>/dev/null
source /etc/os-release 2>/dev/null && echo "Pretty Name: ${PRETTY_NAME}"
echo "Date       : $(date)"
command -v uptime >/dev/null && {
    str=$(uptime | sed -e 's/^[ \t]*//')
    [[ -n "$str" ]] && echo "Uptime     : $str"
}
id
ipinfo="$(HTTPS https://ipinfo.io 2>/dev/null)" && {
    ptrcn="${ipinfo#*  \"hostname\": \"}"
    ptrcn="${ptrcn%%\",*}"
    echo -e "$ipinfo"
}

[[ -n "$inet" ]] && {
    echo -e "${CY}>>>>> Addresses${CN}"
    echo "$inet"
}

unset arr
addcn "$ptrcn"
addcn "$(hostname 2>/dev/null)"

# Ngingx sites
[[ -d /etc/nginx ]] && {
    lines=($(grep -r -E 'server_name .*;' /etc/nginx 2>/dev/null))
    for str in "${lines[@]}"; do
        str="${str#*server_name }"
        str="${str%;*}"
        addline "$str"
    done
}

# Apache sites
[[ -d /etc/httpd ]] && {
    lines=($(grep -r -E ':*(ServerName|ServerAlias)[ ]+' /etc/httpd 2>/dev/null | grep -v ':[ ]*#'))
    for str in "${lines[@]}"; do
        str="${str#*ServerName }"
        str="${str#*ServerAlias }"
        addline "$str"
    done
}

# Find where the certificates are stored:
unset certsfn
IFS=$'\n'
[[ -d /etc/nginx ]] && certsfn=($(find /etc/nginx -name '*.conf*' -exec grep -F "ssl_certificate " {} \; 2>/dev/null | awk '{print $NF;}' | sed 's/;$//' | sort -u))

# Any any file that sounds like a certificate
certsfn+=($(find /etc -name '*.crt' -o -name '*.pem' 2>/dev/null))

# Add all found certificate-files
for fn in "${certsfn[@]}"; do
    addcertfn "$fn"
done

# Grab certificate from live server (in case we dont have read access to the file):
addcn "$(openssl s_client -showcerts -connect 0:443 2>/dev/null  </dev/null | openssl x509 -noout -subject  2>/dev/null | sed '/^subject/s/^.*CN.*=[ ]*//g')"

# Assess /etc/hosts. Extract valid domains.
IFS=$'\n' lines=($(grep -v '^#' /etc/hosts | grep -v -E '(^255\.|\sip6)'))
unset harr
IFS=$'\n'
for x in "${lines[@]}"; do
    [[ "${inet:-BLAHBLAHNOTEXIST} 127.0.0.1" == *"$(echo "$x" | awk '{print $1;}')"* ]] && {
        # Save domains that are assigned to _this_ IP
        addline "$(echo "$x" | sed -E 's/[0-9.]+[ \t]+//')"
        continue
    }
    # Save all other domains in host array
    IFS=" "$'\t' harr+=($(echo "$x" | grep -vF localhost | sed -E 's/[0-9.]+[ \t]+//')) 
done
unset lines
unset IFS

IFS=$'\n' res=($(printf "%s\n" "${arr[@]}" | sort -u))
unset arr
[[ ${#res[@]} -gt 0 ]] && {
    echo -e "${CY}>>>>> Domain Names${CN} (${#res[@]})"
    printf "DOMAIN %s\n" "${res[@]}"
}

IFS=$'\n' res=($(printf "%s\n" "${harr[@]}" | sort -u))
unset harr
[[ ${#res[@]} -gt 0 ]] && {
    echo -e "${CY}>>>>> Other hosts (from /etc/hosts)${CN} (${#res[@]})"
    printf "HOST  %s\n" "${res[@]}" | sort -u
}
unset res

[[ -f ~/.ssh/known_hosts ]] && {
    echo -e "${CDM}>>>>> Last SSH usage (Hosts: $(wc -l <~/.ssh/known_hosts))${CN}"
    command ls -ltu ~/.ssh/known_hosts
    IFS="" str="$(grep -v '^|' ~/.ssh/known_hosts | cut -f1 -d" " | cut -f1 -d, | uniq)"
    [[ -n "$str" ]] && echo -e "${CDM}>>>>> SSH hosts accessed${CN}\n${str}"
}

echo -e "${CDM}>>>>> Storage ${CN}"
df -h 2>/dev/null | grep -v ^tmpfs

echo -e "${CDM}>>>>> Last History${CN}"
ls -al ~/.*history* 2>/dev/null

echo -e "${CDM}>>>>> /home (top20)${CN}"
# BusyBox does not know --sort=time
ls -Lld -t /root /home/* 2>/dev/null | head -n20

str=$(w -o -h 2>/dev/null | head -n100)
[[ -n "$str" ]] && {
    echo -e "${CDM}>>>>> Online${CN}"
    echo "$str"
}

str=$(lastlog 2>/dev/null | tail -n+2 | grep -vF 'Never logged in')
[[ -n "$str" ]] && {
    echo -e "${CDM}>>>>> Lastlog${CN}"
    echo "$str"
}

echo -e "${CDM}>>>>> /root/${CN}"
ls -lat /root/ 2>/dev/null | head -n 100

# Output network information
if command -v ip >/dev/null; then
    echo -e "${CB}>>>>> ROUTING table${CN}"
    ip route show 2>/dev/null | COL
    echo -e "${CB}>>>>> LINK stats${CN}"
    # BusyBox does not support -s
    { ip -s link || ip link show;} 2>/dev/null 
    echo -e "${CB}>>>>> ARP table${CN}"
    ip n sh 2>/dev/null | COL
else
    command -v netstat >/dev/null && {
        echo -e "${CB}>>>>> ROUTING table${CN}"
        netstat -rn 2>/dev/null
        echo -e "${CB}>>>>> LINK stats${CN}"
        netstat -in 2>/dev/null
    }
    echo -e "${CB}>>>>> ARP table${CN}"
    command -v arp >/dev/null && arp -an 2>/dev/null | COL
fi

command -v netstat >/dev/null && {
    str=$(netstat -antp 2>/dev/null | grep LISTEN) || str=$(netstat -an 2>/dev/null | grep ^tcp | grep LISTEN | sort -u -k4 | sort -k1)
    [[ -n "$str" ]] && {
        echo -e "${CDG}>>>>> Listening TCP${CN}"
        echo "$str"
    }
    str=$(netstat -anup 2>/dev/null | grep ^udp | grep -v ESTABL) || str=$(netstat -an 2>/dev/null | grep ^udp | grep -v ESTABL | grep -vF '0  *.*' | sort -u  -k4 |grep -E '\*\s*$')
    [[ -n "$str" ]] && {
        echo -e "${CDG}>>>>> Listening UDP${CN}"
        echo "$str"
    }
}

[[ -n "$(docker ps -aq 2>/dev/null)" ]] && {
    echo -e "${CDR}>>>>> Docker Containers${CN}"
    docker ps -a
}

echo -e "${CDR}>>>>> Process List${CN}"
# Dont display kernel threads
# BusyBox only supports "ps w"
{ ps --ppid 2 -p 2 --deselect flwww || ps alxwww || ps w;} 2>/dev/null | head -n 500

# use "|head -n-1" to not display this line
echo -e "${CW}>>>>> 📖 Please help to make this tool better - https://t.me/thcorg${CN} 😘"
# return with "success"

exit 0

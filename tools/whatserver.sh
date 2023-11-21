#! /usr/bin/env bash

# Script to quickly find juicy targets. Often used in combination with gsexecio to
# retrieve information from all hosts:
#  cat secrets.txt | parallel -j50 'cat whatserver.sh | exec gsexecio {} >whatserver-{}.log'
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
        [[ -n $ip ]] && geoip=$(geoip "${ip}")
        grep ^DOMAIN "$fn" | while read x; do
	        x=${x//|}
	        x=${x//$'\r'}
	        unset origcn
	        [[ "$x" == *"xn--"* ]] && {
		        origcn=" [${x:7:40}]"
		        x="DOMAIN $(idn2 -d "${x:7}" 2>/dev/null)"
	        }
	       echo "$as|${geoip:-N/A}|${ip:-N/A}|${x:0:48}${origcn}"
	    done
done | anew | column -t -s'|' -o' | '

COMMENT

# NOCOLOR=1  # un-comment this line to disable colors

[[ -z $NOCOLOR ]] && {
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
    [[ -z $str ]] && return
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
    IFS=$'\t'" " names=(${str})
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

unset inet
if command -v ip >/dev/null; then
    IFS=$'\n' inet="$(ip a show)"
elif command -v ifconfig >/dev/null; then
    IFS=$'\n' inet="$(ifconfig)"
fi
[[ -n $inet ]] && {
    IFS=$'\n' inet=$(echo "$inet" | grep inet | grep -vF 'inet 127.' | grep -vF 'inet6 ::1' | awk '{print $2;}')
}

echo -e "${CW}>>>>> Info${CN}"
uname -a
date
uptime
id
HTTPS https://ipinfo.io 2>/dev/null
echo ""
echo -e "${CY}>>>>> Addresses${CN}"
echo "$inet"

unset arr
addcn "$(hostname)"

# Ngingx sites
[[ -d /etc/nginx ]] && {
    IFS=$'\n' lines=($(grep -r -E 'server_name .*;' /etc/nginx 2>/dev/null))
    for str in "${lines[@]}"; do
        str="${str#*server_name }"
        str="${str%;*}"
        addline "$str"
    done
}

# Apache sites
[[ -d /etc/httpd ]] && {
    IFS=$'\n' lines=($(grep -r -E ':*(ServerName|ServerAlias)[ ]+' /etc/httpd 2>/dev/null | grep -v ':[ ]*#'))
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
IFS=$'\n' lines=($(grep -v '^#' /etc/hosts | grep -v -E '(^127\.|^255\.|localhost| ip6)'))
unset harr
IFS=$'\n'
for x in "${lines[@]}"; do
    [[ "${inet:-BLAHBLAHNOTEXIST}" == *"$(echo "$x" | awk '{print $1;}')"* ]] && {
        # Save domains that are assigned to _this_ IP
        addline "$(echo "$x" | sed -E 's/[0-9.]+[ \t]+//')"
        continue
    }
    # Save all other domains in host array
    IFS=" "$'\t' harr+=($(echo "$x" | sed -E 's/[0-9.]+[ \t]+//')) 
done
unset lines
unset IFS

IFS=$'\n' res=($(printf "%s\n" "${arr[@]}" | sort -u))
unset arr
echo -e "${CY}>>>>> Domain Names${CN} (${#res[@]})"
[[ ${#res[@]} -gt 0 ]] && printf "DOMAIN %s\n" "${res[@]}"

IFS=$'\n' res=($(printf "%s\n" "${harr[@]}" | sort -u))
unset harr
echo -e "${CY}>>>>> Other hosts (from /etc/hosts)${CN} (${#res[@]})"
[[ ${#res[@]} -gt 0 ]] && printf "HOST  %s\n" "${res[@]}" | sort -u
unset res

[[ -f ~/.ssh/known_hosts ]] && {
    echo -e "${CDM}>>>>> Last SSH usage${CN}"
    ls -l --time=atime ~/.ssh/known_hosts
    IFS="" str="$(grep -v '^|' ~/.ssh/known_hosts | cut -f1 -d" " | cut -f1 -d,)"
    [[ -n $str ]] && echo -e "${CDM}>>>>> SSH hosts accessed${CN}"
}

echo -e "${CDM}>>>>> Last History${CN}"
ls -al ~/.*history* 2>/dev/null

echo -e "${CDM}>>>>> /home (top20)${CN}"
ls -ld /root /home/* --sort=time | head -n20

# Output network information
if command -v ip >/dev/null; then
    echo -e "${CB}>>>>> ROUTING table${CN}"
    ip route show | COL
    echo -e "${CB}>>>>> LINK stats${CN}"
    ip -s link
    echo -e "${CB}>>>>> ARP table${CN}"
    ip n sh | COL
else
    command -v netstat >/dev/null && {
        echo -e "${CB}>>>>> ROUTING table${CN}"
        netstat -rn
        echo -e "${CB}>>>>> LINK stats${CN}"
        netstat -in
    }
    echo -e "${CB}>>>>> ARP table${CN}"
    command -v arp >/dev/null && arp -n | COL
fi

command -v netstat >/dev/null && {
    echo -e "${CDG}>>>>> Listening TCP${CN}"
    netstat -antp | grep LISTEN
    echo -e "${CDG}>>>>> Listening UDP${CN}"
    netstat -anup
}

[[ -n "$(docker ps -aq 2>/dev/null)" ]] && {
    echo -e "${CDR}>>>>> Docker Containers${CN}"
    docker ps -a
}

echo -e "${CDR}>>>>> Process List${CN}"
# Dont display kernel threads
ps --ppid 2 -p 2 --deselect flwww

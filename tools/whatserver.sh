#! /usr/bin/env bash

# Script to quickly find juicy targets. Often used in combination with gsexecio to
# retrieve information from all hosts:
#  cat secrets.txt | parallel -j50 'cat ~/whatserver.sh | exec gsexecio {} >host_{}/whatserver.log 2>host_{}/whatserver.err'

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
uptime
id
HTTPS https://ipinfo.io
echo ""
echo -e "${CY}>>>>> Addresses${CN}"
echo "$inet"

# Ngingx sites
IFS=$'\n' arr=($(hostname))
[[ -d /etc/nginx ]] && {
    IFS=$'\t'$'\n'" " arr=($(grep -r -F "server_name " /etc/nginx | sed 's/.*server_name[ ]\+\(.*\);/\1/g' | sort -u))
}

# Apache sites
[[ -d /etc/httpd ]] && {
    IFS=$'\t'$'\n'" " arr+=($(grep -r -E '(:*ServerName[ ]+|:*ServerAlias[ ]+)' /etc/httpd | grep -v ':[ ]*#' | sed 's/.*:.*Server[a-zA-Z]\+[ ]\+\(.*\)/\1/g' | sort -u))
}

### Certificates
addcn() {
    local str="$1"
    [[ -z $str ]] && return
    [[ "$str" != *"."* ]] && return  # Not containing any .
    [[ "$str" == *"@"* ]] && return  # Is an email
    [[ "${arr[*]}" == *"$str"* ]] && return
    arr+=("$str")
}

addcert() {
    local fn="$1"
    local str
    [[ "$(openssl x509 -noout -in "$fn" -ext basicConstraints 2>/dev/null)" == *"CA:TRUE"* ]] && return
    str="$(openssl x509 -noout -in "$fn" -subject 2>/dev/null | sed '/^subject/s/^.*CN.*=[ ]*//g')"
    addcn "$str"
}

# Find where the certificates are stored:
unset certs
IFS=$'\n'
[[ -d /etc/nginx ]] && certs=($(find /etc/nginx -name '*.conf*' -exec grep -F "ssl_certificate " {} \; 2>/dev/null | awk '{print $NF;}' | sed 's/;$//' | sort -u))

# Any any file that sounds like a certificate
cert+=($(find /etc -name '*.crt' -o -name '*.pem' 2>/dev/null))

# Add all found certificate-files
for fn in "${lines[@]}"; do
    addcert "$fn"
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
        IFS=" "$'\t' arr+=($(echo "$x" | sed -E 's/[0-9.]+[ \t]+//'))
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
    ip n sh
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

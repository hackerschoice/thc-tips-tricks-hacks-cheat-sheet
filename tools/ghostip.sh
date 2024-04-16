#! /usr/bin/env bash

# Usage:
# ======
# source <(curl -fsSL https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet/raw/master/tools/ghostip.sh)
#
# A Linux tool to use a non existing IP address (aka GHOST-IP). It temporarily
# re-configures the current running shell: Any application started from that shell
# will use a Ghost-IP.
#
# A typical use case is to attack a target with nmap [et al.] from a host
# but using an IP address that is not assigned to that host.
# The nmap-scans will originate from the non-existing source IP (untraceable).
#
# Using it on a HOST/LAN-Spoofing: It uses an unused IP (aka Ghost-IP) from
# the LAN's network range. All traffic will originate from that Ghost-IP.
#
# Using it on a ROUTER/WAN-Spooing: It uses 1.0.0.2 to access any workstation
# within the LAN. The workstation will see the traffic originating from
# 1.0.0.2, whereas it really originates from the router (e.g. nmap running on
# the router, not on the spoofed IP of 1.0.0.2).
#
# This tool will fail on some VPS providers (like AWS) which don't allow
# ghost-IPs (IPs not registered to the host).
#
# Practiacal Scenarios:
# =====================
# We have access to a workstation. We like to scan the internal
# network but without the target seeing our workstation's IP address.
#
# We have access to a router. We like to scan the internal network
# (or multiple internal networks) but without the target seeing
# that the scan comes from within the internal network (we make it appear
# as if comming from 1.0.0.2 - an exteranl IP address).
#
# Notes:
# ======
# Ghost-route LAN & WAN taffic by default.
#
# GHOST_IP_WAN=
#     An unused IP address on the WAN facing Interface (the default route).
#     For HOSTS (not routers) this is a unused IP address of the LAN.
#     Find an IP Address automatcially if not set [default].
#     -1 to disable WAN ghosting.
#
# GHOST_IP_LAN=
#     The Ghost IP to use for traffic towards the LAN [default=1.0.0.2].
#     Only needed when GhostIP is used on a ROUTER (which typicallly has
#     a WAN and a LAN interface).
#     If set to a LAN address then ghost a single LAN interface only.
#     -1 to disable LAN ghosting.
#
# On a single host (not a router) only the GHOST_IP_WAN= is used.
#
# Complex Examples for HOSTS:
# ===========================
# Example 1: Ghost-route traffic towards the LAN & WAN:
#    appearing from 192.168.0.222 (an unused local LAN IP):
#    $ GHOST_IP_WAN=192.168.0.222 GHOST_IP_LAN=-1 source ./ghostip.sh
#
#
# Complex Examples for ROUTERS:
# =============================
# Example 2: Ghost-route traffic towards _all_ LANs,
#     appearing from 1.0.0.2 [default]
#     $ GHOST_IP_WAN=-1 source ./ghostip.sh
#
# Example 3: Ghost-route traffic towards _one_ specific LAN,
#    appearing from 172.17.0.99 (an unused local LAN IP):
#    $ GHOST_IP_WAN=-1 GHOST_IP_LAN=172.17.0.99 source ./ghostip.sh
#
# GHOST_NAME=update
#     The name of the cgroup. Must not exist.
#
# GHOST_IPT=
#     IPtables match of traffic that should be ghost-routed.
#     This is really only needed if the host is NOT a ROUTER _and_
#     the application is a proxy (like Wiretap, socks, gsnc, ..):
#     It allows the application to connect back to the C2 but all other
#     traffic by the application will be ghost-routed.
#
#     Do not ghost the C2 traffic:
#         GHOST_IPT="! -d 1.2.3.0/24"
#     Only ghost TCP:
#         GHOST_IPT="-p tcp"
#
# How it work:
# ============
# It createa a cgroup and iptable SNAT/DNAT rules for the cgroup. It then moves
# the current shell into the new cgroup. Any new programm started from that shell
# will use the Ghost-IP.
#
# This script can be sourced/evaled or executed as BASH or ZSH script.
# Some ninja to make it work on ZSH & BASH:
# - Bash arrays start at index #0, Zsh at index #1.
# - Array expansion differs between Bash and Zsh.
#   Try IFS="/" a=(${=HOME}) && echo "${#a[@]}" to understand.
#
# Some ideas stolen from novpn:
# https://gist.github.com/kriswebdev/a8d291936fe4299fb17d3744497b1170

if [ -n "$ZSH_EVAL_CONTEXT" ]; then
    [[ "$ZSH_EVAL_CONTEXT" =~ :file$ ]] && sourced=1
else
    (return 0 2>/dev/null) && sourced=1
fi

err() {
    echo -e >&2 "${CDR}ERROR: ${CN}$*"
}

# Find the Internet facing GW
ghost_find_gw() {
    local arr
    local IFS
    local l
    IFS=" " arr=($(ip route show match "1.1.1.1"))
    gw_dev="${arr[@]:4:1}"
    # gw_ip="${arr[@]:2:1}"

    # Get the device IP:
    l="$(ip addr show dev "$gw_dev" | grep -m1 'inet '))"
    l="${l##*inet }"
    l="${l%% *}"
    gw_dev_ip="${l%%/*}"
}

ghost_find_other() {
    local arr
    local IFS
    local d
    local i

    unset ghost_all_dev
    unset ghost_all_dev_ip

    [ "$GHOST_IP_LAN" == "-1" ] && return

    IFS=$'\n' arr=($(ip addr show))
    for l in "${arr[@]}"; do
        [[ "$l" =~ ^[0-9]+: ]] && {
            unset d
            unset i
            [[ "$l" != *"state UP"* ]] && continue
            [[ "$l" == *" master "* ]] && continue # Bridge master / veth
            d="${l#*:}"
            d="${d%%:*}"
            d="${d// /}"
            # Main Internet dev
            [ "$d" == "$gw_dev" ] && unset d
            [ "$d" == "lo" ] && unset d
            continue
        }
        [ -z "$d" ] && continue
        [[ "$l" == *"inet "* ]] && {
            l="${l##*inet }"
            i="${l%% *}"
            i="${i%%/*}"
            [ -z "$i" ] && continue
            ghost_all_dev+=("$d")
            ghost_all_dev_ip+=("$i")
            unset d
        }
    done
}

ghost_find_single() {
    local IFS
    local l
    local arr

    unset single_dev single_dev_ip
    [ -z "$ghost_ip" ] && return
    IFS=$'\n' arr=($(ip route show match "${ghost_ip:?}"))

    # Find the DEV for this IP
    for l in "${arr[@]}"; do
        [[ "$l" != *" scope link "* ]] && continue
        single_dev="${l##*dev }"
        single_dev="${single_dev%% *}"
        single_dev_ip="${l##*link src }"
        single_dev_ip="${single_dev_ip%% *}"
        break
    done
}

ghost_init() {
    local IFS=" "
    local classid="0xF0110011"
    local ipt_cgroup="cgroup2"

    [ -t 1 ] && {
        CDR="\e[0;31m" # red
        CDC="\e[0;36m" # cyan
        CDY="\e[0;33m" # yellow
        CY="\e[1;33m"  # yellow
        CDM="\e[0;35m" # magenta
        CDG="\e[0;32m" # green
        CF="\e[2m"     # faint
        CN="\e[0m"     # none
    }

    [ -z "$UID" ] && UID=$(id -u)
    [ "$UID" -ne 0 ] && { err "Must be root. Try ${CDC}sudo bash${CN} first."; return 255; }

    command -v iptables >/dev/null || { err "iptables: command not found. Try ${CDC}apt install iptables${CN}"; return 255; }
    GHOST_NAME="${GHOST_NAME:-update}"

    # Some iptables use '-m cgroup' when it should be '-m cgroup2'
    # https://www.spinics.net/lists/netdev/msg352495.html
    iptables -m "$ipt_cgroup" -h &>/dev/null || {
        ipt_cgroup="cgroup"
        iptables -m "$ipt_cgroup" -h &>/dev/null || { err "cgroup not supported by iptables [${CF}iptables -m cgroup -h${CN}]."; return 255; }
    }

    # Check for cgroup v1
    cg_root="/sys/fs/cgroup/net_cls"
    [ ! -f "${cg_root}/cgroup.procs" ] && cg_root="$(mount -t cgroup | grep net_cls | head -n1 | grep -oP '^cgroup on \K\S+')"
    [ ! -f "${cg_root}/cgroup.procs" ] && unset cg_root
    ipt_args=("-m" "cgroup" "--cgroup" "$classid")

    # Check for cgroup v2
    # First check if Userland tools support cgroup2
    if iptables -m "$ipt_cgroup" --help 2>&1 | grep -m1 -q -- --path; then
        cg_rootv2="/sys/fs/cgroup"
        [ ! -f "${cg_rootv2}/cgroup.procs" ] && cg_rootv2="/sys/fs/cgroup/unified"
        [ ! -f "${cg_rootv2}/cgroup.procs" ] && cg_rootv2="$(mount -t cgroup2 | head -n1 | grep -oP '^cgroup2 on \K\S+')"
        [ ! -f "${cg_rootv2}/cgroup.procs" ] && unset cg_rootv2
        [ -n "$cg_rootv2" ] && {
            cg_root="${cg_rootv2}"
            ipt_args=("-m" "$ipt_cgroup" "--path" "${GHOST_NAME:?}")
        }
    else
        [ -z "$cg_root" ] && {
            err "iptables expect cgroup1 but kernel does not support cgroup1"
            return 255
        }
    fi

    # ZSH/BASH compat (see notes above)
    ipt_args=($(echo "$GHOST_IPT") "${ipt_args[@]}")
    [ -z "$cg_root" ] && { err "No cgroup v1 or v2 found. Not possible to isolate an app to a ghost-IP."; return 255; }

    mkdir -p "${cg_root}/${GHOST_NAME}" 2>/dev/null
    [ -z "$cg_rootv2" ] && echo "$classid" >"${cg_root}/${GHOST_NAME}/net_cls.classid"
    return 0
}

# Add rule if not exist yet
iptnat() {
    local IFS
    local ins="$1"
    shift 1

    unset IFS
    GHOST_UNDO_CMD+=("iptables -t nat -D $*")
    iptables -t nat -C "$@" 2>/dev/null && return
    iptables -t nat "$ins" "$@" || return
}

if command -v arp >/dev/null; then
    is_arp_bad() { [[ "$(arp -n "$1")" == *"incomplete"* ]] && return; }
else
    is_arp_bad() {
        local str="$(ip neig sh "$1")"
        [[ "$str" == *"INCOMPLETE"* ]] && return
        [[ "$str" == *"FAILED"* ]] && return
    }
fi

# Find an unused IP Address on the LAN
ghost_find_local() {
    local arr
    local IFS
    local str
    local cidr
    local ipp
    local dev="${1:?}"
    local mode="${2}"

    IFS=" " arr=($(ip addr show dev "${dev:?}" | grep -m1 -F " inet "))
    str="${arr[@]:1:1}"
    cidr=${str##*/}
    ipp=${str%%/*}
    ipp=${ipp%.*}
    [ -z "$cidr" ] && cidr="24"
    [ "$cidr" -lt 24 ] && cidr="24"
    [ "$cidr" -gt 24 ] && return  # To bad. cant find automatically.
    for n in {0..10}; do
        # .0, .1 , .254, .255 should not be tried.
        d=$((RANDOM % 252 + 2))
        # ping -4 not supported on older versions
        ping -c2 -i1 -W2 -w2 -A -q "$ipp.$d" &>/dev/null || {
            is_arp_bad "$ipp.$d" && break
        }
        unset d
    done
    [ -z "$d" ] && return
    ghost_ip="$ipp.$d"
    echo -e "--> Using unused IP ${CDY}${ghost_ip}${CN}. Set ${CDC}GHOST_IP_${mode}=<IP>${CN} otherwise."
}

# orig-ip new-ip device
ghost_print() {
    local dev="$3                  "
    local ip="$2                  "
    echo -e "[${CDG}$4${CN}] ${CDM}Traffic leaving ${CDG}${dev:0:8}${CDM} will now appear as ${CY}${ip:0:16} ${CDY}${CF}[not $1]${CN}"
}

# ghost_single [LAN,WAN]
ghost_single() {
    local mode="$1"
    [ -z "$single_dev" ] && return 255
    [ -z "$single_dev_ip" ] && return 255

    [ -n "$ghost_ip" ] && [ -z "$single_dev" ] && { err "${CDC}GHOST_IP_${mode}=${CN} must be a local IP address [not ${ghost_ip}]"; return; }
    [ -z "$ghost_ip" ] && ghost_find_local "$single_dev" "$mode"
    [ -z "$ghost_ip" ] && {
        err "Set ${CDC}export GHOST_IP_${mode}=<IP>${CN} to a local and unused IP Address."
        return 255
    }

    iptnat -I POSTROUTING -o "${single_dev:?}"                  -m state --state NEW,ESTABLISHED    "${ipt_args[@]}" -j SNAT --to "${ghost_ip:?}" || { is_error=1; return; }
    # NO longer needed because we used -m state for outgoing.
    # iptnat -I PREROUTING  -i "${single_dev:?}" -d "${ghost_ip}" -m state --state ESTABLISHED,RELATED                 -j DNAT --to "${single_dev_ip:?}"

    # Block anyone connecting to our Ghost-IP:
    # We dont want to show in the INPUT chain. Instead route all invalid to 255.255.255.255 (linux will drop them):
    iptnat -I PREROUTING  -i "${single_dev}" -d "${ghost_ip}" -m state --state NEW -j DNAT --to 255.255.255.255

    # We must respond to ARP request to our Ghost-IP. The simplest is to add
    # the Ghost-IP to the same network interface. An alternative would be to
    # use "arp -i eth0 -Ds ${ghost_ip} eth0"
    ip addr add "${ghost_ip}/32" dev "${single_dev}" 2>/dev/null

    GHOST_UNDO_CMD+=("ip addr del ${ghost_ip}/32 dev ${single_dev}")
    ghost_print "${single_dev_ip}" "${ghost_ip}" "${single_dev}" "$mode"
    return 0
}

ghost_lan() {
    local n
    local d
    local ghost_ip
    local devip

    [ -n "$GHOST_IP_LAN" ] && {
        ghost_ip="${GHOST_IP_LAN}"
        ghost_find_single
        ghost_single "LAN"
        return
    }

    ghost_find_other
    [ ${#ghost_all_dev[@]} -le 0 ] && return

    # We like to keep the IPT rules to a min. Thus can't use connmark. Instead
    # pick a Ghost-IP that is not essential.
    # ghost_ip_default="104.17.25.14" # cdnjs.cloudflare.com
    ghost_ip="${GHOST_IP_LAN:-1.0.0.2}"

    iptnat -I POSTROUTING ! -o "${gw_dev:?}" -m state --state NEW,ESTABLISHED "${ipt_args[@]}" -j SNAT --to "${ghost_ip:?}" || { is_error=1; return; }
    n=0
    for d in "${ghost_all_dev[@]}"; do
        devip="${ghost_all_dev_ip[@]:$n:1}"
        ghost_print "${devip}" "${ghost_ip}" "${d}" "LAN"
        iptnat -I PREROUTING  -i "${d}" -d "${ghost_ip}" -m state --state ESTABLISHED,RELATED -j DNAT --to "${devip}"
        ((n++))
    done
    iptnat -I PREROUTING -d "${ghost_ip}" -m state --state NEW -j DNAT --to 0.0.0.0

    return 0
}

ghost_up2() {
    local ghost_ip

    ghost_find_gw || return

    [ "$GHOST_IP_LAN" != "-1" ] && { ghost_lan || return; }

    [ "$GHOST_IP_WAN" != "-1" ] && {
        ghost_ip="${GHOST_IP_WAN}"
        single_dev="$gw_dev"
        single_dev_ip="$gw_dev_ip"
     
        ghost_single "WAN"
        return
    }

    return 0
}

ghost_up() {
    local is_error

    ghost_down
    ghost_up2

    [ -n "$is_error" ] && {
        ghost_down
        err "Oops. This did not work..."
        return
    }

    # We cant exit yet if LAN or WAN was a success.
    if [ "${#GHOST_UNDO_CMD[@]}" -le 0 ]; then
        err "No WAN/LAN found. Check ${CDC}GHOST_IP_WAN=${CN} and ${CDC}GHOST_IP_LAN=${CN}."
        return
    fi

    [ -n "$GHOST_IPT" ] && echo -e "Traffic matching: ${CDG}${GHOST_IPT}${CN}"

    if [ -n "$sourced" ]; then
        echo "$$" >"${cg_root:?}/${GHOST_NAME}/cgroup.procs"
        [[ "$PS1" != *$'\n'* ]] && {
            GHOST_PS_BAK="$PS1"
            PS1="${PS1//\\h/\\h-GHOST}"
            [ "$PS1" == "$GHOST_PS_BAK" ] && unset GHOST_PS_BAK
        }
        # sfwg support
        export TYPE=wiretap
        echo -e "\
--> Your current shell (${SHELL##*/}/$$) and any further process started
    from this shell are now ghost-routed.
--> To ghost-route new connections of an already running process:
    ${CDC}"'echo "<PID>" >"'"${cg_root:?}/${GHOST_NAME}/cgroup.procs"'"'"${CN}
To UNDO type ${CDC}ghost_down${CN} or:${CF}"
        [ -n "$GHOST_PS_BAK" ] && echo "PS1='$GHOST_PS_BAK'"
    else
        echo -e "\
--> To ghost-route the current shell and all processes started from
    this shell:
    ${CDC}"'echo "$$" >"'"${cg_root:?}/${GHOST_NAME}/cgroup.procs"'"'"${CN}
--> To ghost-route new connections of an already running process:
    ${CDC}"'echo "<PID>" >"'"${cg_root:?}/${GHOST_NAME}/cgroup.procs"'"'"${CN}
To UNDO type:${CF}"
    fi

    for c in "${GHOST_UNDO_CMD[@]}"; do
        echo "$c";
    done
    [ -n "$sourced" ] && echo "unset GHOST_UNDO_CMD GHOST_PS_BAK TYPE"
    echo -en "${CN}"
}

ghost_down() {
    local c

    [ -n "$GHOST_PS_BAK" ] && PS1="$GHOST_PS_BAK"
    for c in "${GHOST_UNDO_CMD[@]}"; do
        eval "$c" &>/dev/null
    done
    unset GHOST_PS_BAK
    unset GHOST_UNDO_CMD
}

ghost_init && \
ghost_up

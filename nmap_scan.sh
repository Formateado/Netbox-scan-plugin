#!/bin/bash

for net in "$@" # Remove for cycle
do
    NETNAME=$(echo $net | tr -s '/' '-')
    echo $NETNAME
    OUTPUT="./scans/scan-$NETNAME.xml"

    nmap "$net" -T4 -O --system-dns --host-timeout 30s -oX $OUTPUT
done

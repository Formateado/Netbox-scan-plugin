i#!/bin/bash


PREFIX=$1
NETNAME=$(echo $PREFIX | tr -s '/' '-')
OUTPUT="./scans/scan-$NETNAME.xml"

nmap -sn -PE "$PREFIX" -oG - | awk '/Up$/{print $2}' > tmp_file.txt
nmap -iL tmp_file.txt -T4 -O --system-dns --host-timeout 30s -oX $OUTPUT

rm tmp_file.txt

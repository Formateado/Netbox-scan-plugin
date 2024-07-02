#!/usr/bin/bash

TODAY="$(date +%Y%m%d_%H%M%S)"

cd ./scans || exit

tar -czvf nmap-"$TODAY".tar.gz *.xml
rm -rf *.xml

cd ..

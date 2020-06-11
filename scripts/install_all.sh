#!/bin/sh

./cscli -c dev.yaml list parsers -a -o json | jq -r ".[].name" > installed_parsers.txt
cat installed_parsers.txt | while read parser; do
    echo "install ${parser}" ;
    ./cscli -c dev.yaml install parser ${parser} ;
done

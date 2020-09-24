#!/bin/sh

./cscli -c dev.yaml list parser list -a -o json | jq -r ".[].name" > installed_parsers.txt
cat installed_parsers.txt | while read parser; do
    echo "install ${parser}" ;
    ./cscli -c dev.yaml parser install ${parser} ;
done

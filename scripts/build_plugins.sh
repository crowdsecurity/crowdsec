#!/bin/bash

PLUGIN_DIR="./plugins/"


goto() {
    echo "[*] Going to $1"
    cd $1
}


goto $PLUGIN_DIR
CURRENT_DIR=$(pwd)
for path in $(ls);
do
    goto $path
    modules=$(find . -name "*.go")
    CURRENT_PLUGDIN_DIR=$(pwd)
    for mod in $modules;
    do
        folder=$(dirname $mod) 
        plugin_file=$(basename -- "$mod")
        plugin_name=(${plugin_file%.*})
        echo "[*] Building plugin $plugin_name from $mod"
        go build -buildmode=plugin -o "$plugin_name.so" $plugin_file
        goto $CURRENT_PLUGDIN_DIR
    done
    goto $CURRENT_DIR
done
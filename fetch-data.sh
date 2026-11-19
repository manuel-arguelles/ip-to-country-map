#!/usr/bin/env bash

ROUTER="root@192.168.1.1"
COMMAND="nft list set inet fw4 scanner_v4"
INPUTDIR="input/"

mkdir -p $INPUTDIR

fetch_data() {
    local -r file="ips-$(date -Iminutes).txt"

    ssh $ROUTER "$COMMAND" | grep -Po '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' | awk -F' ' '{print $1}' > "$INPUTDIR/$file"
}

fetch_data

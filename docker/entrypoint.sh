#!/bin/bash

if [ ! -d "/home/netos/tools/eclipseclp" ]; then
    echo "Warning. EclipseCLP is not present."
fi

cd /source

if [ "$1" == "" ]; then
    exec "/bin/bash" 
else
    exec "$@" 
fi

#!/bin/bash

##########################################################################
# Copyright (c) 2019, ETH Zurich.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.
# If you do not find this file, copies can be found by writing to:
# ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
##########################################################################

# configuragion. Note BF_SOURCE and BF_BUILD must be absolute paths!
BF_SOURCE=$(readlink -f `dirname $0`)
BF_BUILD=$BF_SOURCE/build
BF_DOCKER=bf-gitlab-ci-runner
#BF_DOCKER=achreto/barrelfish-ci
BF_CMD="$@"

echo "bfdocker: $BF_DOCKER"
echo "bfsrc: $BF_SOURCE  build: $BF_BUILD"
echo "bfcmd: $BF_CMD"

# create the build directory
mkdir -p $BF_BUILD

if [ $# == 0 ]; then
    exit
fi

# run the command in the docker image
docker run --rm --privileged -i -t \
    -v $BF_SOURCE:/source \
    -v $BF_BUILD:/source/build \
    $BF_DOCKER /bin/bash -c "(cd /source/build && $BF_CMD)"

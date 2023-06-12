#!/usr/bin/env bash

set -eu

DEVICE_ID=${1}
LIB_PATH=${2}

BUSYBOX_BASE=/data/local/tmp/busybox
BUSYBOX_BIN=$BUSYBOX_BASE/

adb -s ${DEVICE_ID} shell "mkdir -p $BUSYBOX_BASE"
adb -s ${DEVICE_ID} push /busybox/arm64/bin/busybox $BUSYBOX_BASE

python -m caid -w /inout/ ${LIB_PATH} ${DEVICE_ID}

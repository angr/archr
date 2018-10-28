#!/bin/sh

ulimit -c unlimited
ulimit -f unlimited

OUR_DIR=$(dirname $0)
QEMU_VARIANT=$1
shift
exec $OUR_DIR/ld-linux-* --library-path $OUR_DIR ./$QEMU_VARIANT "$@"

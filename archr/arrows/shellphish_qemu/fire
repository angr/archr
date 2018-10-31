#!/bin/sh -x

ulimit -c unlimited
ulimit -f unlimited

echo "$@" > /tmp/commands

OUR_DIR=$(dirname $0)
TMP_DIR=$1
shift
QEMU_VARIANT=$1
shift
mkdir -p $TMP_DIR
cd $TMP_DIR
exec $OUR_DIR/ld-linux-* --library-path $OUR_DIR $OUR_DIR/$QEMU_VARIANT "$@"

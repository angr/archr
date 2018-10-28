#!/bin/bash

[ $# -ge 1 ] || { echo "Usage: $0 /path/to/tarball"; exit 1; }

FIRE_SCRIPT=${0//bundle/fire}
QEMU_PATH=$(python -c "import shellphish_qemu; print(shellphish_qemu.qemu_base())")
QEMU_LIBS=$(ldd $QEMU_PATH/* | grep "=>" | awk '{print $3}' | sort -u)
QEMU_LD=$(ldd $QEMU_PATH/shellphish-qemu-cgc-base | tail -n1 | awk '{print $1}')
BUNDLE_DIR=$(mktemp -d)
cp -L $QEMU_PATH/* $QEMU_LIBS $QEMU_LD $BUNDLE_DIR
cp -L $FIRE_SCRIPT $BUNDLE_DIR/fire
tar cf $1 -C $BUNDLE_DIR .

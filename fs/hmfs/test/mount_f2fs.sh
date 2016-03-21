#!/bin/bash

# create a 100M file
dd if=/dev/zero of=/opt/dev0-backstore bs=1M count=100

# create the loopback block device
mknod /dev/fake-dev0 b 7 200

losetup /dev/fake-dev0 /opt/dev0-backstore
mount -t f2fs /dev/fake-dev0 ~/mount_f2fs/
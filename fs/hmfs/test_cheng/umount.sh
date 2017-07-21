#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
password="cwy12345"
echo $password | sudo -S umount $WORK_DIR
echo "umount succeeded!"
echo -e "\nResult of the mount command:"
mount | grep hmfs
echo -e "\nResult of the df -lh command:"
df -lh


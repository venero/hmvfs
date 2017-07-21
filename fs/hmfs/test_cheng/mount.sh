#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
password="cwy12345"

echo $password | sudo mount -t hmfs -o physaddr=0x40000000,init=2G,gid=1000,uid=1000 none $WORK_DIR
echo "Mount succeeded!"
echo -e "\nResult of the mount command:"
mount | grep hmfs
echo -e "\nResult of the df -lh command:"
df -lh


#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
DEBUG_DIR="/sys/kernel/debug/hmfs/1073741824"

echo "usage: ./delete_version.sh version_number"
cd $DEBUG_DIR
echo "cp d $1" >info & cat info 
echo "version $1 deleted!"


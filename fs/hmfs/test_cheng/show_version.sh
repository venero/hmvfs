#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
DEBUG_DIR="/sys/kernel/debug/hmfs/1073741824"

echo "Version information now:"
cd $DEBUG_DIR
echo "cp a" >info & cat info 
echo "FIles in $WORK_DIR:"
ls $WORK_DIR




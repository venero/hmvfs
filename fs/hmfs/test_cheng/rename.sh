#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
num_file=100

for ((i=0; i<$num_file; i++)); do
    touch ${WORK_DIR}test_file_$i.txt
done

echo "File in $WORK_DIR before rename:"
ls -li $WORK_DIR

cmd="rename"
while true;do
read Arg
if [ "$Arg"x = "$cmd"x ];then
    break
fi
done

rename s/file/fileRename/ ${WORK_DIR}test_file*.txt

echo "$num_file files renamed..."

echo "File in $WORK_DIR after rename:"
ls -li $WORK_DIR





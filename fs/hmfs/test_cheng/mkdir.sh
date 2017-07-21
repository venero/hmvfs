#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
num_dir=200

echo "File in $WORK_DIR before creation:"
ls $WORK_DIR

for ((i=0; i<$num_dir; i++)); do
    mkdir ${WORK_DIR}test_dir_$i
done

echo "$num_dir directories created..."

echo "File in $WORK_DIR after creation:"
ls $WORK_DIR


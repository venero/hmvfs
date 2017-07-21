#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
num_dir=200

echo "File in $WORK_DIR before deletion:"
ls $WORK_DIR

for ((i=0; i<$num_dir; i++)); do
    rm -rf ${WORK_DIR}test_dir_$i
done

echo "$num_dir directories deleted..."

echo "File in $WORK_DIR after deletion:"
ls $WORK_DIR


#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
num_file=200

echo "File in $WORK_DIR before creation:"
ls $WORK_DIR

#create testing files, they will be orphan files later
for ((i=0; i<$num_file; i++)); do
    touch ${WORK_DIR}test_file_${i}.txt
done

echo "$num_file files created..."

echo "File in $WORK_DIR after creation:"
ls $WORK_DIR


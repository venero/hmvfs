#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
num_file=200


for ((i=0; i<$num_file; i++)); do
    echo "diff for file $i:"
    diff $1 ${WORK_DIR}test_file_$i.txt
done


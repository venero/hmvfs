#!/bin/bash

num_file=200
WORK_DIR="/home/weiyu/mnt-hmfs/"

echo "Files in $WORK_DIR before deletion:"
ls $WORK_DIR

for ((i=0; i<$num_file; i++)); do
    #remove the file will create an orhan file
    rm ${WORK_DIR}test_file_$i.txt
done

echo "$num_file files deleted..."

echo "Files in $WORK_DIR after deletion:"
ls $WORK_DIR

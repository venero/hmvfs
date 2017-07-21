#!/bin/bash

WORK_DIR="/home/weiyu/mnt-hmfs/"
num_file=100

echo "File in $WORK_DIR before creation:"
ls -li $WORK_DIR

for ((i=0; i<$num_file; i++)); do
    touch ${WORK_DIR}test_file_$i.txt
    ln ${WORK_DIR}test_file_$i.txt ${WORK_DIR}test_file_${i}_link.txt
done

echo "$num_file links created..."

echo "File in $WORK_DIR after creation:"
ls -li $WORK_DIR

cmd="unlink"
while true;do
read Arg
echo "$Arg"
if [ "$Arg"x = "$cmd"x ];then
    break
fi
done

for ((i=0; i<$num_file; i++)); do
    rm ${WORK_DIR}test_file_${i}_link.txt
done

echo "$num_file links deleted..."

echo "File in $WORK_DIR after deletion:"
ls -li $WORK_DIR





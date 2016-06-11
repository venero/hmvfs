#!/bin/bash

# test remove checkpoints
DIR="/home/goku/mnt-hmfs/"	#Mount ppoint of tested HMFS instance
THREAD=8
NUM=1000000

function create_files()
{
	for i in $(seq $1 $2 $3); do
		touch $DIR$i
#		echo "touch "$i
	done
}

for i in $(seq $THREAD); do
	$(create_files $i $THREAD $NUM)&
done

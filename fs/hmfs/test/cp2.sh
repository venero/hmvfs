#!/bin/bash

# test remove checkpoints
DIR="/home/goku/mnt-hmfs"	#Mount ppoint of tested HMFS instance
NUM=100000

function rand()
{
	ret=$RANDOM$RANDOM;
	max=$2-$1
	((ret=ret%max+$1))
	echo $ret
}

cd $DIR

for i in $(seq $NUM); do
	((mode=$RANDOM%100))
	if [ $mode -eq 0 ];then
		flag=0
		for file in `ls`; do
			((size=$RANDOM%1024))
			if [ $flag -eq 0 ];then
				truncate --size $size $file
				flag=1
			else
				echo `perl -e "print 'q'x$size"` >> $file
				flag=0
			fi
		done
		continue
	fi
	if [ $mode -gt 60 ];then
		touch $RANDOM
	else
		file=$RANDOM
		if [ -f $file ];then
			rm $file
		else
			touch $file
		fi
	fi
	sync
	echo $i
done

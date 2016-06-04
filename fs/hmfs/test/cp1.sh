#!/bin/bash

# test remove checkpoints
DIR="/home/goku/mnt-hmfs"	#Mount ppoint of tested HMFS instance
MODULE="hmfs"				#Name of compiled HMFS module
CONTENT="/home/goku/workspace/hmfs/fs/hmfs/test/content" #Path of content which is source of text for testing
PHYSADDR="0x100000000"		#Physical address of HMFS
INITSIZE="6G"				#initial size of HMFS

internal=8					# version number to test roll back

if [ ! -d $DIR ]; then
	mkdir $DIR
fi
rm "$DIR"/* 2> /dev/null
is_mount=`df -T |awk 'sprintf("%s",$7)==DIR {print $7}' DIR="$DIR"` 
echo $is_mount
if [ -n "$is_mount" ]; then
	is_mount=`df -T |awk 'sprintf("%s",$2)==MODULE&&sprintf("%s",$7)==DIR {print $7}' MODULE="$MODULE" DIR="$DIR"`
	if [ -n "$is_mount" ]; then
		umount $DIR
		if [ $? -ne 0 ]; then
			echo "Fail to umount original HMFS instance:"$DIR
			exit
		fi
	fi
fi
is_load=`lsmod|grep $MODULE`
if [ -n "$is_load" ]; then
	rmmod $MODULE
	if [ $? -ne 0 ]; then
		exit
	fi
fi
cd ..
./make.sh > /dev/null
if [ $? -ne 0 ]; then
	exit
fi
insmod $MODULE".ko"
if [ $? -ne 0 ]; then
	exit
fi
mount -t hmfs -o physaddr=$PHYSADDR,init=$INITSIZE none $DIR
if [ $? -ne 0 ]; then
	exit
fi
cd $DIR

function rand()
{
	ret=$RANDOM$RANDOM;
	max=$2-$1
	((ret=ret%max+$1))
	echo $ret
}

function rand_str()
{
#	ofs=$RANDOM
#	ret=`dd if=$CONTENT skip=$ofs bs=1 count=$1 2> /dev/null`
#	echo $ret
	echo `perl -e "print 'q'x$1"`
}

file_append=$DIR"/append"
file_truncate=$DIR"/truncate"

function create_new()
{
	a_sz=$(rand 1024 4096)
	echo $(rand_str $a_sz) >> $file_append
		
	t_sz=$(rand 10240 409600)
	echo $(rand_str $t_sz) > $file_truncate

	#create new files
	nr_new=$(rand 10 20)
	for j in $(seq 1 $nr_new)
	do
		filename=$DIR"/"$1"."$j
		sz=$(rand 4096 409600)
		echo $(rand_str $sz)>$filename
#		echo "touch "$filename,$sz
	done
	if [ $1 -gt 2 ]; then
		((last=$i-1))
		for j in $(seq 2 $last)
		do
			filename=$DIR"/"$j"."$(rand 0 20)
			if [ -f $filename ]; then
				rm $filename
				#echo "rm "$filename
			fi
		done
	fi
	sync
}

function echo_red()
{
	echo -e "\033[31m"$1"\033[0m"
}

function echo_green()
{
	echo -e "\033[32m"$1"\033[0m"
}

cp_time=$(rand 10 20);
echo "Checkpoint Test Cases:"$cp_time

#checkpoint 1 is the first checkpoint
for i in $(seq 2 $internal)
do
#	echo "cp "$i
	create_new $i
done
cp8_md5=`cat *|md5sum`
((next=$internal+1))
for i in $(seq $next $cp_time)
do
#	echo "cp "$i
	create_new $i
done
new_md5=`cat *|md5sum`

#
cd /sys/kernel/debug/hmfs/4294967296/
count=0;
while [[ $count -lt $internal ]];
do
	i=$(rand 1 $internal);
	if [ $i -eq $internal ]; then
		continue
	fi
	echo "cp d "$i > info
	ret=`cat info`
#	echo "delete checkpoint "$i
	((count=$count+1))
done

# read-only roll back to checkpoint 8
umount $DIR
mount -t hmfs -o physaddr=$PHYSADDR,ro,mnt_cp=$internal none $DIR
cd $DIR
check_md5=`cat *|md5sum`
#echo $cp8_md5
#echo $check_md5
if [[ $cp8_md5 = $check_md5 ]]; then
	echo_green "Roll back test pass,"$cp8_md5
else
	echo_red "Roll back test fail"
fi
#delete all previous checkpoints
cd ..
umount $DIR
mount -t hmfs -o physaddr=$PHYSADDR none $DIR
if [ $? -ne 0 ]; then
	echo "Fail to mount HMFS"
	exit
fi

cd /sys/kernel/debug/hmfs/4294967296/
for i in $(seq 1 19)
do
	echo "cp d "$i > info
	#echo "delete checkpoint "$i
	ret=`cat info`
done
umount $DIR
mount -t hmfs -o physaddr=$PHYSADDR none $DIR
if [ $? -ne 0 ]; then
	echo "Fail to mount HMFS"
	exit
fi
cd $DIR
check_md5=`cat *|md5sum`
#echo $new_md5
#echo $check_md5
if [[ $new_md5 != $check_md5 ]]; then
	echo_red "Delete checkpoint test fail,"
else
	echo_green "Delete checkpoint test pass,"$check_md5
fi
cd ..
umount $DIR

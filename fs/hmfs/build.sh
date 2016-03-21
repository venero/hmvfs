#!/bin/bash

if [ "$1" == "hmfs" ] 
    then
    insmod ./hmfs.ko 
    sudo mount -t hmfs -o physaddr=0x4B000000,init=100M none ~/mount_hmfs/
elif [ "$1" == "nohmfs" ] 
    then
    umount ~/mount_hmfs
    rmmod hmfs
fi
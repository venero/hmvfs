#!/bin/bash

num_file=2048
for ((i=0; i<$num_file; i++)); do
    #remove the file will create an orhan file
    rm ~/mount_hmfs/orphan_$i.txt
done

echo "$num_file files deleted..."

#check the cmi info
. ./info.sh "cmi"

#sync the file to enforce doing checkpoint
sync

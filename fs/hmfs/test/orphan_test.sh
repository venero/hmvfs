#!/bin/bash

num_file=2048
cd ~/mount_hmfs/

#create testing files, they will be orphan files later
for ((i=0; i<$num_file; i++)); do
    touch orphan_$i.txt
    echo "this is a test file" > orphan_$i.txt
done

echo ${num_file} "file created"

#python3 $HOME/hmfs/fs/hmfs/test/hold_file_open.py &

#for ((i=0; i<$num_file; i++)); do
    #remove the file will create an orhan file
#    rm orphan_$i.txt
#done

#cd $HOME/hmfs/fs/hmfs/test/
#check the cmi info
#. ./info.sh "cmi"

#sync the file to enforce doing checkpoint
#sync






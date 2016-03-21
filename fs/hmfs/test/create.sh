#!/bin/bash

num_file=2048

#create testing files, they will be orphan files later
for ((i=0; i<$num_file; i++)); do
    touch ~/mount_hmfs/orphan_$i.txt
    echo "this is a test file" > ~/mount_hmfs/orphan_$i.txt
done

echo "$num_file files created..."
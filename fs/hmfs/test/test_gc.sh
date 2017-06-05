# make checkpoints

# delete checkpoints
root="debug_root"
path=/sys/kernel/debug/hmfs/$root/info
for i in `seq 1 100`
do
    echo "cp d $i" > $path
    cat $path
    sleep 1
done

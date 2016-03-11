hmfs_300M_2G:
	sudo mount -t hmfs -o physaddr=0x80000000,uid=1000,gid=1000,init=140M none ~/hmfsMount/
hmfs_300M_2G_deep:
	sudo mount -t hmfs -o physaddr=0x80000000,uid=1000,gid=1000,init=140M,deep_fmt=1 none ~/hmfsMount/
hmfs_300M_2G_remount:
	sudo mount -t hmfs -o physaddr=0x80000000,uid=1000,gid=1000 none ~/hmfsMount/
hmfs_1G_2G:
	sudo mount -t hmfs -o physaddr=0x80000000,uid=1000,gid=1000,init=1G none ~/hmfsMount/
ins_print:
	sudo insmod $(PRINTPATH)/printt.ko
rm_print:
	sudo rmmod printt
ins_hmfs:
	sudo insmod ./hmfs.ko 
rm_hmfs:
	sudo rmmod hmfs
mount_hmfs:
	sudo mount -t hmfs -o physaddr=0xc0000000,init=40M none ~/hmfsMount/
hmfs:
	sudo insmod ./hmfs.ko && sudo mount -t hmfs -o physaddr=0xc0000000,init=40M none ~/hmfsMount/
nohmfs:
	sudo umount ~/hmfsMount && sudo rmmod hmfs

hmfs_300M_2G:
	sudo mount -t hmfs -o physaddr=0x80000000,init=140M none ~/hmfsMount/
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

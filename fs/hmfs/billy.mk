
	
ins_print:
	sudo insmod $(PRINTPATH)/printtty.ko
ins_hmfs:
	sudo insmod ./hmfs.ko 
mount_hmfs:
	sudo mount -t hmfs -o physaddr=0xc0000000,init=40M none ~/hmfs/
hmfs:
	sudo insmod ./hmfs.ko && sudo mount -t hmfs -o physaddr=0xc0000000,init=40M none ~/hmfsMount/
nohmfs:
	sudo umount ~/hmfsMount && sudo rmmod hmfs

# BILLY: 
#PRINTPATH := /data/jinzha/wheels/printtty
#KBUILD_EXTRA_SYMBOLS := $(PRINTPATH)/Module.symvers

# hhmfs build 
obj-m += hmfs.o
hmfs-y := super.o


all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean



#TODO : source following commands to a test Makefile

nohmfs:
	sudo umount ~/hmfs && sudo rmmod hmfs
insprint:
	sudo insmod PRINTPATH/printty.ko
ins_hmfs:
	sudo insmod ./hmfs.ko 
mount_hmfs:
	sudo mount -t hmfs -o physaddr=0xc0000000,init=40M none ~/hmfs/

wrong_hmfs:
#	sudo mount -t phmfs -o physaddr=0x80000000,init=298M none ~/hmfs/
	sudo insmod ./hmfs.ko && sudo mount -t hmfs -o physaddr=0x100000000,init=40M none ~/hmfs/
	

hmfs:
	sudo insmod ./hmfs.ko && sudo mount -t hmfs -o physaddr=0xc0000000,init=40M none ~/hmfs/



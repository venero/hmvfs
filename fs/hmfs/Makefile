//KBUILD_EXTRA_SYMBOLS:=/data/jinzha/wheels/printtty/Module.symvers
-include ./billy.mk
obj-m += hmfs.o
hmfs-objs := super.o debug.o node.o inode.o checkpoint.o file.o data.o namei.o segment.o hash.o dir.o symlink.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean


wrong_hmfs:
#	sudo mount -t phmfs -o physaddr=0x80000000,init=298M none ~/hmfs/
	sudo insmod ./hmfs.ko && sudo mount -t hmfs -o physaddr=0x100000000,init=40M none ~/hmfs/


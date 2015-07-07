obj-m += hmfs.o
hmfs-objs := super.o debug.o
all:
	make -C /lib/modules/`uname -r`/build M=`pwd`
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean

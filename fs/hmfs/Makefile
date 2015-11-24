ccflags-y += -DCONFIG_HMFS_DEBUG
obj-m += hmfs.o
hmfs-objs := super.o debug.o node.o inode.o checkpoint.o file.o data.o namei.o segment.o hash.o dir.o symlink.o gc.o
-include billy.mk

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean

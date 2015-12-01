ccflags-y += -DCONFIG_HMFS_DEBUG
ccflags-y += -DCONFIG_HMFS_XATTR
ccflags-y += -DCONFIG_HMFS_FAST_READ
obj-m += hmfs.o
hmfs-objs := super.o debug.o node.o inode.o checkpoint.o file.o data.o namei.o segment.o hash.o dir.o symlink.o gc.o xattr.o util.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean

ccflags-y += -DCONFIG_HMFS_DEBUG
ccflags-y += -DCONFIG_HMFS_DEBUG_GC
ccflags-y += -DCONFIG_HMFS_XATTR
#ccflags-y += -DCONFIG_HMFS_FAST_READ
ccflags-y += -DCONFIG_HMFS_ACL
ccflags-y += -DCONFIG_HMFS_DEBUG_RW_LOCK

obj-m += hmfs.o

hmfs-objs := super.o node.o inode.o checkpoint.o file.o data.o namei.o segment.o hash.o dir.o symlink.o gc.o recovery.o
hmfs-objs += debug.o
hmfs-objs += xattr.o
hmfs-objs += util.o
hmfs-objs += acl.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean

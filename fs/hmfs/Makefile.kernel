ccflags-y	:= -O0
obj-$(CONFIG_HMFS_FS) += hmfs.o

hmfs-y := super.o node.o inode.o checkpoint.o file.o data.o namei.o segment.o hash.o dir.o symlink.o gc.o recovery.o vmap.o initfs.o util.o proc.o

hmfs-$(CONFIG_HMFS_DEBUG) += debug.o
hmfs-$(CONFIG_HMFS_XATTR) += xattr.o
hmfs-$(CONFIG_HMFS_ACL) += acl.o


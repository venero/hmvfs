#include "hmfs.h"

const struct inode_operations hmfs_file_inode_operations;
const struct inode_operations hmfs_dir_inode_operations={
.lookup=simple_lookup,
.link=simple_link,
.rmdir=simple_rmdir,
.rename=simple_rename,
};
const struct inode_operations hmfs_symlink_inode_operations;
const struct inode_operations hmfs_special_inode_operations;

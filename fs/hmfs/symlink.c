#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/namei.h>
#include "hmfs_fs.h"
#include "hmfs.h"

int hmfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct inode *inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(dir);
	void *data_blk;
	size_t symlen = strlen(symname) + 1;

	if (symlen > HMFS_MAX_SYMLINK_NAME_LEN)
		return -ENAMETOOLONG;

	inode = hmfs_make_dentry(dir, dentry, S_IFLNK | S_IRWXUGO);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &hmfs_symlink_inode_operations;
	inode->i_mapping->a_ops = &hmfs_aops_xip;

	data_blk = alloc_new_data_block(sbi, inode, 0);
	if (IS_ERR(data_blk))
		return PTR_ERR(data_blk);
	hmfs_memcpy(data_blk, (void *)symname, symlen);

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	return 0;
}

static int hmfs_readlink(struct dentry *dentry, char __user * buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	void *data_blk;

	inode_read_lock(inode);
	data_blk = get_data_block(inode, 0);
	inode_read_unlock(inode);
	if (IS_ERR(data_blk)) {
		return -ENODATA;
	}
	return vfs_readlink(dentry, buffer, buflen, data_blk);

}

static void *hmfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	void *data_blk;

	inode_read_lock(inode);
	data_blk = get_data_block(inode, 0);
	inode_read_unlock(inode);
	if (IS_ERR(data_blk)) {
		return ERR_PTR(-ENODATA);
	}
	nd_set_link(nd, data_blk);
	return 0;
}

const struct inode_operations hmfs_symlink_inode_operations = {
	.readlink = hmfs_readlink,
	.follow_link = hmfs_follow_link,
	.getattr = hmfs_getattr,
	.setattr = hmfs_setattr,
	.get_acl = hmfs_get_acl,
#ifdef CONFIG_HMFS_XATTR
	.setxattr = generic_setxattr,
	.getxattr = generic_getxattr,
	.listxattr = hmfs_listxattr,
	.removexattr = generic_removexattr,
#endif 
};

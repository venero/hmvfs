#include <linux/fs.h>
#include "hmfs.h"
#include "hmfs_fs.h"
static struct inode *hmfs_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	nid_t ino;
	struct inode *inode;
	int err;
	bool nid_free = false;
	struct hmfs_inode_info *i_info;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	printk(KERN_INFO "new inode:%d\n",
	       is_inode_flag_set(HMFS_I(inode), FI_NEW_INODE));

	if (!alloc_nid(sbi, &ino, NULL)) {
		err = -ENOSPC;
		goto fail;
	}

	inode->i_uid = current_fsuid();

	if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else {
		inode->i_gid = current_fsgid();
	}

	inode->i_ino = ino;
	inode->i_mode = mode | HMFS_DEF_FILE_MODE;
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	if (S_ISDIR(mode)) {
		set_inode_flag(HMFS_I(inode), FI_INC_LINK);
		inode->i_size = HMFS_PAGE_SIZE;
	} else {
		inode->i_size = 0;
	}

	err = insert_inode_locked(inode);
	if (err) {
		err = -EINVAL;
		nid_free = true;
		goto out;
	}
	//TODO: sync with nvm
	i_info = HMFS_I(inode);
	i_info->i_pino = dir->i_ino;
	err = sync_hmfs_inode(inode);
	printk(KERN_INFO "allocate new inode:%lu, result:%d\n", inode->i_ino,
	       err);
	if (!err)
		return inode;
out:
	clear_nlink(inode);
	unlock_new_inode(inode);
fail:
	make_bad_inode(inode);
	iput(inode);
	if (nid_free)
		alloc_nid_failed(sbi, ino);
	return ERR_PTR(err);
}

static struct inode *hmfs_make_dentry(struct inode *dir, struct dentry *dentry,
				      umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct inode *inode;
	int err = 0;

	inode = hmfs_new_inode(dir, mode);
	printk(KERN_INFO "add link:%d\n", PTR_ERR(inode));
	if (IS_ERR(inode))
		return inode;
	err = hmfs_add_link(dentry, inode);
	printk(KERN_INFO "instantiate:%d\n", err);
	if (err)
		goto out;
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);
	return inode;
out:
	clear_nlink(inode);
	unlock_new_inode(inode);
	make_bad_inode(inode);
	iput(inode);
	alloc_nid_failed(sbi, inode->i_ino);
	return ERR_PTR(err);
}

static int hmfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		      dev_t rdev)
{
	struct inode *inode;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	inode = hmfs_make_dentry(dir, dentry, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, inode->i_mode, rdev);
	inode->i_op = &hmfs_special_inode_operations;

	return 0;
}

static int hmfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	struct inode *inode;

	inode = hmfs_make_dentry(dir, dentry, mode);
	printk(KERN_INFO "make entry\n");
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	printk(KERN_INFO "make success\n");
	inode->i_op = &hmfs_file_inode_operations;
	inode->i_fop = &hmfs_file_operations;
	inode->i_mapping->a_ops = &hmfs_dblock_aops;

	return 0;
}

static int hmfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	inode = hmfs_make_dentry(dir, dentry, S_IFDIR | mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &hmfs_dir_inode_operations;
	inode->i_fop = &hmfs_dir_operations;
	inode->i_mapping->a_ops = &hmfs_dblock_aops;
	return 0;
}

static struct dentry *hmfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct inode *inode = NULL;
	struct hmfs_dir_entry *de;

	if (dentry->d_name.len > HMFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	de = hmfs_find_entry(dir, &dentry->d_name);
	if (de) {
		inode = hmfs_iget(dir->i_sb, de->ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

const struct inode_operations hmfs_file_inode_operations;

const struct inode_operations hmfs_dir_inode_operations = {
	.create = hmfs_create,
	.mkdir = hmfs_mkdir,
	.mknod = hmfs_mknod,
	.lookup = hmfs_lookup,
	.link = simple_link,
	.rmdir = simple_rmdir,
	.rename = simple_rename,
};

const struct inode_operations hmfs_symlink_inode_operations;
const struct inode_operations hmfs_special_inode_operations;

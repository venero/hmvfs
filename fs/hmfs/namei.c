#include <linux/fs.h>
#include "hmfs.h"
#include "hmfs_fs.h"

static struct inode *hmfs_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_inode_info *i_info;
	struct inode *inode;
	nid_t ino;
	int err, ilock;
	bool nid_free = false;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!alloc_nid(sbi, &ino)) {
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
	} else if (S_ISLNK(mode)) {
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
	i_info = HMFS_I(inode);
	i_info->i_pino = dir->i_ino;
	update_nat_entry(nm_i, ino, ino, NEW_ADDR, CM_I(sbi)->new_version, true);
	ilock = mutex_lock_op(sbi);
	err = sync_hmfs_inode(inode);
	mutex_unlock_op(sbi, ilock);
	if (!err) {
		inc_valid_inode_count(sbi);
		return inode;
	}
out:
	clear_nlink(inode);
	clear_inode_flag(HMFS_I(inode), FI_INC_LINK);
	unlock_new_inode(inode);
fail:	
	make_bad_inode(inode);
	iput(inode);
	if (nid_free)
		alloc_nid_failed(sbi, ino);
	return ERR_PTR(err);
}

struct inode *hmfs_make_dentry(struct inode *dir, struct dentry *dentry,
			       umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct inode *inode;
	int err = 0, ilock;

	inode = hmfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return inode;
	ilock = mutex_lock_op(sbi);
	err = hmfs_add_link(dentry, inode);
	mutex_unlock_op(sbi, ilock);
	if (err)
		goto out;
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

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	return 0;
}

static int hmfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	struct inode *inode;

	inode = hmfs_make_dentry(dir, dentry, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	inode->i_op = &hmfs_file_inode_operations;
	inode->i_fop = &hmfs_file_operations;
	inode->i_mapping->a_ops = &hmfs_dblock_aops;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

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

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	return 0;
}

static int hmfs_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int err, ilock;

	inode->i_ctime = CURRENT_TIME;
	ihold(inode);

	set_inode_flag(HMFS_I(inode), FI_INC_LINK);
	ilock = mutex_lock_op(sbi);
	err = hmfs_add_link(dentry, inode);
	mutex_unlock_op(sbi, ilock);
	if (err)
		goto out;
	d_instantiate(dentry, inode);
	return 0;
out:	
	clear_inode_flag(HMFS_I(inode), FI_INC_LINK);
	iput(inode);
	return err;
}

static int hmfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct inode *inode = dentry->d_inode;
	struct hmfs_dir_entry *de;
	struct hmfs_dentry_block *res_blk;
	int err = -ENOENT;
	int bidx, ofs_in_blk, ilock;

	de = hmfs_find_entry(dir, &dentry->d_name, &bidx, &ofs_in_blk);
	if (!de)
		goto fail;

	err = check_orphan_space(sbi);
	if (err)
		goto fail;

	ilock = mutex_lock_op(sbi);
	res_blk = alloc_new_data_block(dir, bidx);
	if (IS_ERR(res_blk)) {
		err = PTR_ERR(res_blk);
		mutex_unlock_op(sbi, ilock);
		goto fail;
	}
	de = &res_blk->dentry[ofs_in_blk];
	//FIXME: mutex?
	hmfs_delete_entry(de, res_blk, dir, inode, bidx);

	mutex_unlock_op(sbi, ilock);
	mark_inode_dirty(inode);
fail:
	return err;
}

static int hmfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	if (hmfs_empty_dir(inode))
		return hmfs_unlink(dir, dentry);

	return -ENOTEMPTY;
}

static int hmfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry)
{
	struct super_block *sb = old_dir->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct hmfs_dentry_block *old_dentry_blk, *new_dentry_blk;
	struct hmfs_dir_entry *old_dir_entry = NULL, *old_entry, *new_entry;
	int err = -ENOENT, ilock;
	int new_ofs, new_bidx, old_bidx, old_ofs;

	old_entry = hmfs_find_entry(old_dir, &old_dentry->d_name, &old_bidx,
				    &old_ofs);
	if (!old_entry)
		goto out;

	ilock = mutex_lock_op(sbi);

	old_dentry_blk = alloc_new_data_block(old_dir, old_bidx);
	if (IS_ERR(old_dentry_blk)) {
		err = PTR_ERR(old_dentry_blk);
		goto out_k;
	}
	old_entry = &old_dentry_blk->dentry[old_ofs];

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		// .. in hmfs_dentry_block of old_inode
		old_dir_entry = hmfs_parent_dir(old_inode);
		if (!old_dir_entry)
			goto out_k;
	}

	if (new_inode) {
			printk(KERN_INFO"%s-%d\n",__FUNCTION__,__LINE__);
		err = -ENOTEMPTY;
		if (old_dir_entry && !hmfs_empty_dir(new_inode))
			goto out_k;

		err = -ENOENT;
		new_entry =
		 hmfs_find_entry(new_dir, &new_dentry->d_name, &new_bidx,
				 &new_ofs);
		if (!new_entry)
			goto out_k;

		new_dentry_blk = alloc_new_data_block(new_dir, new_bidx);
		if (IS_ERR(new_dentry_blk)) {
			err = PTR_ERR(new_dentry_blk);
			goto out_k;
		}
		new_entry = &new_dentry_blk->dentry[new_ofs];

		hmfs_set_link(new_dir, new_entry, old_inode);

		new_inode->i_ctime = CURRENT_TIME;
		if (old_dir_entry)
			drop_nlink(new_inode);
		drop_nlink(new_inode);

		if (!new_inode->i_nlink) {
			err = check_orphan_space(sbi);
			if (err)
				goto out_k;

			add_orphan_inode(sbi, new_inode->i_ino);
		}
		mark_inode_dirty(new_inode);
	} else {
			printk(KERN_INFO"%s-%d\n",__FUNCTION__,__LINE__);
		err = hmfs_add_link(new_dentry, old_inode);
		if (err)
			goto out_k;
		if (old_dir_entry) {
			inc_nlink(new_dir);
			mark_inode_dirty(new_dir);
		}
	}

	old_inode->i_ctime = CURRENT_TIME;
	mark_inode_dirty(old_inode);

	hmfs_delete_entry(old_entry, old_dentry_blk, old_dir, NULL,
			  old_bidx);

	if (old_dir_entry) {
		if (old_dir != new_dir) {
			hmfs_set_link(old_inode, old_dir_entry, new_dir);
		}
		drop_nlink(old_dir);
		mark_inode_dirty(old_dir);
	}
out_k:	
	mutex_unlock_op(sbi, ilock);
out:
	return err;
}

int hmfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	generic_fillattr(inode, stat);
	stat->blocks <<= 3;
	return 0;
}

static void __setattr_copy(struct inode *inode, const struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	if (ia_valid & ATTR_UID)
		inode->i_uid = attr->ia_uid;
	if (ia_valid & ATTR_GID)
		inode->i_gid = attr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = timespec_trunc(attr->ia_atime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MTIME)
		inode->i_mtime = timespec_trunc(attr->ia_mtime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = timespec_trunc(attr->ia_ctime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;
		if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
			mode &= ~S_ISGID;
		inode->i_mode = mode;
	}
}

int hmfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int err = 0;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if ((attr->ia_valid & ATTR_SIZE) && attr->ia_size != i_size_read(inode)) {
		truncate_setsize(inode, attr->ia_size);
		hmfs_truncate(inode);
	}

	__setattr_copy(inode, attr);

	mark_inode_dirty(inode);
	return err;
}

static struct dentry *hmfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct inode *inode = NULL;
	struct hmfs_dir_entry *de;

	if (dentry->d_name.len > HMFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	de = hmfs_find_entry(dir, &dentry->d_name, NULL, NULL);
	if (de) {
		inode = hmfs_iget(dir->i_sb, de->ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

const struct inode_operations hmfs_dir_inode_operations = {
	.create = hmfs_create,
	.mkdir = hmfs_mkdir,
	.mknod = hmfs_mknod,
	.lookup = hmfs_lookup,
	.link = hmfs_link,
	.unlink = hmfs_unlink,
	.symlink = hmfs_symlink,
	.getattr = hmfs_getattr,
	.setattr = hmfs_setattr,
	.rmdir = hmfs_rmdir,
	.rename = hmfs_rename,
};

const struct inode_operations hmfs_special_inode_operations = {
	.getattr = hmfs_getattr,
	.setattr = hmfs_setattr,
};

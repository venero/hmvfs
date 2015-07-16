#include "hmfs_fs.h"

static int do_read_inode(struct inode *inode)
{
	//TODO
}

static int is_meta_inode(unsigned long ino)
{
	return ino >= 3;
}

/* allocate an inode */
struct inode *hmfs_iget(struct super_block *sb, unsigned long ino)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct inode *inode;
	int ret;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	if (is_meta_inode(ino))
		goto make_now;

	ret = do_read_inode(inode);
	if (ret)
		goto bad_inode;
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &hmfs_file_inode_operations;
		inode->i_fop = &hmfs_file_operations;
		inode->i_mapping->a_ops = &hmfs_dblock_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &hmfs_dir_inode_operations;
		inode->i_fop = &hmfs_dir_operations;
		inode->i_mapping->a_ops = &hmfs_dblock_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &hmfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &hmfs_dblock_aops;
	} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)
		   || S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		inode->i_op = &hmfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	}

make_now:
	if (ino == HMFS_NAT_INO) {
		inode->i_mapping->a_ops = &hmfs_nat_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HMFS_ZERO);
	} else if (ino == HMFS_SIT_INO) {
		inode->i_mapping->a_ops = &hmfs_sit_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HMFS_ZERO);
	} else if (ino == HMFS_SSA_INO) {
		inode->i_mapping->a_ops = &hmfs_ssa_aops;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HMFS_ZERO);
	} else {
		ret = -EIO;
		goto bad_inode;
	}

	unlock_new_inode(inode);
	return inode;
bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}

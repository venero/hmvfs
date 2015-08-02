#include "hmfs_fs.h"
#include "hmfs.h"

struct backing_dev_info hmfs_backing_dev_info __read_mostly = {
	.ra_pages = 0,
	.capabilities = BDI_CAP_NO_ACCT_AND_WRITEBACK,
};

static int do_read_inode(struct inode *inode)
{
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct hmfs_inode *hi;

	if (check_nid_range(sbi, inode->i_ino)) {
		printk(KERN_INFO "[HMFS] Invalid inode number:%lu\n",
		       inode->i_ino);
		return -EINVAL;
	}

	hi = get_node(sbi, inode->i_ino);
	if (IS_ERR(hi))
		return PTR_ERR(hi);

	inode->i_mode = le16_to_cpu(hi->i_mode);
	i_uid_write(inode, le32_to_cpu(hi->i_uid));
	i_gid_write(inode, le32_to_cpu(hi->i_gid));
	set_nlink(inode, le32_to_cpu(hi->i_links));
	inode->i_size = le64_to_cpu(hi->i_size);
	inode->i_blocks = le64_to_cpu(hi->i_blocks);

	inode->i_atime.tv_sec = le64_to_cpu(hi->i_atime);
	inode->i_ctime.tv_sec = le64_to_cpu(hi->i_ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(hi->i_mtime);
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_generation = le32_to_cpu(hi->i_generation);

	//TODO: deal with device file

	fi->i_current_depth = le32_to_cpu(hi->i_current_depth);
	fi->i_flags = le32_to_cpu(hi->i_flags);
	fi->flags = 0;
	fi->i_pino = le32_to_cpu(hi->i_pino);
	return 0;
}

void hmfs_update_isize(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct hmfs_node *hn;

	hn = get_new_node(sbi, inode->i_ino, inode->i_ino);
	hn->i.i_size = cpu_to_le64(inode->i_size);
	hn->i.i_blocks = cpu_to_le64(inode->i_blocks);
	hn->i.i_ctime = cpu_to_le64(get_seconds());
}

int sync_hmfs_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct hmfs_node *rn;
	struct hmfs_inode *hi;

	rn = get_new_node(sbi, inode->i_ino, inode->i_ino);
	if (IS_ERR(rn))
		return PTR_ERR(rn);

	hi = &(rn->i);

	hi->i_mode = cpu_to_le16(inode->i_mode);
	hi->i_uid = cpu_to_le32(i_uid_read(inode));
	hi->i_gid = cpu_to_le32(i_gid_read(inode));
	hi->i_links = cpu_to_le32(inode->i_nlink);
	hi->i_size = cpu_to_le64(inode->i_size);
	hi->i_blocks = cpu_to_le64(inode->i_blocks);

	hi->i_atime = cpu_to_le64(inode->i_atime.tv_sec);
	hi->i_ctime = cpu_to_le64(inode->i_ctime.tv_sec);
	hi->i_mtime = cpu_to_le64(inode->i_mtime.tv_sec);
	hi->i_generation = cpu_to_le32(inode->i_generation);

	hi->i_current_depth = cpu_to_le32(fi->i_current_depth);
	hi->i_flags = cpu_to_le32(fi->i_flags);
	hi->i_pino = cpu_to_le64(fi->i_pino);

	rn->footer.nid = cpu_to_le64(inode->i_ino);
	rn->footer.ino = cpu_to_le64(inode->i_ino);
	rn->footer.cp_ver = cpu_to_le32(cp_i->version);
	return 0;
}

static int is_meta_inode(unsigned long ino)
{
	return ino < HMFS_ROOT_INO;
}

/* allocate an inode */
struct inode *hmfs_iget(struct super_block *sb, unsigned long ino)
{
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
	inode->i_mapping->backing_dev_info = &hmfs_backing_dev_info;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &hmfs_file_inode_operations;
		inode->i_fop = &hmfs_file_operations;
		inode->i_mapping->a_ops = &hmfs_dblock_aops;
		break;
	case S_IFDIR:
		inode->i_op = &hmfs_dir_inode_operations;
		inode->i_fop = &hmfs_dir_operations;
		inode->i_mapping->a_ops = &hmfs_dblock_aops;
		break;
	case S_IFLNK:
		inode->i_op = &hmfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &hmfs_dblock_aops;
		break;
	default:
		inode->i_op = &hmfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	}
	goto out;
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
out:
	unlock_new_inode(inode);
	return inode;
bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}

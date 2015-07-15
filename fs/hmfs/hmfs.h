#include <linux/slab.h>
#include <linux/types.h>

struct hmfs_sb_info {
	struct super_block *sb;

	/* 1. location info  */
	phys_addr_t phys_addr;	//get from user mount                   [hmfs_parse_options]
	void *virt_addr;	//hmfs_superblock & also HMFS address   [ioremap]

	unsigned long initsize;
	unsigned long s_mount_opt;

	/* basic file system units */
	unsigned long total_node_count;		/* total node block count */
	unsigned long total_valid_node_count;	/* valid node block count */
	unsigned long total_valid_inode_count;	/* valid inode count */

	unsigned long user_block_count;		/* # of user blocks */
	unsigned long total_valid_block_count;	/* # of valid blocks */
	unsigned long alloc_valid_block_count;	/* # of allocated blocks */
	unsigned long last_valid_block_count;		/* for recovery */

	/**
	 * statiatic infomation, for debugfs
	 */
	struct hmfs_stat_info *stat_info;
};

struct hmfs_inode_info {
	struct inode vfs_inode;	/* vfs inode */
};

struct hmfs_stat_info {
	struct list_head stat_list;
	struct hmfs_sb_info *sbi;
};

/*
 * Inline functions
 */
static inline struct hmfs_inode_info *HMFS_I(struct inode *inode)
{
	return container_of(inode, struct hmfs_inode_info, vfs_inode);
}
static inline struct hmfs_sb_info *HMFS_SB(struct super_block *sb)                                                                               
{
	return sb->s_fs_info;
}

/**
 * debug.c
 */
void __init hmfs_create_root_stat(void);
void hmfs_destroy_root_stat(void);
int hmfs_build_stats(struct hmfs_sb_info *sbi);
void hmfs_destroy_stats(struct hmfs_sb_info *sbi);

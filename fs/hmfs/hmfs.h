
#ifndef _LINUX_HMFS_H
#define _LINUX_HMFS_H

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/radix-tree.h>
#include <linux/pagemap.h>

typedef unsigned long nid_t;

struct checkpoint_info {
	unsigned int version;

	unsigned long cur_node_segno;
	unsigned int cur_node_blkoff;

	unsigned long cur_data_segno;
	unsigned int cur_data_blkoff;

	unsigned valid_inode_count;

	unsigned last_checkpoint_addr;

	struct hmfs_checkpoint *cp;
	struct page *cp_page;
};

struct hmfs_nm_info {
	struct inode *nat_inode;
	nid_t max_nid;		/* maximum possible node ids */
	nid_t next_scan_nid;	/* the next nid to be scanned */

	/* NAT cache management */
	struct radix_tree_root nat_root;	/* root of the nat entry cache */
	rwlock_t nat_tree_lock;	/* protect nat_tree_lock */
	unsigned int nat_cnt;	/* the # of cached nat entries */
	struct list_head nat_entries;	/* cached nat entry list (clean) */
	struct list_head dirty_nat_entries;	/* cached nat entry list (dirty) */

	/* free node ids management */
	struct list_head free_nid_list;	/* a list for free nids */
	spinlock_t free_nid_list_lock;	/* protect free nid list */
	unsigned int fcnt;	/* the number of free node id */
	struct mutex build_lock;	/* lock for build free nids */
};

/*
 * ioctl commands
 */
#define HMFS_IOC_GETVERSION		FS_IOC_GETVERSION

/* used for hmfs_inode_info->flags */
enum {
	FI_DIRTY_INODE,		/* indicate inode is dirty or not */
};

struct hmfs_sb_info {
	struct super_block *sb;			/* pointer to VFS super block */
	/* 1. location info  */
	phys_addr_t phys_addr;	//get from user mount                   [hmfs_parse_options]
	void *virt_addr;	//hmfs_superblock & also HMFS address   [ioremap]

	unsigned long initsize;
	unsigned long s_mount_opt;

	unsigned long page_count;
	unsigned long segment_count;

	struct checkpoint_info *cp_info;

	unsigned long ssa_addr;
	unsigned long main_addr_start;
	unsigned long main_addr_end;

	struct rw_semaphore cp_rwsem;		/* blocking FS operations */
	/* 5. ... */
	 /**/ /**/
	/**
	 * statiatic infomation, for debugfs
	 */
	struct hmfs_stat_info *stat_info;

	struct hmfs_nm_info *nm_info;
	struct inode *sit_inode;
	struct inode *ssa_inode;
};

struct hmfs_inode_info {
	struct inode vfs_inode;	/* vfs inode */
	atomic_t dirty_pages;		/* # of dirty pages */
	unsigned long i_flags;		/* keep an inode flags for ioctl */
};

struct hmfs_stat_info {
	struct list_head stat_list;
	struct hmfs_sb_info *sbi;
};

extern const struct file_operations hmfs_file_operations;
extern const struct file_operations hmfs_dir_operations;

extern const struct inode_operations hmfs_file_inode_operations;
extern const struct inode_operations hmfs_dir_inode_operations;
extern const struct inode_operations hmfs_symlink_inode_operations;
extern const struct inode_operations hmfs_special_inode_operations;

extern const struct address_space_operations hmfs_dblock_aops;
extern const struct address_space_operations hmfs_nat_aops;
extern const struct address_space_operations hmfs_sit_aops;
extern const struct address_space_operations hmfs_ssa_aops;
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

static inline struct checkpoint_info *CURCP_I(struct hmfs_sb_info *sbi)
{
	return sbi->cp_info;
}

static inline void *ADDR(struct hmfs_sb_info *sbi, unsigned logic_addr)
{
	return (sbi->virt_addr + logic_addr);
}

static inline nid_t START_NID(nid_t nid)
{
	//TODO
	return nid;
}

static inline struct hmfs_sb_info *HMFS_I_SB(struct inode *inode)
{
	return HMFS_SB(inode->i_sb);
}


static inline struct hmfs_nm_info *NM_I(struct hmfs_sb_info *sbi)
{
	return sbi->nm_info;
}

static inline struct kmem_cache *hmfs_kmem_cache_create(const char *name,
							size_t size,
							void (*ctor) (void *))
{
	return kmem_cache_create(name, size, 0, SLAB_RECLAIM_ACCOUNT, ctor);
}

static inline int is_inode_flag_set(struct hmfs_inode_info *fi, int flag)
{
	return test_bit(flag, &fi->i_flags);
}

static inline void hmfs_lock_op(struct hmfs_sb_info *sbi)
{
	down_read(&sbi->cp_rwsem);
}

static inline void hmfs_unlock_op(struct hmfs_sb_info *sbi)
{
	up_read(&sbi->cp_rwsem);
}

/* define prototype function */

/* inode.c */
struct inode *hmfs_iget(struct super_block *sb, unsigned long ino);


/**
 * debug.c
 */
void hmfs_create_root_stat(void);
void hmfs_destroy_root_stat(void);
int hmfs_build_stats(struct hmfs_sb_info *sbi);
void hmfs_destroy_stats(struct hmfs_sb_info *sbi);

struct node_info;

/* node.c */
int build_node_manager(struct hmfs_sb_info *sbi);
void destroy_node_manager(struct hmfs_sb_info *sbi);
void get_node_info(struct hmfs_sb_info *sbi, nid_t nid, struct node_info *ni);
int create_node_manager_caches(void);
void destroy_node_manager_caches(void);

/* checkpoint.c */
int init_checkpoint_manager(struct hmfs_sb_info *sbi);
int destroy_checkpoint_manager(struct hmfs_sb_info *sbi);
int lookup_journal_in_cp(struct checkpoint_info *cp_info, unsigned int type,
			 nid_t nid, int alloc);
struct hmfs_nat_entry nat_in_journal(struct checkpoint_info *cp_info,
				     int index);

#endif

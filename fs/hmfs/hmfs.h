#ifndef _LINUX_HMFS_H
#define _LINUX_HMFS_H

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/radix-tree.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>

#include "hmfs_fs.h"

#ifdef CONFIG_HMFS_CHECK_FS
#define hmfs_bug_on(sbi, condition)	BUG_ON(condition)
#define hmfs_down_write(x, y)	down_write_nest_lock(x, y)
#else
#define hmfs_bug_on(sbi, condition)					\
	do {								\
		if (unlikely(condition)) {				\
			WARN_ON(1);					\
			set_sbi_flag(sbi, SBI_NEED_FSCK);		\
		}							\
	} while (0)
#define hmfs_down_write(x, y)	down_write(x)
#endif

#define MAX_DIR_RA_PAGES	4	/* maximum ra pages of dir */

#define HMFS_DEF_FILE_MODE	0664

/*
 * For INODE and NODE manager
 */
/* for directory operations */
struct hmfs_dentry_ptr {
	const void *bitmap;
	struct hmfs_dir_entry *dentry;
	 __u8(*filename)[HMFS_SLOT_LEN];
	int max;
};

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

struct hmfs_sb_info {
	struct super_block *sb;	/* pointer to VFS super block */
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

	struct rw_semaphore cp_rwsem;	/* blocking FS operations */
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
	atomic_t dirty_pages;	/* # of dirty pages */
	unsigned long i_flags;	/* keep an inode flags for ioctl */
	unsigned char i_dir_level;	/* use for dentry level for large dir */
	hmfs_hash_t chash;	/* hash value of given file name */
	unsigned int i_current_depth;	/* use only in directory structure */
	unsigned int clevel;	/* maximum level of given file name */
	/* Use below internally in hmfs */
	unsigned long flags;	/* use to pass per-file flags */
	struct rw_semaphore i_sem;	/* protect fi info */
	unsigned int i_pino;	/* parent inode number */
};

struct hmfs_stat_info {
	struct list_head stat_list;
	struct hmfs_sb_info *sbi;
};

/* used for hmfs_inode_info->flags */
enum {
	FI_NEW_INODE,		/* indicate newly allocated inode */
	FI_DIRTY_INODE,		/* indicate inode is dirty or not */
	FI_DIRTY_DIR,		/* indicate directory has dirty pages */
	FI_INC_LINK,		/* need to increment i_nlink */
	FI_ACL_MODE,		/* indicate acl mode */
	FI_NO_ALLOC,		/* should not allocate any blocks */
	FI_UPDATE_DIR,		/* should update inode block for consistency */
	FI_DELAY_IPUT,		/* used for the recovery */
	FI_NO_EXTENT,		/* not to use the extent cache */
	FI_INLINE_XATTR,	/* used for inline xattr */
	FI_INLINE_DATA,		/* used for inline data */
	FI_INLINE_DENTRY,	/* used for inline dentry */
	FI_APPEND_WRITE,	/* inode has appended data */
	FI_UPDATE_WRITE,	/* inode has in-place-update data */
	FI_NEED_IPU,		/* used for ipu per file */
	FI_ATOMIC_FILE,		/* indicate atomic file */
	FI_VOLATILE_FILE,	/* indicate volatile file */
	FI_FIRST_BLOCK_WRITTEN,	/* indicate #0 data block was written */
	FI_DROP_CACHE,		/* drop dirty page cache */
	FI_DATA_EXIST,		/* indicate data exists */
	FI_INLINE_DOTS,		/* indicate inline dot dentries */
};

enum page_type {
	DATA,
	NODE,
	META,
	NR_PAGE_TYPE,
	META_FLUSH,
	INMEM,			/* the below types are used by tracepoints only. */
	INMEM_DROP,
	IPU,
	OPU,
};

enum DATA_RA_TYPE {
	RA_DB_END,		/* get data block address within a direct node */
	RA_END,			/* get data block to end */
};

enum ADDR_TYPE {
	NULL_ADDR = 0,
	NEW_ADDR = -1,
};

enum READ_DNODE_TYPE {
	ALLOC_NODE,
	LOOKUP_NODE,
};
/*
 * this structure is used as one of function parameters.
 * all the information are dedicated to a given direct node block determined
 * by the data offset in a file.
 */
struct dnode_of_data {
	struct inode *inode;	/* vfs inode pointer */
	struct hmfs_inode *inode_block;	/* its inode, NULL is possible */
	struct direct_node *node_block;	/* direct node */
	nid_t nid;		/* node id of the direct node block */
	unsigned int ofs_in_node;	/* data offset in the node page */
	int level;		/* depth of data block */
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

static inline struct hmfs_nm_info *NM_I(struct hmfs_sb_info *sbi)
{
	return sbi->nm_info;
}

static inline int check_nid_range(struct hmfs_sb_info *sbi, nid_t nid)
{
	if (nid >= NM_I(sbi)->max_nid)
		return -EINVAL;
	return 0;
}

static inline struct hmfs_sb_info *HMFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct checkpoint_info *CURCP_I(struct hmfs_sb_info *sbi)
{
	return sbi->cp_info;
}

static inline struct hmfs_inode *HMFS_INODE(struct page *page)
{
	return &((struct hmfs_node *)page_address(page))->i;
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

static inline struct kmem_cache *hmfs_kmem_cache_create(const char *name,
							size_t size,
							void (*ctor) (void *))
{
	return kmem_cache_create(name, size, 0, SLAB_RECLAIM_ACCOUNT, ctor);
}

static inline int is_inode_flag_set(struct hmfs_inode_info *fi, int flag)
{
	return test_bit(flag, &fi->flags);
}

static inline void hmfs_lock_op(struct hmfs_sb_info *sbi)
{
	down_read(&sbi->cp_rwsem);
}

static inline void hmfs_unlock_op(struct hmfs_sb_info *sbi)
{
	up_read(&sbi->cp_rwsem);
}

static inline struct hmfs_sb_info *HMFS_M_SB(struct address_space *mapping)
{
	return HMFS_I_SB(mapping->host);
}

static inline struct hmfs_sb_info *HMFS_P_SB(struct page *page)
{
	return HMFS_M_SB(page->mapping);
}

static inline void set_inode_flag(struct hmfs_inode_info *fi, int flag)
{
	if (!test_bit(flag, &fi->flags))
		set_bit(flag, &fi->flags);
}

static inline void clear_inode_flag(struct hmfs_inode_info *fi, int flag)
{
	if (test_bit(flag, &fi->flags))
		clear_bit(flag, &fi->flags);
}

static inline unsigned long cal_page_addr(unsigned long segno,
					  unsigned int blkoff)
{
	return (segno << HMFS_SEGMENT_SIZE_BITS) +
	    (blkoff << HMFS_PAGE_SIZE_BITS);
}

static inline loff_t hmfs_max_size(void)
{
	loff_t res = 0;
	res = NORMAL_ADDRS_PER_INODE;
	res += 2 * ADDRS_PER_BLOCK;
	res += 2 * ADDRS_PER_BLOCK * NIDS_PER_BLOCK;
	res += NIDS_PER_BLOCK * NIDS_PER_BLOCK * ADDRS_PER_BLOCK;
	res = (res << HMFS_PAGE_SIZE_BITS);

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;
	return res;
}

/* define prototype function */

/* inode.c */
struct inode *hmfs_iget(struct super_block *sb, unsigned long ino);
void hmfs_update_isize(struct inode *inode);
int sync_hmfs_inode(struct inode *inode);

/* debug.c */
void hmfs_create_root_stat(void);
void hmfs_destroy_root_stat(void);
int hmfs_build_stats(struct hmfs_sb_info *sbi);
void hmfs_destroy_stats(struct hmfs_sb_info *sbi);

struct node_info;

/* node.c */
int build_node_manager(struct hmfs_sb_info *sbi);
void destroy_node_manager(struct hmfs_sb_info *sbi);
int get_node_info(struct hmfs_sb_info *sbi, nid_t nid, struct node_info *ni);
void *get_node(struct hmfs_sb_info *sbi, nid_t nid);
int create_node_manager_caches(void);
void destroy_node_manager_caches(void);
void alloc_nid_failed(struct hmfs_sb_info *sbi, nid_t uid);
bool alloc_nid(struct hmfs_sb_info *sbi, nid_t * uid, nid_t * ino);
void *get_new_node(struct hmfs_sb_info *sbi, nid_t nid, nid_t ino);

/* checkpoint.c */
int init_checkpoint_manager(struct hmfs_sb_info *sbi);
int destroy_checkpoint_manager(struct hmfs_sb_info *sbi);
int lookup_journal_in_cp(struct checkpoint_info *cp_info, unsigned int type,
			 nid_t nid, int alloc);
struct hmfs_nat_entry nat_in_journal(struct checkpoint_info *cp_info,
				     int index);

/* data.c */
int get_data_blocks(struct inode *inode, int start, int end, void **blocks,
		    int *size, int mode);
void *get_new_data_block(struct inode *inode, int block);
int get_dnode_of_data(struct dnode_of_data *dn, int index, int mode);

/* dir.c */
int __hmfs_add_link(struct inode *inode, const struct qstr *name,
		    struct inode *child);
struct hmfs_dir_entry *hmfs_find_entry(struct inode *dir, struct qstr *child);
struct hmfs_dir_entry *hmfs_parent_dir(struct inode *inode, struct page **page);
unsigned long hmfs_inode_by_name(struct inode *inode, struct qstr *name);
void hmfs_set_link(struct inode *inode, struct hmfs_dir_entry *entry,
		   struct page *, struct inode *);
void hmfs_delete_entry(struct hmfs_dir_entry *, struct page *, struct inode *,
		       struct inode *);
int hmfs_make_empty(struct inode *, struct inode *);
bool hmfs_empty_dir(struct inode *);

/* hash.c */
hmfs_hash_t hmfs_dentry_hash(const struct qstr *name_info);

static inline int hmfs_add_link(struct dentry *dentry, struct inode *inode)
{
	return __hmfs_add_link(dentry->d_parent->d_inode, &dentry->d_name,
			       inode);
}

static inline void hmfs_put_page(struct page *page, int unlock)
{
	if (!page)
		return;

	if (unlock) {
		//hmfs_bug_on(HMFS_P_SB(page), !PageLocked(page));
		unlock_page(page);
	}
	page_cache_release(page);
}

static inline int hmfs_has_inline_dentry(struct inode *inode)
{
	return is_inode_flag_set(HMFS_I(inode), FI_INLINE_DENTRY);
}

static inline void hmfs_dentry_kunmap(struct inode *dir, struct page *page)
{
	if (!hmfs_has_inline_dentry(dir))
		kunmap(page);
}
#endif

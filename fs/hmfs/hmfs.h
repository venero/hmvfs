#ifndef _LINUX_HMFS_H
#define _LINUX_HMFS_H

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/radix-tree.h>
#include <linux/pagemap.h>
#include <linux/bitops.h>
#include <linux/backing-dev.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>
#include "hmfs_fs.h"
#include "checkpoint.h"
//#include "segment.h"

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

#define HMFS_DEF_FILE_MODE	0664

#define DEF_OP_SEGMENTS		6	/* default percentage of overprovision segments */

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

static inline void make_dentry_ptr(struct hmfs_dentry_ptr *d, void *src,
				   int type)
{
	//XXX;type always == 1?
//      if (type == 1) {
	struct hmfs_dentry_block *t = (struct hmfs_dentry_block *)src;
	d->max = NR_DENTRY_IN_BLOCK;
	d->bitmap = &t->dentry_bitmap;
	d->dentry = t->dentry;
	d->filename = t->filename;
//      } else {
//              struct hmfs_inline_dentry *t = (struct hmfs_inline_dentry *)src;
//              d->max = NR_INLINE_DENTRY;
//              d->bitmap = &t->dentry_bitmap;
//              d->dentry = t->dentry;
//              d->filename = t->filename;
//      }
}

typedef unsigned int nid_t;
struct free_nid;

enum SEG_TYPE {
	TYPE_NODE = 0, TYPE_DATA = 1
};

struct checkpoint_info {
	struct list_head list;

	unsigned int version;
	unsigned int next_version;
	struct hmfs_nat_node *nat_root;
	/* only useful for current checkpoint_info */
	struct hmfs_checkpoint *cp;
};

struct orphan_inode_entry {
	struct list_head list;
	nid_t ino;
};

struct hmfs_nm_info {
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
	struct free_nid *free_nids;
	spinlock_t free_nid_list_lock;	/* protect free nid list */

	unsigned int fcnt;	/* the number of free node id */
	struct mutex build_lock;	/* lock for build free nids */
};

/*
 * ioctl commands
 */
#define HMFS_IOC_GETVERSION		FS_IOC_GETVERSION
#define NR_GLOBAL_LOCKS	16
struct hmfs_sb_info {
	struct super_block *sb;	/* pointer to VFS super block */

	phys_addr_t phys_addr;	//get from user mount                   [hmfs_parse_options]
	void *virt_addr;	//hmfs_superblock & also HMFS address   [ioremap]

	u64 initsize;
	unsigned long s_mount_opt;
	kuid_t uid;
	kgid_t gid;

	unsigned long long page_count;
	unsigned long long segment_count;
	unsigned long long segment_count_main;

	struct hmfs_cm_info *cm_info;
	struct mutex fs_lock[NR_GLOBAL_LOCKS];
	unsigned char next_lock_num;

	/* GC */
	struct mutex gc_mutex;
	struct hmfs_gc_kthread *gc_thread;
	unsigned int last_victim[2];

	struct hmfs_sit_entry *sit_entries;
	struct hmfs_summary *ssa_entries;
	unsigned long long main_addr_start;
	unsigned long long main_addr_end;
	char nat_height;

	struct rw_semaphore cp_rwsem;	/* blocking FS operations */

	/**
	 * statiatic infomation, for debugfs
	 */
	struct hmfs_stat_info *stat_info;
	struct hmfs_nm_info *nm_info;
	struct hmfs_sm_info *sm_info;	/* segment manager */

	int por_doing;		/* recovery is doing or not */
};

struct hmfs_inode_info {
	struct inode vfs_inode;	/* vfs inode */
	unsigned long i_flags;	/* keep an inode flags for ioctl */
	hmfs_hash_t chash;	/* hash value of given file name */
	unsigned int i_current_depth;	/* use only in directory structure */
	unsigned int clevel;	/* maximum level of given file name */
	/* Use below internally in hmfs */
	unsigned long flags;	/* use to pass per-file flags */
	struct rw_semaphore i_sem;	/* protect fi info */
	u64 i_pino;		/* parent inode number */
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

enum DATA_RA_TYPE {
	RA_DB_END,		/* get data block address within a direct node */
	RA_END,			/* get data block to end */
};

enum ADDR_TYPE {
	NULL_ADDR = 0, NEW_ADDR = -1, FREE_ADDR = -2,
};

enum READ_DNODE_TYPE {
	ALLOC_NODE, LOOKUP_NODE,
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

/*
 * Inline functions
 */
static inline struct hmfs_super_block *HMFS_RAW_SUPER(struct hmfs_sb_info *sbi)
{
	return (struct hmfs_super_block *)(sbi->virt_addr);
}

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

static inline struct hmfs_cm_info *CM_I(struct hmfs_sb_info *sbi)
{
	return sbi->cm_info;
}

static inline struct checkpoint_info *CURCP_I(struct hmfs_sb_info *sbi)
{
	return CM_I(sbi)->cur_cp_i;
}

static inline void *ADDR(struct hmfs_sb_info *sbi, unsigned long logic_addr)
{
	return (sbi->virt_addr + logic_addr);
}

static inline block_t DEADDR(struct hmfs_sb_info *sbi, void *ptr)
{
	return (block_t) (ptr - sbi->virt_addr);
}

static inline nid_t START_NID(nid_t nid)
{
//TODO
	return ((nid / NAT_ENTRY_PER_BLOCK) * NAT_ENTRY_PER_BLOCK);

}

static inline struct hmfs_sb_info *HMFS_I_SB(struct inode *inode)
{
	return HMFS_SB(inode->i_sb);
}

static inline unsigned long GET_SEGNO(struct hmfs_sb_info *sbi, u64 addr)
{
	return (addr - sbi->main_addr_start) >> HMFS_SEGMENT_SIZE_BITS;
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

static inline void mutex_lock_all(struct hmfs_sb_info *sbi)
{
	int i;

//FIXME:cp_mutex?
	for (i = 0; i < NR_GLOBAL_LOCKS; i++)
		mutex_lock(&sbi->fs_lock[i]);
}

static inline void mutex_unlock_all(struct hmfs_sb_info *sbi)
{
	int i;

	for (i = 0; i < NR_GLOBAL_LOCKS; i++)
		mutex_unlock(&sbi->fs_lock[i]);
}

static inline int mutex_lock_op(struct hmfs_sb_info *sbi)
{
	unsigned char next_lock = sbi->next_lock_num % NR_GLOBAL_LOCKS;
	int i;

	for (i = 0; i < NR_GLOBAL_LOCKS; ++i)
		if (mutex_trylock(&sbi->fs_lock[i]))
			return i;

	mutex_lock(&sbi->fs_lock[next_lock]);
	sbi->next_lock_num++;

	return next_lock;
}

static inline void mutex_unlock_op(struct hmfs_sb_info *sbi, int ilock)
{
	BUG_ON(ilock < 0 || ilock >= NR_GLOBAL_LOCKS);
	mutex_unlock(&sbi->fs_lock[ilock]);
}

static inline bool inc_valid_node_count(struct hmfs_sb_info *sbi,
					struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	u64 alloc_valid_block_count;

	spin_lock(&cm_i->stat_lock);
	alloc_valid_block_count = cm_i->alloc_block_count + count;

	if (alloc_valid_block_count > cm_i->user_block_count) {
		spin_unlock(&cm_i->stat_lock);
		return false;
	}

	if (inode)
		inode->i_blocks += count;

	cm_i->valid_node_count += count;
	cm_i->alloc_block_count = alloc_valid_block_count;
	spin_unlock(&cm_i->stat_lock);

	return true;
}

static inline void dec_valid_node_count(struct hmfs_sb_info *sbi,
					struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	spin_lock(&cm_i->stat_lock);
	cm_i->valid_node_count -= count;
	if (likely(inode))
		inode->i_blocks -= count;
	spin_unlock(&cm_i->stat_lock);
}

static inline int dec_valid_block_count(struct hmfs_sb_info *sbi,
					struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	spin_lock(&cm_i->stat_lock);
	inode->i_blocks -= count;
	cm_i->valid_block_count -= count;
	spin_unlock(&cm_i->stat_lock);
	return 0;
}

static inline bool inc_valid_block_count(struct hmfs_sb_info *sbi,
					 struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	u64 alloc_block_count;

	spin_lock(&cm_i->stat_lock);
	alloc_block_count = cm_i->alloc_block_count + count;
//FIXME: need this check ?
	if (alloc_block_count > cm_i->user_block_count) {
		spin_unlock(&cm_i->stat_lock);
		return false;
	}
	inode->i_blocks += count;
	cm_i->alloc_block_count = alloc_block_count;
	cm_i->valid_block_count += count;
	spin_unlock(&cm_i->stat_lock);
	return true;
}

static inline void dec_valid_inode_count(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	spin_lock(&cm_i->stat_lock);
	cm_i->valid_inode_count--;
	spin_unlock(&cm_i->stat_lock);
}

static inline void inc_valid_inode_count(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	spin_lock(&cm_i->stat_lock);
	cm_i->valid_inode_count++;
	spin_unlock(&cm_i->stat_lock);
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

static inline int hmfs_test_bit(unsigned int nr, char *addr)
{
	int mask;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	return mask & *addr;
}

static inline int hmfs_set_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr |= mask;
	return ret;
}

static inline int hmfs_clear_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr &= ~mask;
	return ret;
}

/* define prototype function */

/* inode.c */
struct inode *hmfs_iget(struct super_block *sb, unsigned long ino);
int sync_hmfs_inode(struct inode *inode);

/* file.c */
int truncate_data_blocks_range(struct dnode_of_data *dn, int count);
void truncate_data_blocks(struct dnode_of_data *dn);
void hmfs_truncate(struct inode *inode);
int truncate_hole(struct inode *inode, pgoff_t start, pgoff_t end);

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
struct hmfs_node *__get_node(struct hmfs_sb_info *sbi,
			     struct checkpoint_info *cp_i, nid_t nid);
int create_node_manager_caches(void);
void destroy_node_manager_caches(void);
void alloc_nid_failed(struct hmfs_sb_info *sbi, nid_t uid);
bool alloc_nid(struct hmfs_sb_info *sbi, nid_t * nid);
void *alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid, struct inode *,
		     char sum_type);
void update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid, nid_t ino,
		      unsigned long blk_addr, unsigned int version, bool dirty);
int truncate_inode_blocks(struct inode *, pgoff_t);
int get_node_path(long block, int offset[4], unsigned int noffset[4]);
block_t flush_nat_entries(struct hmfs_sb_info *sbi);
void set_new_dnode(struct dnode_of_data *dn, struct inode *inode,
		   struct hmfs_inode *hi, struct direct_node *db, nid_t nid);
void truncate_node(struct dnode_of_data *dn);
struct hmfs_nat_block *get_nat_entry_block(struct hmfs_sb_info *sbi,
					   unsigned version, nid_t nid);
struct hmfs_nat_entry *get_nat_entry(struct hmfs_sb_info *sbi, unsigned version,
				     nid_t nid);
void setup_summary_of_delete_node(struct hmfs_sb_info *sbi, block_t blk_addr);

/* segment.c*/
void flush_sit_entries(struct hmfs_sb_info *sbi);
int build_segment_manager(struct hmfs_sb_info *);
void destroy_segment_manager(struct hmfs_sb_info *);
void allocate_new_segments(struct hmfs_sb_info *sbi);
struct hmfs_summary_block *get_summary_block(struct hmfs_sb_info *sbi,
					     unsigned long segno);
struct hmfs_summary *get_summary_by_addr(struct hmfs_sb_info *sbi,
					 block_t blk_addr);
block_t alloc_free_data_block(struct hmfs_sb_info *sbi);
block_t alloc_free_node_block(struct hmfs_sb_info *sbi);
unsigned long long __cal_page_addr(struct hmfs_sb_info *sbi,
				   unsigned long long segno, int blkoff);
void dc_nat_root(struct hmfs_sb_info *sbi, block_t nat_root_addr);
void dc_checkpoint(struct hmfs_sb_info *sbi, block_t cp_addr);
void dc_block(struct hmfs_sb_info *sbi, block_t blk_addr);
void dc_itself(struct hmfs_sb_info *sbi, block_t blk_addr);
void dc_nat_branch(struct hmfs_sb_info *sbi, block_t nat_branch_addr);
void dc_nat_block(struct hmfs_sb_info *sbi, block_t nat_block_addr);
void dc_checkpoint_block(struct hmfs_sb_info *sbi,
			 block_t checkpoint_block_addr);
void dc_direct(struct hmfs_sb_info *sbi, block_t direct_block_addr);
void dc_indirect(struct hmfs_sb_info *sbi, block_t indirect_block_addr);
void dc_inode(struct hmfs_sb_info *sbi, block_t inode_block_addr);
void dc_data(struct hmfs_sb_info *sbi, block_t data_block_addr);
int ic_block(struct hmfs_sb_info *sbi, block_t blk_addr);
void invalidate_block_after_dc(struct hmfs_sb_info *sbi, block_t blk_addr);

/* checkpoint.c */
int init_checkpoint_manager(struct hmfs_sb_info *sbi);
int destroy_checkpoint_manager(struct hmfs_sb_info *sbi);
int lookup_journal_in_cp(struct checkpoint_info *cp_info, unsigned int type,
			 nid_t nid, int alloc);
struct hmfs_nat_entry nat_in_journal(struct checkpoint_info *cp_info,
				     int index);
void add_orphan_inode(struct hmfs_sb_info *sbi, nid_t);
void remove_orphan_inode(struct hmfs_sb_info *sbi, nid_t);
void recover_orphan_inode(struct hmfs_sb_info *sbi);
int check_orphan_space(struct hmfs_sb_info *);
int create_checkpoint_caches(void);
void destroy_checkpoint_caches(void);
void write_checkpoint(struct hmfs_sb_info *sbi);
int read_checkpoint(struct hmfs_sb_info *sbi, u32 version);
unsigned int find_this_version(struct hmfs_sb_info *sbi);
struct checkpoint_info *get_checkpoint_info(struct hmfs_sb_info *sbi,
					    unsigned int version);
struct checkpoint_info *get_next_cp_i(struct hmfs_sb_info *sbi,
				      struct checkpoint_info *cp_i);

/* data.c */
int get_data_blocks(struct inode *inode, int start, int end, void **blocks,
		    int *size, int mode);
void *alloc_new_data_block(struct inode *inode, int block);
void *alloc_new_data_partial_block(struct inode *inode, int block, int start,
				   int size, bool fill_zero);
int get_dnode_of_data(struct dnode_of_data *dn, int index, int mode);

/* dir.c */
int __hmfs_add_link(struct inode *, const struct qstr *, struct inode *);
struct hmfs_dir_entry *hmfs_find_entry(struct inode *, struct qstr *, int *,
				       int *);
struct hmfs_dir_entry *hmfs_parent_dir(struct inode *);
unsigned long hmfs_inode_by_name(struct inode *inode, struct qstr *name);
void hmfs_set_link(struct inode *inode, struct hmfs_dir_entry *entry,
		   struct inode *);
void hmfs_delete_entry(struct hmfs_dir_entry *, struct hmfs_dentry_block *,
		       struct inode *, struct inode *, int bidx);
int hmfs_make_empty(struct inode *, struct inode *);
bool hmfs_empty_dir(struct inode *);

/* symlink.c */
int hmfs_symlink(struct inode *inode, struct dentry *, const char *symname);

/* hash.c */
hmfs_hash_t hmfs_dentry_hash(const struct qstr *name_info);

/* namei.c */
int hmfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat);
int hmfs_setattr(struct dentry *dentry, struct iattr *attr);
struct inode *hmfs_make_dentry(struct inode *dir, struct dentry *dentry,
			       umode_t mode);

/* gc.c */
int hmfs_gc(struct hmfs_sb_info *sbi,int gc_type);

static inline int hmfs_add_link(struct dentry *dentry, struct inode *inode)
{
	return __hmfs_add_link(dentry->d_parent->d_inode, &dentry->d_name,
			       inode);
}

static inline int hmfs_has_inline_dentry(struct inode *inode)
{
	return is_inode_flag_set(HMFS_I(inode), FI_INLINE_DENTRY);
}
#endif

#define TEST 1
#ifdef TEST
void printtty(const char *format, ...);
#define print printtty
#define tprint printtty
#else
#define print printk
#define tprint printk
#endif

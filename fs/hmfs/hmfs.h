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

#define HMFS_DEF_FILE_MODE	0664

#define DEF_OP_SEGMENTS		6	/* default percentage of overprovision segments */

#define CURSEG_DATA			1
#define CURSEG_NODE			0
#define	NR_CURSEG_DATA_TYPE	(1)
#define NR_CURSEG_NODE_TYPE	(1)
#define NR_CURSEG_TYPE	(NR_CURSEG_DATA_TYPE + NR_CURSEG_NODE_TYPE)

/* IO Control Command */
#define HMFS_IOC_GETVERSION		FS_IOC_GETVERSION
#define HMFS_IOC_GETFLAGS		FS_IOC_GETFLAGS
#define HMFS_IOC_SETFLAGS		FS_IOC_SETFLAGS
#define HMFS_IOC32_GETVERSION	FS_IOC32_GETVERSION
#define HMFS_IOC32_GETFLAGS		FS_IOC32_GETFLAGS
#define HMFS_IOC32_SETFLAGS		FS_IOC32_SETFLAGS

/* # of FS Lock in hmfs_sb_info */
#define NR_GLOBAL_LOCKS	16

#ifdef CONFIG_HMFS_DEBUG
#define hmfs_bug_on(sbi, condition)	\
			do {					\
				if (condition) {	\
					spin_lock(&CM_I(sbi)->stat_lock);	\
					CM_I(sbi)->nr_bugs++;				\
					spin_unlock(&CM_I(sbi)->stat_lock);	\
					BUG();								\
				}										\
			} while(0)
#define hmfs_dbg(fmt, ...) printk(KERN_INFO"%s-%d:"fmt, \
							__FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define hmfs_bug_on(sbi, condition)
#define hmfs_dbg(fmt, ...)
#endif

/* Mount option */
#define HMFS_MOUNT_BG_GC			0x00000001
#define HMFS_MOUNT_XATTR_USER		0x00000002

#define clear_opt(sbi, option)	(sbi->s_mount_opt &= ~HMFS_MOUNT_##option)
#define set_opt(sbi, option)	(sbi->s_mount_opt |= ~HMFS_MOUNT_##option)
#define test_opt(sbi, option)	(sbi->s_mount_opt & HMFS_MOUNT_##option)

typedef unsigned int nid_t;
typedef unsigned int ver_t;		/* version type */
typedef unsigned long seg_t;		/* segment number type */
typedef unsigned long pgc_t;	/* page count type */



enum SEG_TYPE {
	TYPE_NODE = 0, TYPE_DATA = 1
};

enum DATA_RA_TYPE {
	RA_DB_END,		/* get data block address within a direct node */
	RA_END,			/* get data block to end */
};

enum ADDR_TYPE {
	NULL_ADDR = 0,
	NEW_ADDR = 1,
};

enum READ_DNODE_TYPE {
	ALLOC_NODE, LOOKUP_NODE,
};

/* used for hmfs_inode_info->flags */
enum {
	FI_NEW_INODE,		/* indicate newly allocated inode */
	FI_DIRTY_SIZE,
	FI_DIRTY_INODE,		/* indicate inode is dirty or not */
	FI_INC_LINK,		/* need to increment i_nlink */
	FI_NO_ALLOC,		/* should not allocate any blocks */
	FI_UPDATE_DIR,		/* should update inode block for consistency */
};



struct free_nid;

/* for directory operations */
struct hmfs_dentry_ptr {
	const void *bitmap;
	struct hmfs_dir_entry *dentry;
	 __u8(*filename)[HMFS_SLOT_LEN];
	int max;
};

struct checkpoint_info {
	struct list_head list;			/* cp_info list */
	ver_t version;					/* cp version */
	struct hmfs_nat_node *nat_root;
	struct hmfs_checkpoint *cp;
};

struct orphan_inode_entry {
	struct list_head list;
	nid_t ino;
};

/* for the list of dirty fmap inodes */
struct map_inode_entry {
	struct list_head list;
	struct inode *inode;
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

/* hmfs checkpoint manager */
struct hmfs_cm_info {
	struct checkpoint_info *cur_cp_i;
	ver_t new_version;

	struct checkpoint_info *last_cp_i;

	pgc_t valid_inode_count;
	pgc_t valid_node_count;

	/* block whose count in summary is > 0 */
	pgc_t valid_block_count;
	/* maximum # of blocks users could get */
	pgc_t user_block_count;
	/* # of blocks of all dirty ,full and current segments */
	pgc_t alloc_block_count;
	/* # fo blocks left in current segments */
	int left_blocks_count[NR_CURSEG_TYPE];
#ifdef CONFIG_HMFS_DEBUG
	int nr_bugs;		/* # of bugs found */
#endif

	rwlock_t journal_lock;

	struct mutex orphan_inode_mutex;
	struct list_head orphan_inode_list;
	unsigned long long n_orphans;

	struct radix_tree_root cp_tree_root;
	struct mutex cp_tree_lock;

	spinlock_t stat_lock;

	unsigned nr_nat_journals;

	struct mutex cp_mutex;
};

struct hmfs_sb_info {
	struct super_block *sb;	/* pointer to VFS super block */

	phys_addr_t phys_addr;	/* physical address of NVM */
	void *virt_addr;	/* hmfs_superblock & also HMFS address */

	/* Mount Option */
	unsigned long long initsize;	/* size of NVM */
	unsigned long s_mount_opt;	
	unsigned int mnt_cp_version;	/* version of checkpoint for RO-Mount */
	kuid_t uid;						/* user id */
	kgid_t gid;						/* group id */
	char deep_fmt;				/* whether set 0 of whole area of NVM */

	/* FS statisic */
	pgc_t segment_count;			/* # of all segments */
	pgc_t segment_count_main;		/* # of segments in main area */
	pgc_t page_count_main;			/* # of pages in main area */
	atomic_t nr_dirty_map_pages;				/* # of dirty pages used by mmap */
	int s_dirty;								/* FS is dirty or not */
	struct hmfs_sit_entry *sit_entries;			/* Address of sit entries */
	struct hmfs_summary *ssa_entries;			/* Address of SSA entries */
	block_t main_addr_start;			/* Start address of main area */
	block_t main_addr_end;
	char nat_height;							/* Height of nat tree in cp */

	/* Managet Structure */
	struct hmfs_cm_info *cm_info;				/* checkpoint manager */
	struct hmfs_stat_info *stat_info;			/* debug info manager */
	struct hmfs_nm_info *nm_info;				/* node manager */
	struct hmfs_sm_info *sm_info;				/* segment manager */

	/* Lock */
	struct mutex fs_lock[NR_GLOBAL_LOCKS];		/* FS lock */
	unsigned char next_lock_num;				/* hint for get FS lock */
	struct mutex gc_mutex;						/* GC lock */

	/* GC */
	struct hmfs_gc_kthread *gc_thread;			/* GC thread */
	unsigned int last_victim[2];				/* victims of last gc process */

	/* Other */
	struct list_head dirty_map_inodes;			/* Inodes which contains dirty DRAM page */
	spinlock_t dirty_map_inodes_lock;			/* Lock of dirty map inodes list */
	struct page *map_zero_page;					/* Empty page for hole in file */
	u64 map_zero_page_number; 					/* pfn of above empty page */

	int recovery_doing;								/* recovery is doing or not */
	struct list_head dirty_inodes_list;			/* dirty inodes marked by VFS */
};

struct hmfs_inode_info {
	struct inode vfs_inode;				/* vfs inode */
	unsigned long i_flags;				/* keep an inode flags for ioctl */
	unsigned char i_advise;				/* use to give file attribute hints */
	hmfs_hash_t chash;					/* hash value of given file name */
	unsigned int i_current_depth;		/* use only in directory structure */
	unsigned int clevel;				/* maximum level of given file name */
	/* Use below internally in hmfs */
	unsigned long flags;				/* use to pass per-file flags */
	nid_t i_pino;						/* parent inode number */
	atomic_t nr_dirty_map_pages;
	struct list_head list;
	struct rw_semaphore i_sem;
	void *read_addr;					/* Start address of read-only file */
};

struct hmfs_stat_info {
	struct list_head stat_list;
	struct hmfs_sb_info *sbi;

	int nr_gc_try;			/* Time of call hmfs_gc */
	int nr_gc_real;			/* Time of doing GC */
};

/*
 * this structure is used as one of function parameters.
 * all the information are dedicated to a given direct node block determined
 * by the data offset in a file.
 */
struct dnode_of_data {
	struct inode *inode;			/* vfs inode pointer */
	struct hmfs_inode *inode_block;	/* its inode, NULL is possible */
	struct direct_node *node_block;	/* direct node */
	nid_t nid;						/* node id of the direct node block */
	unsigned int ofs_in_node;		/* data offset in the node page */
	int level;						/* depth of data block */
};

/* 
 * This structure is used to describe start address
 * of an read-only file that has been remap into VMALLOC
 * area. Because we save the struct pointer in struct file,
 * we need some magic number to verify the identity of this struct
 */
struct ro_file_address {
	unsigned long magic;
	void *start_addr;
};

extern const struct file_operations hmfs_file_operations;
extern const struct file_operations hmfs_dir_operations;
extern const struct inode_operations hmfs_file_inode_operations;
extern const struct inode_operations hmfs_dir_inode_operations;
extern const struct inode_operations hmfs_symlink_inode_operations;
extern const struct inode_operations hmfs_special_inode_operations;
extern const struct address_space_operations hmfs_dblock_aops;



/* Inline functions */
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

static inline block_t L_ADDR(struct hmfs_sb_info *sbi, void *ptr)
{
	return (block_t) ((char *)ptr - (char *)sbi->virt_addr);
}

static inline struct hmfs_sb_info *HMFS_I_SB(struct inode *inode)
{
	return HMFS_SB(inode->i_sb);
}

static inline unsigned long GET_SEGNO(struct hmfs_sb_info *sbi, block_t addr)
{
	return (addr - sbi->main_addr_start) >> HMFS_SEGMENT_SIZE_BITS;
}

static inline unsigned int GET_SEG_OFS(struct hmfs_sb_info *sbi, block_t addr)
{
	return ((addr - sbi->main_addr_start) & (~HMFS_SEGMENT_MASK)) >>
			HMFS_PAGE_SIZE_BITS;
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

	for (i = 0; i < NR_GLOBAL_LOCKS; i++)
		mutex_lock(&sbi->fs_lock[i]);
}

static inline u64 pfn_from_vaddr(struct hmfs_sb_info *sbi, void *vaddr)
{
	return (sbi->phys_addr + L_ADDR(sbi, vaddr)) >> PAGE_SHIFT;
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
	hmfs_bug_on(sbi, ilock < 0 || ilock >= NR_GLOBAL_LOCKS);
	mutex_unlock(&sbi->fs_lock[ilock]);
}

static inline bool inc_valid_node_count(struct hmfs_sb_info *sbi,
					struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	pgc_t alloc_valid_block_count;

	spin_lock(&cm_i->stat_lock);

	alloc_valid_block_count = cm_i->alloc_block_count + count;

	if (unlikely(cm_i->left_blocks_count[CURSEG_NODE] < count
	     && alloc_valid_block_count > cm_i->user_block_count)) {
		spin_unlock(&cm_i->stat_lock);
		return false;
	}

	if (inode)
		inode->i_blocks += count;

	if (inode && inode->i_ino == HMFS_ROOT_INO) 
		printk(KERN_INFO"%s-%d:%d\n",__FUNCTION__,__LINE__,(int)inode->i_blocks);

	cm_i->valid_node_count += count;
	cm_i->valid_block_count += count;
	cm_i->alloc_block_count = alloc_valid_block_count;
	cm_i->left_blocks_count[CURSEG_NODE] -= count;;
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

static inline bool inc_gc_block_count(struct hmfs_sb_info *sbi, int seg_type)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	pgc_t alloc_block_count;

	spin_lock(&cm_i->stat_lock);
	alloc_block_count = cm_i->alloc_block_count + 1;
	if (alloc_block_count > sbi->page_count_main) {
		spin_unlock(&cm_i->stat_lock);
		return false;
	}
	cm_i->left_blocks_count[seg_type]--;
	cm_i->alloc_block_count = alloc_block_count;
	spin_unlock(&cm_i->stat_lock);
	return true;
}

static inline bool inc_valid_block_count(struct hmfs_sb_info *sbi,
					 struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	pgc_t alloc_block_count;

	spin_lock(&cm_i->stat_lock);
	alloc_block_count = cm_i->alloc_block_count + count;

	if (unlikely(cm_i->left_blocks_count[CURSEG_DATA] < count
	     && alloc_block_count > cm_i->user_block_count)) {
		spin_unlock(&cm_i->stat_lock);
		return false;
	}
	if (inode)
		inode->i_blocks += count;

	cm_i->alloc_block_count = alloc_block_count;
	cm_i->valid_block_count += count;
	cm_i->left_blocks_count[CURSEG_DATA] -= count;
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

static inline loff_t hmfs_max_file_size(void)
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

static inline void inc_dirty_map_pages_count(struct hmfs_sb_info *sbi)
{
	atomic_inc(&sbi->nr_dirty_map_pages);
	sbi->s_dirty = 1;
}

static inline void dec_dirty_map_pages_count(struct hmfs_sb_info *sbi)
{
	atomic_dec(&sbi->nr_dirty_map_pages);
}

static inline void inode_inc_dirty_map_pages_count(struct inode *inode)
{
	atomic_inc(&HMFS_I(inode)->nr_dirty_map_pages);
}

static inline void inode_dec_dirty_map_pages_count(struct inode *inode)
{
	atomic_dec(&HMFS_I(inode)->nr_dirty_map_pages);
}

static inline struct inode *get_stat_object(struct inode *inode, bool source)
{
	return source ? NULL : inode;
}

static inline int hmfs_readonly(struct super_block *sb)
{
	return sb->s_flags & MS_RDONLY;
}

static inline void make_dentry_ptr(struct hmfs_dentry_ptr *d, void *src,
				   int type)
{
	struct hmfs_dentry_block *t = (struct hmfs_dentry_block *)src;

	d->max = NR_DENTRY_IN_BLOCK;
	d->bitmap = t->dentry_bitmap;
	d->dentry = t->dentry;
	d->filename = t->filename;
}

static inline void make_summary_entry(struct hmfs_summary *summary,
				      nid_t nid,
				      ver_t start_version,
				      unsigned int ofs_in_node,
				      unsigned char type)
{
	summary->nid = cpu_to_le32(nid);
	summary->start_version = cpu_to_le32(start_version);
	summary->ofs_in_node = cpu_to_le16(ofs_in_node);
	summary->bt = cpu_to_le16(type);
}

static inline nid_t get_summary_nid(struct hmfs_summary *summary)
{
	return le32_to_cpu(summary->nid);
}

static inline unsigned int get_summary_offset(struct hmfs_summary *summary)
{
	return le16_to_cpu(summary->ofs_in_node);
}

static inline ver_t get_summary_start_version(struct hmfs_summary
						     *summary)
{
	return le32_to_cpu(summary->start_version);
}

static inline unsigned char get_summary_type(struct hmfs_summary *summary)
{
	return le16_to_cpu(summary->bt) & 0x7f;
}

static inline int get_summary_valid_bit(struct hmfs_summary *summary)
{
	return le16_to_cpu(summary->bt) & (~0x7f);
}

static inline void set_summary_valid_bit(struct hmfs_summary *summary)
{
	int bt = le16_to_cpu(summary->bt);

	bt |= 0x80;
	summary->bt = cpu_to_le16(bt);
}

static inline void set_summary_type(struct hmfs_summary *summary, int type)
{
	int t = le16_to_cpu(summary->bt);
	t &= ~0x7f;
	t |= type & 0x7f;
	summary->bt = cpu_to_le16(t);
}

static inline void clear_summary_valid_bit(struct hmfs_summary *summary)
{
	int bt = le16_to_cpu(summary->bt);

	bt &= 0x7f;
	summary->bt = cpu_to_le16(bt);
}


/* define prototype function */
/* super.c */
int __hmfs_write_inode(struct inode *inode);

/* inode.c */
struct inode *hmfs_iget(struct super_block *sb, unsigned long ino);
int sync_hmfs_inode(struct inode *inode);
void mark_size_dirty(struct inode *inode, loff_t size);
int sync_hmfs_inode_size(struct inode *inode);
void hmfs_set_inode_flags(struct inode *inode);

/* file.c */
int truncate_data_blocks_range(struct dnode_of_data *dn, int count);
unsigned int hmfs_dir_seek_data_reverse(struct inode *dir, unsigned int end_blk);
void truncate_data_blocks(struct dnode_of_data *dn);
void hmfs_truncate(struct inode *inode);
int truncate_hole(struct inode *inode, pgoff_t start, pgoff_t end);
long hmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
int hmfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync);
#ifdef CONFIG_HMFS_FAST_READ
int init_ro_file_address_cache(void);
void destroy_ro_file_address_cache(void);
#else
#define init_ro_file_address_cache()	(0)
#define destroy_ro_file_address_cache()
#endif

/* debug.c */
#ifdef CONFIG_HMFS_DEBUG
void hmfs_create_root_stat(void);
void hmfs_destroy_root_stat(void);
int hmfs_build_stats(struct hmfs_sb_info *sbi);
void hmfs_destroy_stats(struct hmfs_sb_info *sbi);
#else
#define hmfs_destroy_stats(sbi)
#define hmfs_destroy_root_stat()
#define hmfs_build_stats(sbi) 	0
#define hmfs_create_root_stat()
#endif
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
		      block_t blk_addr, ver_t version, bool dirty);
int truncate_inode_blocks(struct inode *, pgoff_t);
int get_node_path(long block, int offset[4], unsigned int noffset[4]);
struct hmfs_nat_node *flush_nat_entries(struct hmfs_sb_info *sbi);
void set_new_dnode(struct dnode_of_data *dn, struct inode *inode,
		   struct hmfs_inode *hi, struct direct_node *db, nid_t nid);
void truncate_node(struct dnode_of_data *dn);
struct hmfs_nat_block *get_nat_entry_block(struct hmfs_sb_info *sbi,
					   ver_t version, nid_t nid);
struct hmfs_nat_entry *get_nat_entry(struct hmfs_sb_info *sbi, ver_t version,
				     nid_t nid);
struct hmfs_nat_node *get_nat_node(struct hmfs_sb_info *sbi,
				   ver_t version, unsigned int index);

/* segment.c*/
void flush_sit_entries(struct hmfs_sb_info *sbi, bool gc_cp);
void recovery_sit_entries(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *hmfs_cp);
int build_segment_manager(struct hmfs_sb_info *);
void destroy_segment_manager(struct hmfs_sb_info *);
struct hmfs_summary_block *get_summary_block(struct hmfs_sb_info *sbi,
					     seg_t segno);
struct hmfs_summary *get_summary_by_addr(struct hmfs_sb_info *sbi,
					 block_t blk_addr);
block_t alloc_free_data_block(struct hmfs_sb_info *sbi);
block_t alloc_free_node_block(struct hmfs_sb_info *sbi);
unsigned long long __cal_page_addr(struct hmfs_sb_info *sbi,
				   seg_t segno, int blkoff);
void get_current_segment_state(struct hmfs_sb_info *sbi, seg_t *segno,
				int *segoff, int seg_type);
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
void add_dirty_map_inode(struct inode *inode);
void remove_dirty_map_inode(struct inode *inode);
void add_orphan_inode(struct hmfs_sb_info *sbi, nid_t);
void remove_orphan_inode(struct hmfs_sb_info *sbi, nid_t);
void recover_orphan_inode(struct hmfs_sb_info *sbi);
int check_orphan_space(struct hmfs_sb_info *);
int create_checkpoint_caches(void);
void destroy_checkpoint_caches(void);
int write_checkpoint(struct hmfs_sb_info *sbi, bool gc_cp);
struct checkpoint_info *get_checkpoint_info(struct hmfs_sb_info *sbi,
					    unsigned int version, bool no_fail);
struct checkpoint_info *get_next_checkpoint_info(struct hmfs_sb_info *sbi,
				struct checkpoint_info *cp_i);
void check_checkpoint_state(struct hmfs_sb_info *sbi);

/* data.c */
void *alloc_new_x_block(struct inode *inode, int x_tag, bool need_copy);
int get_data_blocks(struct inode *inode, int start, int end, void **blocks,
		    int *size, int mode);
void *alloc_new_data_block(struct inode *inode, int block);
void *alloc_new_data_partial_block(struct inode *inode, int block, int start,
				   int size, bool fill_zero);
int get_dnode_of_data(struct dnode_of_data *dn, int index, int mode);
int hmfs_write_data_page(struct page *page, struct writeback_control *wbc);

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
int hmfs_gc(struct hmfs_sb_info *sbi, int gc_type);
void recovery_gc_crash(struct hmfs_sb_info *sbi, struct hmfs_checkpoint *hmfs_cp);
int start_gc_thread(struct hmfs_sb_info *sbi);
void stop_gc_thread(struct hmfs_sb_info *sbi);

/* xattr.c */
ssize_t hmfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size);

/* util.c */
#ifdef CONFIG_HMFS_FAST_READ
int init_util_function(void);
#else
#define init_util_function()	(0)
#endif

static inline int hmfs_add_link(struct dentry *dentry, struct inode *inode)
{
	return __hmfs_add_link(dentry->d_parent->d_inode, &dentry->d_name,
			       inode);
}

#endif

#ifdef TEST
void printtty(const char *format, ...);
#define print printtty
#define tprint printtty
#else
#define print printk
#define tprint printk
#endif

#ifndef _LINUX_HMFS_FS_H
#define _LINUX_HMFS_FS_H

#include <linux/pagemap.h>
#include <linux/types.h>
#include <linux/fs.h>

typedef unsigned long long block_t;	 
typedef __le32 hmfs_hash_t;

/* file types used in inode_info->flags */
enum FILE_TYPE {
	HMFS_FT_UNKNOWN,
	HMFS_FT_REG_FILE,
	HMFS_FT_DIR,
	HMFS_FT_CHRDEV,
	HMFS_FT_BLKDEV,
	HMFS_FT_FIFO,
	HMFS_FT_SOCK,
	HMFS_FT_SYMLINK,
	HMFS_FT_MAX,
};

enum FS_STATE {
	HMFS_NONE,		/* Normal state */
	HMFS_GC,		/* Collect garbage */
	HMFS_RM_CP,		/* Delete a checkpoint */
	HMFS_ADD_CP,	/* Do normal checkpoint */
};

#define HMFS_MAJOR_VERSION		0
#define HMFS_MINOR_VERSION		1

#define NULL_NID				0
#define HMFS_ROOT_INO			3

#define HMFS_DEF_CP_VER			1
#define HMFS_DEF_DEAD_VER		0

#define HMFS_MIN_PAGE_SIZE			4096
#define HMFS_MIN_PAGE_SIZE_BITS		12
#define HMFS_MIN_PAGE_MASK			(~(HMFS_MIN_PAGE_SIZE - 1))
#define HMFS_MAX_PAGE_SIZE_BITS		30		/* 1G block */
#define HMFS_MAX_PAGE_SIZE			(1 << HMFS_MAX_PAGE_SIZE_BITS)
#define HMFS_PAGE_SIZE_BITS_INC		3
#define HMFS_MIN_SEGMENT_SIZE_BITS	21
#define HMFS_MAX_CUR_SEG_COUNT		((HMFS_MAX_PAGE_SIZE_BITS - HMFS_MIN_PAGE_SIZE_BITS) \
									/ HMFS_PAGE_SIZE_BITS_INC + 2)

static const unsigned int HMFS_BLOCK_SIZE_BITS[HMFS_MAX_CUR_SEG_COUNT] = {
	12, 12, 15,	18, 21, 24, 27, 30,
};

#define HMFS_BLOCK_SIZE_BITS(i) (i == 0 ? 12 : (9 + 3 * i))

static const unsigned long HMFS_BLOCK_SIZE[HMFS_MAX_CUR_SEG_COUNT] = {
	1 << HMFS_BLOCK_SIZE_BITS(0),
	1 << HMFS_BLOCK_SIZE_BITS(1),
	1 << HMFS_BLOCK_SIZE_BITS(2),
	1 << HMFS_BLOCK_SIZE_BITS(3),
	1 << HMFS_BLOCK_SIZE_BITS(4),
	1 << HMFS_BLOCK_SIZE_BITS(5),
	1 << HMFS_BLOCK_SIZE_BITS(6),
	1 << HMFS_BLOCK_SIZE_BITS(7),
};

const static unsigned long HMFS_BLOCK_SIZE_4K[HMFS_MAX_CUR_SEG_COUNT] = {
	1,
	1,
	1 << 3,
	1 << 6,
	1 << 9,
	1 << 12,
	1 << 15,
	1 << 18,
};

#define HMFS_MAX_SYMLINK_NAME_LEN	HMFS_MIN_PAGE_SIZE

/* Write orphan inodes in two block */
#define NUM_ORPHAN_BLOCKS		2
#define HMFS_MAX_ORPHAN_NUM		(HMFS_MIN_PAGE_SIZE * NUM_ORPHAN_BLOCKS / 4)

/* This flag is used by sit and nat inode */
#define GFP_HMFS_ZERO	(GFP_NOFS | __GFP_ZERO)

#define set_struct_le64(sb, member, val)		(sb->member = cpu_to_le64(val))
#define set_struct_le32(sb, member, val)		(sb->member = cpu_to_le32(val))
#define set_struct_le16(sb, member, val)		(sb->member = cpu_to_le16(val))

#define set_struct(sb, member, val)	\
			do {						\
				typeof(sb->member) t;			\
				switch (sizeof(t)) {			\
				case 8: set_struct_le64(sb, member, val); break; \
				case 4: set_struct_le32(sb, member, val); break; \
				case 2: set_struct_le16(sb, member, val); break; \
				case 1: (sb->member = val); break; \
				} \
			} while(0)

#define align_page_right(addr) (((addr) + HMFS_MIN_PAGE_SIZE - 1) & HMFS_MIN_PAGE_MASK)
#define align_page_left(addr) ((addr) & HMFS_MIN_PAGE_MASK)

#define hmfs_make_checksum(obj)	crc16(~0, (void *)obj, (char *)(&obj->checksum) - \
				(char *)obj)

/* For directory operations */
#define HMFS_DOT_HASH		0
#define HMFS_DDOT_HASH		HMFS_DOT_HASH
#define HMFS_MAX_HASH		(~((0x3ULL) << 62))
#define HMFS_HASH_COL_BIT	((0x1ULL) << 63)

/* One directory entry slot covers 8bytes-long file name */
#define HMFS_SLOT_LEN		8
#define HMFS_SLOT_LEN_BITS	3

#define GET_DENTRY_SLOTS(x)	((x + HMFS_SLOT_LEN - 1) >> HMFS_SLOT_LEN_BITS)
#define DEF_DIR_LEVEL		0

#define DENTRY_BLOCK(ptr)	((struct hmfs_dentry_block *)ptr)

/* MAX level for dir lookup */
#define MAX_DIR_HASH_DEPTH	63

/* MAX buckets in one level of dir */
#define MAX_DIR_BUCKETS		(1 << ((MAX_DIR_HASH_DEPTH / 2) - 1))

#define SIZE_OF_DIR_ENTRY	11	/* by byte */
#define SIZE_OF_DENTRY_BITMAP	((NR_DENTRY_IN_BLOCK + BITS_PER_BYTE - 1) / \
					BITS_PER_BYTE)
#define SIZE_OF_RESERVED	(HMFS_MIN_PAGE_SIZE - ((SIZE_OF_DIR_ENTRY + \
				HMFS_SLOT_LEN) * \
				NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP))

#define HMFS_JOURNALING_THRESHOLD	4

/* number of all sit logs in checkpoint */
#ifdef CONFIG_HMFS_SMALL_FS
#define NORMAL_ADDRS_PER_INODE	2		/* # of address stored in inode */
#define ADDRS_PER_BLOCK		2			/* # of address stored in direct node  */
#define NIDS_PER_BLOCK		2			/* # of nid stored in indirect node */
#define NUM_NAT_JOURNALS_IN_CP		8
#else
#define NORMAL_ADDRS_PER_INODE	461		/* # of address stored in inode */
#define ADDRS_PER_BLOCK		512			/* # of address stored in direct node  */
#define NIDS_PER_BLOCK		1024		/* # of nid stored in indirect node */
#define NUM_NAT_JOURNALS_IN_CP	(3884 / sizeof(struct hmfs_nat_journal))
#endif
#define HMFS_INLINE_SIZE	(NORMAL_ADDRS_PER_INODE * sizeof(__le64) +\
		5 * sizeof(__le32) + 35)

/* the number of dentry in a block */
/* [4096 - 214 * (11 + 8)] / 8 > 214 */
#define NR_DENTRY_IN_BLOCK			214

#define HMFS_NAME_LEN		255
#define NAT_ADDR_PER_NODE		512		/* # of nat node address stored in nat node */
#define LOG2_NAT_ADDRS_PER_NODE 9
#define BITS_PER_NID 32
#define LOG2_NAT_ENTRY_PER_BLOCK 9	//relatedd to ^
#define NID_TO_BLOCK_OFS(nid)		((nid) % NAT_ENTRY_PER_BLOCK)

#define SIT_ENTRY_SIZE (sizeof(struct hmfs_sit_entry))
#define SIT_ENTRY_PER_BLOCK (HMFS_MIN_PAGE_SIZE / SIT_ENTRY_SIZE)

/* Nid index in inode */
#define NODE_DIR1_BLOCK		(NORMAL_ADDRS_PER_INODE + 1)
#define NODE_DIR2_BLOCK		(NORMAL_ADDRS_PER_INODE + 2)
#define NODE_IND1_BLOCK		(NORMAL_ADDRS_PER_INODE + 3)
#define NODE_IND2_BLOCK		(NORMAL_ADDRS_PER_INODE + 4)
#define NODE_DIND_BLOCK		(NORMAL_ADDRS_PER_INODE + 5)

/* SSA */
#define SUM_TYPE_DATA		(0)		/* data block */
#define SUM_TYPE_XDATA		(1) 	/* extended data block */
#define SUM_TYPE_INODE		(2)		/* inode block */
#define SUM_TYPE_DN			(3)		/* direct block */
#define SUM_TYPE_IDN		(4)		/* indirect block */
#define SUM_TYPE_NATN		(5)		/* nat node block */
#define SUM_TYPE_NATD		(6)		/* nat data block */
#define SUM_TYPE_CP			(7)		/* checkpoint block */
#define SUM_TYPE_ORPHAN		(8)		/* orphan block */


/* For superblock */
struct hmfs_super_block {
	__le64 init_size;	/* total # of Bytes */
	__le64 segment_count;	/* total # of segments */
	__le64 segment_count_ssa;	/* # of segments for SSA */
	__le64 segment_count_main;	/* # of segments for main area */
	__le64 user_block_count;	/* # of user blocks */
	__le64 cp_page_addr;	/* start block address of checkpoint */
	__le64 sit_blkaddr;	/* start block address of SIT area */
	__le64 ssa_blkaddr;	/* start block address of SSA */
	__le64 main_blkaddr;	/* start block address of main area */
	__le32 magic;		/* Magic Number */
	__le32 segment_count_sit;	/* # of segments for SIT */
	__le16 major_ver;	/* Major Version */
	__le16 minor_ver;	/* Minor Version */
	u8 nat_height;

	__le16 checksum;
} __attribute__ ((packed));

/* hmfs inode */
/*
 * What is the difference between i_size and i_blocks?
 * i_size is used to determine the end of data blocks,
 * i.e. end_blk = i_size >> HMFS_PAGE_SIZE_BITS, is the
 * last valid data block. But there maybe no data in that
 * block and the block whose id is small than end_blk.
 * i_blocks is the exact number of data blocks that
 * an inode contain.
 */
struct hmfs_inode {
	__le64 i_size;		/* file size in bytes */
	__le64 i_blocks;	/* file size in blocks */
	__le64 i_atime;		/* access time */
	__le64 i_ctime;		/* change time */
	__le64 i_mtime;		/* modification time */
	__le64 i_xattr_addr;	/* address to save xattr */
	__le64 i_acl_addr;	/* address to save acl */
	__le32 i_uid;		/* user ID */
	__le32 i_gid;		/* group ID */
	__le32 i_links;		/* links count */
	__le32 i_current_depth;	/* only for directory depth */
	__le32 i_flags;		/* file attributes */
	__le32 i_pino;		/* parent inode number */
	__le32 i_namelen;	/* file name length */
	__le32 i_generation;	/* file version (for NFS) */
	__le16 i_mode;		/* file mode */
	__u8 i_advise;		/* file hints */
	__u8 i_inline;		/* file inline flags */
	__u8 i_dir_level;	/* dentry_level for large dir */
	__u8 i_blk_type;	/* data block type */
	__u8 i_name[HMFS_NAME_LEN];	/* file name for SPOR */

	union {
		struct {
			__u8 i_pad[35];
			__le64 i_addr[NORMAL_ADDRS_PER_INODE];	/* Pointers to data blocks */

			/* direct(2), indirect(2), double_indirect(1) node id */
			__le32 i_nid[5];
		} __attribute__ ((packed));
		/* Should modify HMFS_INLINE_SIZE once change size of i_pad */
		__u8 inline_content[HMFS_INLINE_SIZE];
	};
} __attribute__ ((packed));

/* hmfs node */
struct direct_node {
	__le64 addr[ADDRS_PER_BLOCK];	/* array of data block address */
} __attribute__ ((packed));

struct indirect_node {
	__le32 nid[NIDS_PER_BLOCK];	/* array of data block address */
} __attribute__ ((packed));

struct hmfs_node {
	/* can be one of three types: inode, direct, and indirect types */
	union {
		struct hmfs_inode i;
		struct direct_node dn;
		struct indirect_node in;
	};
} __attribute__ ((packed));

/* nat node */
struct hmfs_nat_node {
	__le64 addr[NAT_ADDR_PER_NODE];
} __attribute__ ((packed));

struct hmfs_nat_entry {
	__le32 ino;		/* inode number */
	__le64 block_addr;	/* block address */
} __attribute__ ((packed));

#define NAT_ENTRY_PER_BLOCK		(HMFS_MIN_PAGE_SIZE / sizeof(struct hmfs_nat_entry))
/* nat data block */
struct hmfs_nat_block {
	struct hmfs_nat_entry entries[NAT_ENTRY_PER_BLOCK];
} __attribute__ ((packed));

struct hmfs_nat_journal {
	__le32 nid;
	struct hmfs_nat_entry entry;
} __attribute__ ((packed));

/* sit inode */
struct hmfs_sit_entry {
	__le32 mtime;		/* segment age for cleaning */
	__le16 vblocks;		/* reference above */
	u8 type;
	u8 waste;
} __attribute__ ((packed));

struct hmfs_sit_log_entry {
	__le32 segno;
	__le32 mtime;
	__le16 vblocks;
	u8 type;
} __attribute__ ((packed));

struct hmfs_sit_log_segment {
	struct hmfs_sit_log_entry entries[1];
} __attribute__ ((packed));

/* One directory entry slot representing HMFS_SLOT_LEN-sized file name */
struct hmfs_dir_entry {
	__le32 hash_code;	/* hash code of file name */
	__le32 ino;		/* inode number */
	__le16 name_len;	/* lengh of file name */
	__u8 file_type;		/* file type */
} __attribute__ ((packed));

/* 4KB-sized directory entry block */
struct hmfs_dentry_block {
	/* validity bitmap for directory entries in each block */
	__u8 dentry_bitmap[SIZE_OF_DENTRY_BITMAP];
	__u8 reserved[SIZE_OF_RESERVED];
	struct hmfs_dir_entry dentry[NR_DENTRY_IN_BLOCK];
	__u8 filename[NR_DENTRY_IN_BLOCK][HMFS_SLOT_LEN];
} __attribute__ ((packed));

#define NR_DENTRY_IN_INLINE_INODE	((HMFS_INLINE_SIZE - SIZE_OF_DENTRY_BITMAP -\
				SIZE_OF_RESERVED) / (sizeof(struct hmfs_dir_entry) + \
						HMFS_SLOT_LEN))

#define NUM_SIT_LOGS_SEG		10
/* checkpoint */
struct hmfs_checkpoint {
	__le64 alloc_block_count;	/* # of alloc blocks in main area */
	__le64 valid_block_count;	/* # of valid blocks in main area */
	__le64 free_segment_count;	/* # of free segments in main area */
	__le64 prev_cp_addr;	/* previous checkpoint address */
	__le64 next_cp_addr;	/* next checkpoint address */
	__le64 nat_addr;	/* nat file physical address bias */
	__le64 orphan_addrs[NUM_ORPHAN_BLOCKS];	/* Address of orphan inodes */
	__le32 checkpoint_ver;	/* checkpoint block version number */
	__le32 valid_inode_count;	/* Total number of valid inodes */
	__le32 valid_node_count;	/* total number of valid nodes */

	/* information of current segments */
	__le32 cur_segno[HMFS_MAX_CUR_SEG_COUNT];
	__le32 cur_blkoff[HMFS_MAX_CUR_SEG_COUNT];

	__le32 next_scan_nid;
	__le32 elapsed_time;

	__le32 gc_logs;		/* segno of gc log area */
	__le32 nr_gc_segs;

	__u8 state;				/* fs state, use set_fs_state */

	__u8 nr_segs;
	__le16 nr_logs;

	/* 160 bytes */

	/*
	 * HMFS_GC_DATA: it represents (segno + 1) of current segment,
	 * because segment 0 is a valid segment, and we use state_arg 0
	 * to represent free state, thus we need add 1 to split segment 0 
	 * ans state
	 * HMFS_ADD_CP : represents flushing CP block
	 */
	__le64 state_arg;		/* fs state arguments, for recovery */
	__le64 state_arg_2;

	__le32 sit_logs[NUM_SIT_LOGS_SEG];	/* segment number that records sit logs */


	/* NAT */
	struct hmfs_nat_journal nat_journals[NUM_NAT_JOURNALS_IN_CP];
} __attribute__ ((packed));

/* extended blocks */
#define HMFS_X_BLOCK_TAG_XATTR		((unsigned long)\
				(&(((struct hmfs_inode *)NULL)->i_xattr_addr)))
#define HMFS_X_BLOCK_TAG_ACL		((unsigned long)\
				(&(((struct hmfs_inode *)NULL)->i_acl_addr)))

const static int xblock_tags[] = {
	HMFS_X_BLOCK_TAG_XATTR,
	HMFS_X_BLOCK_TAG_ACL,
};

#define XBLOCK_ADDR(inode, tag)		le64_to_cpu(*((__le64 *)JUMP(inode, tag)))

#define for_each_xblock(inode, child_addr, i)	\
		for (i = 0, child_addr = XBLOCK_ADDR(inode, xblock_tags[0]);	\
						i < ARRAY_SIZE(xblock_tags); i++,	\
						child_addr = XBLOCK_ADDR(inode, xblock_tags[i]))


/* Type conversion */
#define HMFS_NAT_NODE(ptr)		((struct hmfs_nat_node *)(ptr))
#define HMFS_NAT_BLOCK(ptr)		((struct hmfs_nat_block *)(ptr))
#define HMFS_INODE(ptr)			((struct hmfs_inode *)(ptr))
#define DIRECT_NODE(ptr)		((struct direct_node *)(ptr))
#define HMFS_CHECKPOINT(ptr)	((struct hmfs_checkpoint *)(ptr))
#define HMFS_SUMMARY(ptr)		((struct hmfs_summary *)(ptr))
#define HMFS_SUPER_BLOCK(ptr)	((struct hmfs_super_block *)(ptr))


static inline void hmfs_memcpy(void *dest, void *src, unsigned long length)
{
	memcpy(dest, src, length);
}

/*
 * For segment summary
 *
 * One summary block contains exactly 512 summary entries, which represents
 * exactly 2MB segment by default. Not allow to change the basic units.
 *
 * NOTE: For initializing fields, you must use set_summary
 *
 * - If data page, nid represents dnode's nid
 * - If node page, nid represents the node page's nid.
 * - If nat node/data page, nid represent its node index in the whole B-Tree
 *
 * For ofs_in_node,
 * - If data page, it represent index in direct node
 * - If node page, it represent index in nat block
 */
/* a summary entry for a 4KB-sized block in a segment */
struct hmfs_summary {
	__le32 nid;	
	__le32 start_version;
	__le16 ofs_in_node;	/* offset in parent node */
	__le16 bt;		/* valid bit and type */
	__le32 waste_1;
} __attribute__ ((packed));

static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t) dword << 32) | dword;

	asm volatile ("movl %%edx,%%ecx\n"
		      "andl $63,%%edx\n"
		      "shrl $6,%%ecx\n"
		      "jz 9f\n"
		      "1:      movnti %%rax,(%%rdi)\n"
		      "2:      movnti %%rax,1*8(%%rdi)\n"
		      "3:      movnti %%rax,2*8(%%rdi)\n"
		      "4:      movnti %%rax,3*8(%%rdi)\n"
		      "5:      movnti %%rax,4*8(%%rdi)\n"
		      "8:      movnti %%rax,5*8(%%rdi)\n"
		      "7:      movnti %%rax,6*8(%%rdi)\n"
		      "8:      movnti %%rax,7*8(%%rdi)\n"
		      "leaq 64(%%rdi),%%rdi\n"
		      "decl %%ecx\n"
		      "jnz 1b\n"
		      "9:     movl %%edx,%%ecx\n"
		      "andl $7,%%edx\n"
		      "shrl $3,%%ecx\n"
		      "jz 11f\n"
		      "10:     movnti %%rax,(%%rdi)\n"
		      "leaq 8(%%rdi),%%rdi\n"
		      "decl %%ecx\n"
		      "jnz 10b\n"
		      "11:     movl %%edx,%%ecx\n"
		      "shrl $2,%%ecx\n"
		      "jz 12f\n"
		      "movnti %%eax,(%%rdi)\n"
		      "12:\n":"=D" (dummy1), "=d"(dummy2):"D"(dest), "a"(qword),
		      "d"(length):"memory", "rcx");
}

//FIXME: is this mov atomically
/* use CPU instructions to atomically write up to 8 bytes */
static inline void hmfs_memcpy_atomic(void *dest, const void *src, u8 size)
{
	switch (size) {
	case 1: { 
		volatile u8 *daddr = dest;
		const u8 *saddr = src;
		*daddr = *saddr;
		break;
	}
	case 2: {
		volatile __le16 *daddr = dest;
		const u16 *saddr = src;
		*daddr = cpu_to_le16(*saddr);
		break;
	}
	case 4: {
		volatile __le32 *daddr = dest;
		const u32 *saddr = src;
		*daddr = cpu_to_le32(*saddr);
		break;
	}
	case 8: {
		volatile __le64 *daddr = dest;
		const u64 *saddr = src;
		*daddr = cpu_to_le64(*saddr);
		break;
	}
	default:
		BUG();
	}
}

static inline void set_fs_state_arg(struct hmfs_checkpoint *hmfs_cp, u64 value)
{
	hmfs_memcpy_atomic(&hmfs_cp->state_arg, &value, 8);
}

static inline void set_fs_state_arg_2(struct hmfs_checkpoint *hmfs_cp, u64 value)
{
	hmfs_memcpy_atomic(&hmfs_cp->state_arg_2, &value, 8);
}

static inline void set_fs_state(struct hmfs_checkpoint *hmfs_cp, u8 state)
{
	set_fs_state_arg(hmfs_cp, 0);
	hmfs_memcpy_atomic(&hmfs_cp->state, &state, 1);
}

static inline struct hmfs_super_block *next_super_block(
				struct hmfs_super_block *raw_super)
{
	unsigned int size = sizeof(struct hmfs_super_block);

	size = align_page_right(size);
	raw_super = HMFS_SUPER_BLOCK(((char *)raw_super) + size);

	return raw_super;
}

#endif /* _LINUX_HMFS_FS_H */

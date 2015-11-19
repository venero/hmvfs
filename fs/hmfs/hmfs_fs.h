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

#define HMFS_MAJOR_VERSION		0
#define HMFS_MINOR_VERSION		1

#define HMFS_ROOT_INO			3

#define HMFS_DEF_CP_VER			1
#define HMFS_DEF_DEAD_VER		0

#define HMFS_PAGE_SIZE			4096
#define HMFS_PAGE_SIZE_BITS		12
#define HMFS_PAGE_MASK			(~(HMFS_PAGE_SIZE - 1))

#define HMFS_PAGE_PER_SEG		512	/* 2M */
#define HMFS_PAGE_PER_SEG_BITS	9
#define HMFS_SEGMENT_SIZE_BITS	21
#define HMFS_SEGMENT_SIZE		(1 << HMFS_SEGMENT_SIZE_BITS)
#define HMFS_SEGMENT_MASK		(~(HMFS_SEGMENT_SIZE - 1))

#define HMFS_MAX_SYMLINK_NAME_LEN	HMFS_PAGE_SIZE

#define HMFS_MAX_ORPHAN_NUM		(HMFS_PAGE_SIZE / 8)

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

#define align_page_right(addr) (((addr) + HMFS_PAGE_SIZE - 1) & HMFS_PAGE_MASK)
#define align_page_left(addr) ((addr) & HMFS_PAGE_MASK)
#define align_segment_right(addr) (((addr) + HMFS_SEGMENT_SIZE - 1) & HMFS_SEGMENT_MASK)
#define align_segment_left(addr) ((addr) & HMFS_SEGMENT_MASK)

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

/* the number of dentry in a block */
/* [4096 - 214 * (11 + 8)] / 8 > 214 */
#define NR_DENTRY_IN_BLOCK	214

/* MAX level for dir lookup */
#define MAX_DIR_HASH_DEPTH	63

/* MAX buckets in one level of dir */
#define MAX_DIR_BUCKETS		(1 << ((MAX_DIR_HASH_DEPTH / 2) - 1))

#define SIZE_OF_DIR_ENTRY	11	/* by byte */
#define SIZE_OF_DENTRY_BITMAP	((NR_DENTRY_IN_BLOCK + BITS_PER_BYTE - 1) / \
					BITS_PER_BYTE)
#define SIZE_OF_RESERVED	(HMFS_PAGE_SIZE - ((SIZE_OF_DIR_ENTRY + \
				HMFS_SLOT_LEN) * \
				NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP))


#define NUM_NAT_JOURNALS_IN_CP	8

#ifdef CONFIG_HMFS_SMALL_FS
#define NORMAL_ADDRS_PER_INODE	2		/* # of address stored in inode */
#define ADDRS_PER_BLOCK		2			/* # of address stored in direct node  */
#define NIDS_PER_BLOCK		2			/* # of nid stored in indirect node */
#else
#define NORMAL_ADDRS_PER_INODE	467		/* # of address stored in inode */
#define ADDRS_PER_BLOCK		512			/* # of address stored in direct node  */
#define NIDS_PER_BLOCK		1024		/* # of nid stored in indirect node */
#endif

#define HMFS_NAME_LEN		255
#define NAT_ADDR_PER_NODE		512		/* # of nat node address stored in nat node */
#define LOG2_NAT_ADDRS_PER_NODE 9
#define BITS_PER_NID 32
#define LOG2_NAT_ENTRY_PER_BLOCK 9	//relatedd to ^
#define NID_TO_BLOCK_OFS(nid)		((nid) % NAT_ENTRY_PER_BLOCK)

#define SIT_ENTRY_SIZE (sizeof(struct hmfs_sit_entry))
#define SIT_ENTRY_PER_BLOCK (HMFS_PAGE_SIZE / SIT_ENTRY_SIZE)

/* Nid index in inode */
#define NODE_DIR1_BLOCK		(NORMAL_ADDRS_PER_INODE + 1)
#define NODE_DIR2_BLOCK		(NORMAL_ADDRS_PER_INODE + 2)
#define NODE_IND1_BLOCK		(NORMAL_ADDRS_PER_INODE + 3)
#define NODE_IND2_BLOCK		(NORMAL_ADDRS_PER_INODE + 4)
#define NODE_DIND_BLOCK		(NORMAL_ADDRS_PER_INODE + 5)

/* SSA */
#define HMFS_SUMMARY_BLOCK_SIZE		(HMFS_PAGE_SIZE << 1)
#define SUM_ENTRY_PER_BLOCK (HMFS_SUMMARY_BLOCK_SIZE / sizeof(struct hmfs_summary))
#define SUM_TYPE_DATA		(0)	//      data block
#define SUM_TYPE_INODE		(1)	//      inode block
#define SUM_TYPE_DN			(2)	//      direct block
#define SUM_TYPE_NATN		(3)	//      nat node block
#define SUM_TYPE_NATD		(4)	//      nat data block
#define SUM_TYPE_IDN		(5)	//      indirect block
#define SUM_TYPE_CP			(6)	//      checkpoint block



/* For superblock */
struct hmfs_super_block {
	__le32 magic;		/* Magic Number */
	__le16 major_ver;	/* Major Version */
	__le16 minor_ver;	/* Minor Version */
	__le64 segment_count;	/* total # of segments */
	__le64 init_size;	/* total # of Bytes */

	__le32 segment_count_sit;	/* # of segments for SIT */
	__le64 segment_count_ssa;	/* # of segments for SSA */
	__le64 segment_count_main;	/* # of segments for main area */
	__le64 user_block_count;	/* # of user blocks */

	__le64 cp_page_addr;	/* start block address of checkpoint */
	__le64 sit_blkaddr;	/* start block address of SIT area */
	__le64 ssa_blkaddr;	/* start block address of SSA */
	__le64 main_blkaddr;	/* start block address of main area */

	__le16 checksum;
	u8 nat_height;

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
	__le16 i_mode;		/* file mode */
	__u8 i_advise;		/* file hints */
	__u8 i_inline;		/* file inline flags */
	__le32 i_uid;		/* user ID */
	__le32 i_gid;		/* group ID */
	__le32 i_links;		/* links count */
	__le64 i_size;		/* file size in bytes */
	__le64 i_blocks;	/* file size in blocks */
	__le64 i_atime;		/* access time */
	__le64 i_ctime;		/* change time */
	__le64 i_mtime;		/* modification time */
	__le32 i_generation;	/* file version (for NFS) */
	__le32 i_current_depth;	/* only for directory depth */
	__le32 i_xattr_nid;	/* nid to save xattr */
	__le32 i_flags;		/* file attributes */
	__le32 i_pino;		/* parent inode number */
	__le32 i_namelen;	/* file name length */
	__u8 i_name[HMFS_NAME_LEN];	/* file name for SPOR */
	__u8 i_dir_level;	/* dentry_level for large dir */

	__le64 i_addr[NORMAL_ADDRS_PER_INODE];	/* Pointers to data blocks */

	/* direct(2), indirect(2), double_indirect(1) node id */
	__le32 i_nid[5];
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

#define NAT_ENTRY_PER_BLOCK		(HMFS_PAGE_SIZE/sizeof(struct hmfs_nat_entry))
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
	__le16 waste;
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

/* checkpoint */
struct hmfs_checkpoint {
	__le32 checkpoint_ver;	/* checkpoint block version number */
	__le64 alloc_block_count;	/* # of alloc blocks in main area */
	__le64 valid_block_count;	/* # of valid blocks in main area */
	__le64 free_segment_count;	/* # of free segments in main area */

	/* information of current node segments */
	__le32 cur_node_segno;
	__le16 cur_node_blkoff;
	/* information of current data segments */
	__le32 cur_data_segno;
	__le16 cur_data_blkoff;

	__le64 prev_cp_addr;	/* previous checkpoint address */
	__le64 next_cp_addr;	/* next checkpoint address */

	__le32 valid_inode_count;	/* Total number of valid inodes */
	__le32 valid_node_count;	/* total number of valid nodes */

	__le64 nat_addr;	/* nat file physical address bias */

	__le64 orphan_addr;

	__le32 next_scan_nid;

	__le32 elapsed_time;

	/* NAT */
	struct hmfs_nat_journal nat_journals[NUM_NAT_JOURNALS_IN_CP];

	__le16 checksum;
} __attribute__ ((packed));



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
	__le32 nid;		/* parent node id */
	__le32 dead_version;	/* version of checkpoint delete this block */
	__le32 start_version;
	__le16 count;		/*  */
	__le16 ont;		/* ofs_in_node and type */
} __attribute__ ((packed));

/* 8KB-sized summary block structure */
struct hmfs_summary_block {
	struct hmfs_summary entries[SUM_ENTRY_PER_BLOCK];
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

static inline struct hmfs_super_block *next_super_block(struct hmfs_super_block
							*raw_super)
{
	unsigned int size = sizeof(struct hmfs_super_block);

	size = align_page_right(size);
	raw_super = (struct hmfs_super_block *)(((char *)raw_super) + size);

	return raw_super;
}

#endif /* _LINUX_HMFS_FS_H */

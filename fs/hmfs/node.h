#ifndef HMFS_NODE_H
#define HMFS_NODE_H

#include "hmfs.h"
#include "hmfs_fs.h"

#define FREE_NID_BLK_SIZE		(PAGE_SIZE * 2)
#define BUILD_FREE_NID_COUNT	(PAGE_SIZE / sizeof(nid_t))

#define IS_NAT_ROOT(nid)	(!nid)

#define NAT_NODE_OFS_BITS				27
#define NAT_NODE_OFS_MASK				((1 << NAT_NODE_OFS_BITS) - 1)

#define GET_NAT_NODE_HEIGHT(nid)		((nid) >> NAT_NODE_OFS_BITS)
#define GET_NAT_NODE_OFS(nid)			((nid) & NAT_NODE_OFS_MASK)
#define MAKE_NAT_NODE_NID(height, ofs)	(((height) << NAT_NODE_OFS_BITS) |\
				((ofs) & NAT_NODE_OFS_MASK))

#define NAT_FLAG_FREE_NID			0x01
#define NAT_FLAG_JOURNAL			0x02

/* vector size for gang look-up from nat cache that consist of radix tree */
#define NATVEC_SIZE					64

// this is the node info from node
struct node_info {
	nid_t nid;
	nid_t ino;
	block_t blk_addr;
	unsigned long long index;
	char flag;
	nid_t next_warp;
	int current_warp;
	ver_t begin_version;
	unsigned long nread, nwrite;
	unsigned long long sread, swrite;
};

struct nat_entry {
	struct list_head list;
	struct node_info ni;
};

struct warp_candidate_entry {
	struct list_head list;
	struct node_info *nip;
};

struct free_nid {
	nid_t nid;
};

/*
 * ?????
 */
#define make_free_nid(nid, free)		((nid) | (((u32)free) << 31))
#define get_free_nid(nid)			(((nid) << 1) >> 1)
#define is_dirty_free_nid(nid)		(nid >> 31)


static inline void set_node_info_this_version(struct hmfs_sb_info *sbi, struct node_info *ni){
	ni->begin_version = sbi->cm_info->new_version;
}

static inline void node_info_to_raw_nat(struct node_info *ni,
					struct hmfs_nat_entry *ne)
{
	ne->ino = cpu_to_le32(ni->ino);
	ne->block_addr = cpu_to_le64(ni->blk_addr);
}

static inline void node_info_from_raw_nat(struct hmfs_sb_info *sbi, struct node_info *ni,
					  struct hmfs_nat_entry *ne)
{
	ni->ino = le32_to_cpu(ne->ino);
	ni->blk_addr = le64_to_cpu(ne->block_addr);
	ni->current_warp = FLAG_WARP_NORMAL;
	ni->begin_version = sbi->cm_info->new_version;
	ni->nread=0;
	ni->nwrite=0;
	ni->sread=0;
	ni->swrite=0;
	// hmfs_dbg("That %d %d\n", ni->begin_version, sbi->cm_info->new_version);
}

static inline bool is_checkpoint_node(char sum_type)
{
	BUG_ON(sum_type >= SUM_TYPE_NATN && sum_type <= SUM_TYPE_CP &&
			sum_type != SUM_TYPE_NATN && sum_type != SUM_TYPE_NATD 
			&& sum_type != SUM_TYPE_CP);

	return sum_type >= SUM_TYPE_NATN && sum_type <= SUM_TYPE_CP;
}

static inline char hmfs_get_nat_height(unsigned long long initsize)
{
	unsigned long long max_nid;
	unsigned long long nr_blk = 0, nr_current = NAT_ADDR_PER_NODE;
	char height = 1;

	if (initsize >> (BITS_PER_NID + HMFS_MIN_PAGE_SIZE_BITS))
		max_nid = 1 << (BITS_PER_NID - 1);
	else
		max_nid = initsize >> HMFS_MIN_PAGE_SIZE_BITS;

	if (max_nid <= NAT_ENTRY_PER_BLOCK)
		return 0;

	nr_blk = (max_nid + NAT_ENTRY_PER_BLOCK - 1) / NAT_ENTRY_PER_BLOCK;

	while (nr_current < nr_blk) {
		height++;
		nr_current *= NAT_ADDR_PER_NODE;
	}

	return height;
}

#endif

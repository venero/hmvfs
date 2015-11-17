#ifndef NODE_H
#define NODE_H

#include "hmfs.h"
#include "hmfs_fs.h"

#define FREE_NID_BLK_SIZE		(HMFS_PAGE_SIZE * 2)
#define BUILD_FREE_NID_COUNT	(HMFS_PAGE_SIZE / sizeof(nid_t))

#define IS_NAT_ROOT(nid)	(!nid)

#define NAT_NODE_OFS_BITS				27
#define NAT_NODE_OFS_MASK				((1 << NAT_NODE_OFS_BITS) - 1)

#define GET_NAT_NODE_HEIGHT(nid)		((nid) >> NAT_NODE_OFS_BITS)
#define GET_NAT_NODE_OFS(nid)			((nid) & NAT_NODE_OFS_MASK)
#define MAKE_NAT_NODE_NID(height, ofs)	(((height) << NAT_NODE_OFS_BITS) | ((ofs) & NAT_NODE_OFS_MASK))

struct node_info {
	nid_t nid;
	nid_t ino;
	block_t blk_addr;
	ver_t version;
};

struct nat_entry {
	struct list_head list;
	struct node_info ni;
};

struct free_nid {
	nid_t nid;
};

/*
 * ?????
 */
#define make_free_nid(nid,free)		((nid) | (((u32)free) << 31))
#define get_free_nid(nid)			(((nid) << 1) >> 1)

static inline void node_info_to_raw_nat(struct node_info *ni,
					struct hmfs_nat_entry *ne)
{
	ne->ino = cpu_to_le32(ni->ino);
	ne->block_addr = cpu_to_le64(ni->blk_addr);
}

static inline void node_info_from_raw_nat(struct node_info *ni,
					  struct hmfs_nat_entry *ne)
{
	ni->ino = le32_to_cpu(ne->ino);
	ni->blk_addr = le64_to_cpu(ne->block_addr);
}

static inline nid_t get_nid(struct hmfs_node *hn, int off, bool in_i)
{
	if (in_i) {
		return le32_to_cpu(hn->i.i_nid[off - NODE_DIR1_BLOCK]);
	}
	return le32_to_cpu(hn->in.nid[off]);
}

static inline void set_nid(struct hmfs_node *hn, int off, nid_t nid, bool in_i)
{
	if (in_i)
		hn->i.i_nid[off - NODE_DIR1_BLOCK] = cpu_to_le32(nid);
	else
		hn->in.nid[off] = cpu_to_le32(nid);
}

static inline char hmfs_get_nat_height(unsigned long long initsize)
{
	unsigned long long max_nid;
	unsigned long long nr_blk = 0, nr_current = NAT_ADDR_PER_NODE;
	char height = 1;

	if (initsize >> (BITS_PER_NID + HMFS_PAGE_SIZE_BITS))
		max_nid = 1 << (BITS_PER_NID - 1);
	else
		max_nid = initsize >> HMFS_PAGE_SIZE_BITS;

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

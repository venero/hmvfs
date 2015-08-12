#ifndef NODE_H
#define NODE_H

#include "hmfs.h"
#include "hmfs_fs.h"

#define FREE_NID_BLK_SIZE		(HMFS_PAGE_SIZE * 2)
#define BUILD_FREE_NID_COUNT	(HMFS_PAGE_SIZE / sizeof(nid_t))

struct node_info {
	nid_t nid;
	nid_t ino;
	unsigned long blk_addr;
	unsigned int version;
};

struct nat_entry {
	struct list_head list;
	struct node_info ni;
};

struct free_nid {
	nid_t nid;
};

#define make_free_nid(nid,free)		(nid | ((u64)free << 63))
#define get_free_nid(nid)			((nid << 1) >> 1)

static inline void node_info_from_raw_nat(struct node_info *ni,
					  struct hmfs_nat_entry *ne)
{
	ni->ino = le64_to_cpu(ne->ino);
	ni->blk_addr = le64_to_cpu(ne->block_addr);
}

static inline nid_t get_nid(struct hmfs_node *hn, int off, bool in_i)
{
	if (in_i) {
		return le64_to_cpu(hn->i.i_nid[off - NODE_DIR1_BLOCK]);
	}
	return le64_to_cpu(hn->in.nid[off]);
}

static inline void set_nid(struct hmfs_node *hn, int off, nid_t nid, bool in_i)
{
	if (in_i)
		hn->i.i_nid[off - NODE_DIR1_BLOCK] = cpu_to_le64(nid);
	else
		hn->in.nid[off] = cpu_to_le64(nid);
}

#endif

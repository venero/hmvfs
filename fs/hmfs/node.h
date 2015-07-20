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

static inline void node_info_from_raw_nat(struct node_info *ni,
					  struct hmfs_nat_entry *ne)
{
	ni->ino = le64_to_cpu(ne->ino);
	ni->blk_addr = le64_to_cpu(ne->block_addr);
}
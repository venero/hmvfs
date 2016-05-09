#include <linux/fs.h>
#include <uapi/linux/magic.h>

#include "hmfs_fs.h"

/* Prepare SSA and SIT entries for each device */
static void hmfs_mk_metadata(struct hmfs_sb_info *sbi, uint64_t area_ofs, int dev_index)
{
	struct hmfs_dev_info *dev_i = DEV_INFO(sbi, dev_index);
	uint32_t segment_size_bits, segment_size;
	uint64_t end_ofs;
	pgc_t nr_main_segments, nr_ssa_pages;
	uint32_t ssa_blk_size;

	segment_size_bits = calculate_segment_size_bits(sbi->max_page_size_bits);
	segment_size = calculate_segment_size(1 << sbi->max_page_size_bits);
	end_ofs = dev_i->initsize & (~(segment_size - 1));

	ssa_blk_size = (segment_size >> HMFS_MIN_PAGE_SIZE_BITS) * sizeof(struct hmfs_summary);
	nr_main_segments = div64_u64(end_ofs - area_ofs, segment_size + SIT_ENTRY_SIZE + ssa_blk_size);
	nr_ssa_pages = (nr_main_segments * ssa_blk_size + HMFS_MIN_PAGE_SIZE - 1) >>
			HMFS_MIN_PAGE_SIZE_BITS;

	dev_i->ssa_entries = JUMP(dev_i->virt_addr, area_ofs);
	
	area_ofs += (nr_ssa_pages << HMFS_MIN_PAGE_SIZE_BITS);
	dev_i->sit_entries = JUMP(dev_i->virt_addr, area_ofs);

	area_ofs += nr_main_segments * SIT_ENTRY_SIZE;
	dev_i->main_ofs = (area_ofs + segment_size - 1) & (~(segment_size - 1));
	dev_i->main_area = JUMP(dev_i->virt_addr, dev_i->main_ofs);
}

static void make_ssa(struct hmfs_sb_info *sbi, uint32_t ofs, nid_t nid, uint8_t type)
{
	struct hmfs_dev_info *dev_i = DEV_INFO(sbi, 0);
	struct hmfs_summary *sum;

	ofs -= DISTANCE(dev_i->main_area, dev_i->virt_addr);
	sum = JUMP(dev_i->ssa_entries, ofs >> HMFS_MIN_PAGE_SIZE_BITS);
	make_summary_entry(sum, nid, HMFS_DEF_CP_VER, 0, type);
	set_summary_valid_bit(sum);
}

/* Init root inode and return offset of root inode */
static uint64_t hmfs_mk_root(struct hmfs_sb_info *sbi, uint32_t *nofs, uint32_t *dofs)
{
	struct hmfs_inode *hi = JUMP(DEV_INFO(sbi, 0)->main_area, *nofs);
	struct hmfs_dentry_block *dent_blk = JUMP(DEV_INFO(sbi, 0)->main_area, *dofs);
	uint64_t ret_ofs = *nofs;

	hi->i_mode = cpu_to_le16(0x41ed);
	hi->i_links = cpu_to_le32(2);

#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
	hi->i_uid = cpu_to_le32(sbi->uid.val);
	hi->i_gid = cpu_to_le32(sbi->gid.val);
#else
	hi->i_uid = cpu_to_le32(sbi->uid);
	hi->i_gid = cpu_to_le32(sbi->gid);
#endif

	hi->i_size = cpu_to_le64(HMFS_BLOCK_SIZE[SEG_DATA_INDEX] * 1);
	hi->i_blocks = cpu_to_le64(2);

	hi->i_atime = cpu_to_le64(get_seconds());
	hi->i_ctime = hi->i_atime;
	hi->i_mtime = hi->i_atime;
	hi->i_generation = 0;
	hi->i_flags = 0;
	hi->i_namelen = cpu_to_le32(1);
	memcpy(&(root_node->i.i_name), "/", 1);
	hi->i_current_depth = cpu_to_le32(1);
	hi->i_dir_level = DEF_DIR_LEVEL;
	hi->i_blk_type = SEG_DATA_INDEX;

	ADDR_INIT_PHYS(&hi->i_addr[0], 0, *dofs);
	dent_blk->dentry[0].hash_code = HMFS_DOT_HASH;
	dent_blk->dentry[0].ino = cpu_to_le32(HMFS_ROOT_INO);
	dent_blk->dentry[0].name_len = cpu_to_le16(1);
	dent_blk->dentry[0].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[0], ".", 1);

	dent_blk->dentry[1].hash_code = HMFS_DDOT_HASH;
	dent_blk->dentry[1].ino = cpu_to_le32(HMFS_ROOT_INO);
	dent_blk->dentry[1].name_len = cpu_to_le16(2);
	dent_blk->dentry[1].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[1], "..", 2);

	dent_blk->dentry_bitmap[0] = (1 << 1) | (1 << 0);

	make_ssa(sbi, *nofs, HMFS_ROOT_INO, SUM_TYPE_INODE);
	make_ssa(sbi, *dofs, HMFS_ROOT_INO, SUM_TYPE_DATA);
	*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];
	*dofs += HMFS_BLOCK_SIZE[SEG_DATA_INDEX];
	return ret_ofs;
}

static void hmfs_init_sit(struct hmfs_sb_info *sbi, uint32_t *nofs, uint32_t *dofs)
{
	struct hmfs_sit_entry *sit_entry = DEV_INFO(sbi, 0)->sit_entries;
	uint32_t main_ofs = DEV_INFO(sbi, 0)->main_ofs;
	uint32_t segment_size = calculate_segment_size(1 << sbi->max_page_size_bits);
	uint16_t nr_nodes = (*nofs - main_ofs) >> HMFS_MIN_PAGE_SIZE_BITS,
		  nr_data = (*dofs - main_ofs - segment_size) >> HMFS_MIN_PAGE_SIZE_BITS;

	sit_entry->mtime = cpu_to_le32(get_seconds());
	sit_entry->vblocks = cpu_to_le16(nr_nodes);
	sit_entry->type = SEG_NODE_INDEX;
	sit_entry++;

	sit_entry->mtime = cpu_to_le32(get_seconds());
	sit_entry->vblocks = cpu_to_le16(nr_data);
	sit_entry->type = SEG_DATA_INDEX;
}

static void hmfs_init_sb(struct hmfs_sb_info *sbi, uint64_t cp_ofs)
{
	struct hmfs_super_block *super = sbi->virt_addr;
	struct device *device = super->devices;
	struct hmfs_device_info *dev_i = DEV_INFO(sbi, 0);
	uint32_t segment_sz = calculate_segment_size(1 << sbi->max_page_size_bits);
	pgc_t nr_user_blks, nr_main_segs;
		
	/* setup super block */
	set_struct(super, magic, HMFS_SUPER_MAGIC);
	set_struct(super, major_ver, HMFS_MAJOR_VERSION);
	set_struct(super, minor_ver, HMFS_MINOR_VERSION);
	set_struct(super, nat_height, hmfs_get_nat_height(init_size));
	set_struct(super, max_page_size_bits, sbi->max_page_size_bits);
	ADDR_INIT_PHYS(&super->cp_addr, 0, cp_ofs);

	nr_main_segs = (dev_i->end_ofs - dev_i->main_ofs) >> segment_sz;
	nr_user_blks = div64_u64(nr_main_segs * (100 - DEF_OP_SEGMENTS), 100) <<
			(segment_sz_bits - HMFS_MIN_PAGE_SIZE_BITS);

	set_struct(device, phys_addr, dev_i->phys_addr);
	set_struct(device, init_size, dev_i->initsize);
	set_struct(device, nr_segments, dev_i->end_ofs >> segment_sz);
	set_struct(device, nr_main_segments, nr_main_segs);
	set_struct(device, sit_offset, DISTANCE(dev_i->virt_addr, dev_i->sit_entries));
	set_struct(device, ssa_offset, DISTANCE(dev_i->virt_addr, dev_i->ssa_entries));
	set_struct(device, main_offset, dev_i->main_ofs);
	set_struct(device, nr_user_block, nr_user_blks);

	sb_checksum = hmfs_make_checksum(super);
	set_struct(super, checksum, sb_checksum);

	/* copy another super block */
	super = next_super_block(super);
	hmfs_memcpy(super, sbi->virt_addr, sizeof(struct hmfs_super_block));
}

/* Init NAT and offset of root nat node */
static uint64_t hmfs_mk_nat(struct hmfs_sb_info *sbi, uint32_t *nofs, uint32_t inode_ofs)
{
	struct hmfs_dev_info *dev_i = DEV_I(sbi, 0);
	struct hmfs_nat_root *nat_root = JUMP(dev_i->main_area, *nofs);
	struct hmfs_nat_block *nat_data;
	char nat_height = hmfs_get_nat_height(dev_i->initsize);
	uint64_t ret_ofs = *nofs;

	hmfs_bug_on(sbi, nat_height <= 0);
	do {
		make_ssa(sbi, *nofs, MAKE_NAT_NODE_NID(nat_height, 0), SUM_TYPE_NATN);
		*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX]; 
		ADDR_INIT_PHYS(&nat_root->addr[0], 0, *nofs);
		nat_root++;
	} while (--nat_height > 0);

	nat_data = HMFS_NAT_BLOCK(nat_root);
	nat_data->entries[HMFS_ROOT_INO].ino = le32_to_cpu(HMFS_NAT_ROOT);
	ADDR_INIT_PHYS(&nat_data->entries[HMFS_ROOT_INO].block_addr, 0, inode_ofs);
	make_ssa(sbi, *nofs, 0, SUM_TYPE_NATD);
	*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];

	return ret_ofs;
}

static uint64_t hmfs_mk_cp(struct hmfs_sb_info *sbi, uint32_t *nofs, uint32_t *dofs, uint32_t nat_ofs)
{
	struct hmfs_dev_info *dev_i = DEV_INFO(sbi, 0);
	struct hmfs_checkpoint *cp = JUMP(dev_i->main_area, *nofs);
	uint32_t main_ofs = dev_i->main_ofs;
	uint32_t segment_size = calculate_segment_size(1 << sbi->max_page_size_bits);
	uint64_t ret_ofs = *nofs;
	pgc_t nr_nodes;
	int i;
	
	/* prepare checkpoint */
	set_struct(cp, checkpoint_ver, HMFS_DEF_CP_VER);

	/* Previous address of the first checkpoint is itself */
	ADDR_INIT_PHYS(&cp->prev_cp_addr, 0, *nofs);
	ADDR_INIT_PHYS(&cp->next_cp_addr, 0, *nofs);
	ADDR_INIT_PHYS(&cp->nat_addr, 0, nat_ofs);

	nr_nodes = (*nofs - main_ofs + HMFS_BLOCK_SIZE[SEG_NODE_INDEX]) >> HMFS_MIN_PAGE_SIZE_BITS;
	nr_alloc_blocks = nr_nodes + ((*dofs - main_ofs - segment_size) >> HMFS_MIN_PAGE_SIZE_BITS);
	set_struct(cp, alloc_block_count, nr_alloc_blocks);
	set_struct(cp, valid_block_count, nr_alloc_blocks);
	
	ADDR_INIT_PHYS(&cp->write_heads[SEG_NODE_INDEX], 0, *nofs);
	ADDR_INIT_PHYS(&cp->write_heads[SEG_DATA_INDEX], 0, *dofs);
	for (i = SEG_DATA_INDEX + 1; i < HMFS_MAX_CUR_SEG_COUNT; i++) {
		ADDR_INIT_PHYS(&cp->write_heads[i], 0, segment_size + main_ofs);
	}
	set_struct(cp, valid_inode_count, 1);
	/* sit, nat, root */
	set_struct(cp, valid_node_count, nr_nodes);
	set_struct(cp, next_scan_nid, HMFS_ROOT_INO + 1);
	set_struct(cp, elapsed_time, 0);

	make_ssa(sbi, *nofs, 0, SUM_TYPE_CP);
	*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];
	return ret_ofs;
}

static int hmfs_mkfs(struct hmfs_sb_info *sbi)
{
	uint64_t nofs = 0, dofs = 0, inode_ofs, nat_ofs, cp_ofs;
	
	inode_ofs = hmfs_mk_root(sbi, &nofs, &dofs);
	nat_ofs = hmfs_mk_nat(sbi, &nofs, inode_ofs);
	cp_ofs = hmfs_mk_cp(sbi, &nofs, &dofs, nat_ofs);
	hmfs_init_sit(sbi, &nofs, &dofs);
	hmfs_init_sb(sbi, cp_ofs);

	return 0;
}

int hmfs_format_device(struct hmfs_sb_info *sbi, int dev_index)
{
	uint64_t area_ofs = 0, initsize = DEV_INFO(sbi, dev_index)->initsize;
	
	memset(DEV_INFO(sbi, dev_index)->virt_addr, 0, initsize);
	
	if (!dev_index) {
		area_ofs = sizeof(struct hmfs_super_block);
		area_ofs = align_page_right(area_ofs);
		area_ofs = area_ofs * 2;
		sbi->max_page_size_bits = hmfs_max_page_size_bits(initsize);
	} else {
		if ((initsize >> 4) < (1 << sbi->max_page_size_bits))
			return -EINVAL;
	}

	hmfs_mk_metadata(sbi, area_ofs, dev_index);
	
	if (!dev_index)
		return hmfs_mkfs(sbi);
	
	return extend_segment_manager(sbi, dev_index);
}

#include <linux/fs.h>
#include <uapi/linux/magic.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/crc16.h>
#include <linux/ctype.h>

#include "hmfs_fs.h"
#include "hmfs.h"
#include "segment.h"
#include "node.h"
#include "gc.h"
#include "xattr.h"

extern struct super_operations hmfs_sops;

static int hmfs_max_page_size_bits(unsigned long long initsize)
{
	int page_size_bits = 0;
	int max_page_size = initsize >> 4;

	while (max_page_size >>= 1) {
		page_size_bits++;
	}
	
	if (page_size_bits < HMFS_MAX_PAGE_SIZE_BITS) {
		return (page_size_bits - HMFS_MIN_PAGE_SIZE_BITS ) / 
				HMFS_PAGE_SIZE_BITS_INC * HMFS_PAGE_SIZE_BITS_INC
				+ HMFS_MIN_PAGE_SIZE_BITS;
	} else
		return HMFS_MAX_PAGE_SIZE_BITS;
}

static block_t mk_metadata(struct hmfs_sb_info *sbi, block_t *nofs, block_t *dofs)
{
	uint64_t initsize = sbi->initsize, segment_sz, sit_area_size;
	uint32_t ssa_blk_sz;
	block_t end_ofs, area_ofs;
	pgc_t nr_main_segments, nr_ssa_pages;

	memset(sbi->virt_addr, 0, initsize);
	sbi->max_page_size_bits = hmfs_max_page_size_bits(initsize);
	segment_sz = 1 << calculate_segment_size_bits(sbi->max_page_size_bits);
	end_ofs = initsize & (~(segment_sz - 1));

	/* prepare SSA area */
	area_ofs = sizeof(struct hmfs_super_block);
	area_ofs = align_page_right(area_ofs);
	area_ofs <<= 1;	/* two copy of super block */
	sbi->ssa_entries = ADDR(sbi, area_ofs);
	ssa_blk_sz = (segment_sz >> HMFS_MIN_PAGE_SIZE_BITS) * sizeof(struct hmfs_summary);
	nr_main_segments = div64_u64(end_ofs - area_ofs, segment_sz + SIT_ENTRY_SIZE + ssa_blk_sz);
	nr_ssa_pages = (nr_main_segments * ssa_blk_sz + HMFS_MIN_PAGE_SIZE - 1) >> 
			HMFS_MIN_PAGE_SIZE_BITS;

	/* prepare SIT area */
	area_ofs += (nr_ssa_pages << HMFS_MIN_PAGE_SIZE_BITS);
	sbi->sit_entries = ADDR(sbi, area_ofs);
	sit_area_size = nr_main_segments * SIT_ENTRY_SIZE;

	/* prepare main area */
	area_ofs += sit_area_size;
	area_ofs = (area_ofs + segment_sz - 1) & (~(segment_sz - 1));
	sbi->main_addr_start = area_ofs;
	*nofs = area_ofs;
	*dofs = area_ofs + segment_sz;

	return area_ofs;
}

static inline void mk_ssa(struct hmfs_sb_info *sbi, block_t ofs, nid_t nid, uint8_t type)
{
	struct hmfs_summary *sum = get_summary_by_addr(sbi, ofs);
	make_summary_entry(sum, nid, HMFS_DEF_CP_VER, 0, type, 0);
	set_summary_valid_bit(sum);
}

static block_t mk_root(struct hmfs_sb_info *sbi, block_t *nofs, block_t *dofs)
{
	block_t root_ofs = *nofs;
	struct hmfs_inode *hi = ADDR(sbi, root_ofs);
	struct hmfs_dentry_block *dent_blk;

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
	hi->i_ctime = cpu_to_le64(get_seconds());
	hi->i_mtime = cpu_to_le64(get_seconds());
	hi->i_generation = 0;
	hi->i_flags = 0;
	hi->i_namelen = cpu_to_le32(1);
	memcpy(&(hi->i_name), "/", 1);
	hi->i_current_depth = cpu_to_le32(1);
	hi->i_dir_level = DEF_DIR_LEVEL;
	hi->i_blk_type = SEG_DATA_INDEX;

	hi->i_addr[0] = cpu_to_le64(*dofs);
	dent_blk = ADDR(sbi, *dofs);
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

	mk_ssa(sbi, *nofs, HMFS_ROOT_INO, SUM_TYPE_INODE);
	mk_ssa(sbi, *dofs, HMFS_ROOT_INO, SUM_TYPE_DATA);
	*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];
	*dofs += HMFS_BLOCK_SIZE[SEG_DATA_INDEX];

	return root_ofs;
}

static block_t mk_nat(struct hmfs_sb_info *sbi, block_t *nofs, block_t root_ofs)
{
	struct hmfs_nat_node *nat_root = ADDR(sbi, *nofs);
	struct hmfs_nat_block *nat_data;
	char nat_height = hmfs_get_nat_height(sbi->initsize);
	block_t nat_ofs = *nofs;

	do {
		mk_ssa(sbi, *nofs, MAKE_NAT_NODE_NID(nat_height, 0), SUM_TYPE_NATN);
		*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];
		nat_root->addr[0] = le64_to_cpu(*nofs);
		nat_root++;
	} while(--nat_height > 0);

	nat_data = HMFS_NAT_BLOCK(nat_root);
	nat_data->entries[HMFS_ROOT_INO].ino = le32_to_cpu(HMFS_ROOT_INO);
	nat_data->entries[HMFS_ROOT_INO].block_addr = le64_to_cpu(root_ofs);
	mk_ssa(sbi, *nofs, 0, SUM_TYPE_NATD);
	*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];
	return nat_ofs;
}

static void init_sit(struct hmfs_sb_info *sbi, block_t nofs, block_t dofs)
{
	struct hmfs_sit_entry *sit_entry = sbi->sit_entries;
	uint32_t segment_sz = 1 << calculate_segment_size_bits(sbi->max_page_size_bits);
	uint64_t main_ofs = sbi->main_addr_start;
	uint16_t nr_nodes = (nofs - main_ofs) >> HMFS_MIN_PAGE_SIZE_BITS,
			 nr_data = (dofs - main_ofs - segment_sz) >> HMFS_MIN_PAGE_SIZE_BITS;

	sit_entry->mtime = cpu_to_le32(get_seconds());
	sit_entry->vblocks = cpu_to_le16(nr_nodes);
	sit_entry->type = SEG_NODE_INDEX;
	sit_entry++;

	sit_entry->mtime = cpu_to_le32(get_seconds());
	sit_entry->vblocks = cpu_to_le16(nr_data);
	sit_entry->type = SEG_DATA_INDEX;
}

static void init_sb(struct hmfs_sb_info *sbi, uint64_t cp_ofs)
{
	struct hmfs_super_block *super = ADDR(sbi, 0);
	uint8_t segment_sz_bits = calculate_segment_size_bits(sbi->max_page_size_bits);
	uint64_t segment_sz = 1 << segment_sz_bits;
	pgc_t nr_user_blks, nr_main_segs;
	block_t main_ofs = sbi->main_addr_start, end_ofs = sbi->initsize & (~(segment_sz - 1)); 
	uint16_t sb_checksum;

	/* setup super block */
	set_struct(super, magic, HMFS_SUPER_MAGIC);
	set_struct(super, major_ver, HMFS_MAJOR_VERSION);
	set_struct(super, minor_ver, HMFS_MINOR_VERSION);
	set_struct(super, nat_height, hmfs_get_nat_height(sbi->initsize));

	nr_main_segs = (end_ofs - main_ofs) >> segment_sz_bits;
	nr_user_blks = div64_u64(nr_main_segs * (100 - DEF_OP_SEGMENTS), 100) 
			<< (segment_sz_bits - HMFS_MIN_PAGE_SIZE_BITS);
	set_struct(super, segment_count_main, nr_main_segs);
	set_struct(super, init_size, sbi->initsize);
	set_struct(super, segment_count, sbi->initsize >> segment_sz_bits);
	set_struct(super, user_block_count, nr_user_blks);
	set_struct(super, ssa_blkaddr, L_ADDR(sbi, sbi->ssa_entries));
	set_struct(super, sit_blkaddr, L_ADDR(sbi, sbi->sit_entries));
	set_struct(super, main_blkaddr, sbi->main_addr_start);
	set_struct(super, cp_page_addr, cp_ofs);

	sb_checksum = hmfs_make_checksum(super);
	set_struct(super, checksum, sb_checksum);

	/* copy another super block */
	super = next_super_block(super);
	hmfs_memcpy(super, ADDR(sbi, 0), sizeof(struct hmfs_super_block));
}

static block_t mk_cp(struct hmfs_sb_info *sbi, block_t *nofs, block_t *dofs, block_t nat_ofs)
{
	struct hmfs_checkpoint *cp = ADDR(sbi, *nofs);
	block_t cp_addr = *nofs, main_ofs = sbi->main_addr_start;
	pgc_t nr_nodes, nr_alloc_blocks;
	uint64_t segment_sz = 1 << calculate_segment_size_bits(sbi->max_page_size_bits);
	int i;

	mk_ssa(sbi, *nofs, 0, SUM_TYPE_CP);
	*nofs += HMFS_BLOCK_SIZE[SEG_NODE_INDEX];

	/* prepare checkpoint */
	set_struct(cp, checkpoint_ver, HMFS_DEF_CP_VER);

	/* Previous address of the first checkpoint is itself */
	set_struct(cp, prev_cp_addr, cpu_to_le64(cp_addr));
	set_struct(cp, next_cp_addr, cpu_to_le64(cp_addr));
	set_struct(cp, nat_addr, nat_ofs);

	nr_nodes = (*nofs - main_ofs) >> HMFS_MIN_PAGE_SIZE_BITS;
	nr_alloc_blocks = nr_nodes + ((*dofs - segment_sz - main_ofs) >> HMFS_MIN_PAGE_SIZE_BITS);
	set_struct(cp, alloc_block_count, nr_alloc_blocks);
	set_struct(cp, valid_block_count, nr_alloc_blocks);
	set_struct(cp, valid_inode_count, 1);
	set_struct(cp, valid_node_count, nr_nodes);
	set_struct(cp, next_scan_nid, HMFS_ROOT_INO + 1);
	set_struct(cp, elapsed_time, 0);

	set_struct(cp, cur_segno[SEG_NODE_INDEX], 0);
	set_struct(cp, cur_blkoff[SEG_NODE_INDEX], nr_nodes);
	set_struct(cp, cur_segno[SEG_DATA_INDEX], 1);
	set_struct(cp, cur_blkoff[SEG_DATA_INDEX], nr_alloc_blocks - nr_nodes);
	for (i = SEG_DATA_INDEX + 1; i < HMFS_MAX_CUR_SEG_COUNT; i++) {
		set_struct(cp, cur_segno[i], NULL_SEGNO);
		set_struct(cp, cur_blkoff[i], segment_sz >> HMFS_MIN_PAGE_SIZE_BITS);
	}

	return cp_addr;
}

static inline int hmfs_mkfs(struct hmfs_sb_info *sbi)
{
	block_t nofs = 0, dofs = 0, root_ofs, nat_ofs, cp_ofs;

	mk_metadata(sbi, &nofs, &dofs);
	root_ofs = mk_root(sbi, &nofs, &dofs);
	nat_ofs = mk_nat(sbi, &nofs, root_ofs);
	cp_ofs = mk_cp(sbi, &nofs, &dofs, nat_ofs);
	init_sit(sbi, nofs, dofs);
	init_sb(sbi, cp_ofs);
	return 0;
}

/*
 * For mount
 */
enum {
	Opt_addr = 0,
	Opt_size,
	Opt_num_inodes,
	Opt_mode,
	Opt_uid,
	Opt_gid,
	Opt_warp,
	Opt_gc,
	Opt_gc_min_time,
	Opt_gc_max_time,
	Opt_gc_time_step,
	Opt_mnt_cp,
	Opt_deep_fmt,
	Opt_user_xattr,
	Opt_acl,
	Opt_inline_data,
};

static const match_table_t tokens = {
	{Opt_addr, "physaddr=%x"},
	{Opt_size, "init=%s"},
	{Opt_num_inodes, "num_inodes=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_warp, "turn_off_warp=%u"},
	{Opt_gc, "gc=%u"},
	{Opt_gc_min_time, "gc_min_time=%u"},
	{Opt_gc_max_time, "gc_max_time=%u"},
	{Opt_gc_time_step, "gc_time_step=%u"},
	{Opt_mnt_cp, "mnt_cp=%u"},
	{Opt_deep_fmt, "deep_fmt=%u"},
	{Opt_user_xattr, "user_xattr=%u"},
	{Opt_acl, "acl=%u"},
	{Opt_inline_data, "inline=%u"},
};

/* 
 * hmfs_parse_options - format mount options from string @options to @sbi inner attributes
 * @option: options string from mount @data
 * @sbi: super block information for fs
 * @remount: is remount
 */
static int hmfs_parse_options(char *options, struct hmfs_sb_info *sbi, bool remount)
{
	char *p, *rest;
	int token;
	substring_t args[MAX_OPT_ARGS];
	phys_addr_t phys_addr = 0;
	int option;
	bool check_gc_time = false;

	if (!options)
		return 0;

	sbi->initsize = 0;
	sbi->mnt_cp_version = 0;

	while ((p = strsep(&options, ",")) != NULL) {	//parse one option each time
		if (!*p)
			continue;

		token = match_token(p, tokens, args);

		switch (token) {
		case Opt_addr:
			if (remount)
				goto bad_val;
			//remount on another area isn't allowed
			phys_addr = (phys_addr_t) simple_strtoull(args[0].from,
								NULL, 0);
			if (phys_addr == 0 || phys_addr == (phys_addr_t) ULLONG_MAX) {
				goto bad_val;
			}
			if (phys_addr & (HMFS_MIN_PAGE_SIZE - 1))
				goto bad_val;
			sbi->phys_addr = phys_addr;
			break;
		case Opt_size:
			if (remount)
				goto bad_val;
			/* change size isn't allowed */
			/* memparse() accepts a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				goto bad_val;
			sbi->initsize = memparse(args[0].from, &rest);
			break;
		case Opt_uid:
			if (remount)
				goto bad_val;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->uid = make_kuid(current_user_ns(), option);
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_warp:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				sbi->turn_off_warp = true;
			break;
		case Opt_inline_data:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, INLINE_DATA);
			break;
		case Opt_gc:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, GC);
			break;
		case Opt_gc_min_time:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gc_thread_min_sleep_time = option;
			check_gc_time = true;
			break;
		case Opt_gc_max_time:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gc_thread_max_sleep_time = option;
			check_gc_time = true;
			break;
		case Opt_gc_time_step:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gc_thread_time_step = option;
			check_gc_time = true;
			break;
#ifdef CONFIG_HMFS_XATTR
		case Opt_user_xattr:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, XATTR_USER);
			break;
#else
		case Opt_user_xattr:
			break;
#endif
#ifdef CONFIG_HMFS_ACL
		case Opt_acl:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, POSIX_ACL);
			break;
#else
		case Opt_acl:
			break;
#endif
		case Opt_mnt_cp:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->mnt_cp_version = option;
			break;
		case Opt_deep_fmt:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->deep_fmt = option;
			break;
		default:
			goto bad_val;
		}
	}
	
	/* format fs and mount cp in the same time is invalid */
	if (sbi->initsize && sbi->mnt_cp_version)
		goto bad_val;

	if (check_gc_time) {
		if (sbi->gc_thread_min_sleep_time > sbi->gc_thread_max_sleep_time ||
					sbi->gc_thread_time_step > sbi->gc_thread_max_sleep_time)
				goto bad_val;
	} else {
		sbi->gc_thread_min_sleep_time = GC_THREAD_MIN_SLEEP_TIME;
		sbi->gc_thread_time_step = GC_THREAD_MIN_SLEEP_TIME;
		sbi->gc_thread_max_sleep_time = GC_THREAD_MAX_SLEEP_TIME;
	}

	return 0;

bad_val:
	return -EINVAL;
}

static inline void *hmfs_ioremap(phys_addr_t phys_addr, ssize_t size)
{
	//TODO: try to use ioremap_nocache
	return (void __force *) ioremap_cache(phys_addr, size);
}

inline int hmfs_iounmap(void *virt_addr)
{
	iounmap((void __iomem __force *)virt_addr);
	return 0;
}

static int init_map_zero_page(struct hmfs_sb_info *sbi)
{
	sbi->map_zero_page = alloc_page((GFP_KERNEL | __GFP_ZERO));

	if (!sbi->map_zero_page)
		return -ENOMEM;
	lock_page(sbi->map_zero_page);
	sbi->map_zero_page_number = page_to_pfn(sbi->map_zero_page);
	return 0;
}

inline void destroy_map_zero_page(struct hmfs_sb_info *sbi)
{
	hmfs_bug_on(sbi, !PageLocked(sbi->map_zero_page));
	unlock_page(sbi->map_zero_page);
	__free_page(sbi->map_zero_page);
	sbi->map_zero_page = NULL;
	sbi->map_zero_page_number = 0;
}

static struct hmfs_super_block *get_valid_super_block(void *start_addr)
{
	struct hmfs_super_block *super_1, *super_2;
	u16 checksum_1, checksum_2, real_checksum_1, real_checksum_2;
	bool sb_1_valid = false, sb_2_valid = false;

	super_1 = start_addr;
	checksum_1 = hmfs_make_checksum(super_1);
	real_checksum_1 = le16_to_cpu(super_1->checksum);
	if (real_checksum_1 == checksum_1 && super_1->magic == HMFS_SUPER_MAGIC) {
		sb_1_valid = true;
	}

	super_2 = next_super_block(super_1);
	checksum_2 = hmfs_make_checksum(super_2);
	real_checksum_2 = le16_to_cpu(super_2->checksum);
	if (real_checksum_2 == checksum_2 && super_2->magic == HMFS_SUPER_MAGIC) {
		sb_2_valid = true;
	}

	if (sb_1_valid) {
		if (checksum_1 != checksum_2)
			hmfs_memcpy(super_2, super_1, sizeof(struct hmfs_super_block));
		return super_1;
	} else if (sb_2_valid) {
		hmfs_memcpy(super_1, super_2, sizeof(struct hmfs_super_block));
		return super_1;
	}
	
	return NULL;
}

static struct hmfs_super_block *mount_super_block(struct hmfs_sb_info *sbi)
{
	uint64_t input_size = sbi->initsize;
	struct hmfs_super_block *super;

	if (!input_size)
		sbi->initsize = HMFS_MIN_PAGE_SIZE * 2;

	sbi->virt_addr = hmfs_ioremap(sbi->phys_addr, sbi->initsize);
	if (!sbi->virt_addr)
		return ERR_PTR(-EINVAL);

	super = get_valid_super_block(sbi->virt_addr);
	if (!input_size && super != NULL) {
		sbi->initsize = le64_to_cpu(super->init_size);
		hmfs_iounmap(sbi->virt_addr);
		sbi->virt_addr = hmfs_ioremap(sbi->phys_addr, sbi->initsize);
		if (!sbi->virt_addr)
			return ERR_PTR(-EINVAL);
	} else if (input_size) {
		hmfs_mkfs(sbi);
	} else if (sbi->mnt_cp_version) {
		if (!hmfs_readonly(sbi->sb))
			return ERR_PTR(-EACCES);
	} else
		return ERR_PTR(-EINVAL);

	super = get_valid_super_block(sbi->virt_addr);
	return !super ? ERR_PTR(-EINVAL) : super;
}

static void read_super_block(struct hmfs_sb_info *sbi, struct hmfs_super_block *super)
{
	uint8_t segment_sz_bits;
	int i;

	sbi->segment_count = le64_to_cpu(super->segment_count);
	sbi->segment_count_main = le64_to_cpu(super->segment_count_main);
	sbi->ssa_entries = ADDR(sbi, le64_to_cpu(super->ssa_blkaddr));
	sbi->sit_entries = ADDR(sbi, le64_to_cpu(super->sit_blkaddr));
	sbi->nat_height = super->nat_height;
	sbi->nr_max_fg_segs = NR_MAX_FG_SEGS;
	sbi->max_page_size_bits = hmfs_max_page_size_bits(sbi->initsize);
	sbi->max_page_size = 1 << sbi->max_page_size_bits;
	segment_sz_bits = calculate_segment_size_bits(sbi->max_page_size_bits);
	sbi->nr_page_types = (sbi->max_page_size_bits - HMFS_MIN_PAGE_SIZE_BITS) /
			HMFS_PAGE_SIZE_BITS_INC + 2;
	sbi->page_count_main = sbi->segment_count_main << (segment_sz_bits - HMFS_MIN_PAGE_SIZE_BITS);
	sbi->gc_type_info = 0;
	sbi->gc_old_token = DEFAULT_GC_TOKEN;

	sbi->main_addr_start = le64_to_cpu(super->main_blkaddr);
	sbi->main_addr_end = sbi->main_addr_start + (sbi->segment_count_main << segment_sz_bits);

	for (i = 0; i < NR_GLOBAL_LOCKS; ++i)
		mutex_init(&sbi->fs_lock[i]);
	mutex_init(&sbi->gc_mutex);
	sbi->next_lock_num = 0;

	sbi->s_dirty = 0;
	INIT_LIST_HEAD(&sbi->dirty_inodes_list);
	INIT_LIST_HEAD(&sbi->mmap_block_list);
	mutex_init(&sbi->mmap_block_lock);
	spin_lock_init(&sbi->dirty_inodes_lock);
	sbi->sb->s_magic = le32_to_cpu(super->magic);
	sbi->sb->s_op = &hmfs_sops;
	sbi->sb->s_xattr = hmfs_xattr_handlers;
	sbi->sb->s_maxbytes = hmfs_max_file_size();
	sbi->sb->s_flags |= MS_NOSEC;
	sbi->sb->s_flags = (sbi->sb->s_flags & ~MS_POSIXACL) | 
			(test_opt(sbi, POSIX_ACL) ? MS_POSIXACL : 0);
}

static int build_manager(struct hmfs_sb_info *sbi)
{
	int retval = 0;
	struct inode *root;

	/* init nat */
	retval = init_checkpoint_manager(sbi);
	if (retval)
		goto free_cp_mgr;

	retval = build_node_manager(sbi);
	if (retval)
		goto free_node_mgr;

	retval = build_segment_manager(sbi);
	if (retval)
		goto free_segment_mgr;
	hmfs_bug_on(sbi, sbi->main_addr_end & (SM_I(sbi)->segment_size - 1));

	if (!sbi->mnt_cp_version)
		check_checkpoint_state(sbi);

	retval = init_gc_logs(sbi);
	if (retval)
		goto free_segment_mgr;

	if (test_opt(sbi, GC) && !hmfs_readonly(sbi->sb)) {
		/* start gc kthread */
		hmfs_dbg("[HMFS] : GC configed!\n");
		retval = start_gc_thread(sbi);
		if (retval)
			goto free_segment_mgr;
	}
	
	retval = -EINVAL;
	if (recover_orphan_inodes(sbi))
		goto free_segment_mgr;

	root = hmfs_iget(sbi->sb, HMFS_ROOT_INO);
	if (IS_ERR(root)) {
		retval = PTR_ERR(root);
		goto free_segment_mgr;
	}

	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		retval = -EINVAL;
		goto free_root_inode;
	}

	sbi->sb->s_root = d_make_root(root);	
	if (!sbi->sb->s_root) {
		retval = -ENOMEM;
		goto free_root_inode;
	}

	retval = init_map_zero_page(sbi);
	if (retval)
		goto free_root_inode;

	/* create debugfs */
	retval = hmfs_build_stats(sbi);
	if (retval)
		goto free_zero_page;

	return 0;
free_zero_page:
	destroy_map_zero_page(sbi);
free_root_inode:
	iput(root);
	sbi->sb->s_root = NULL;
free_segment_mgr:
	destroy_segment_manager(sbi);
free_node_mgr:
	destroy_node_manager(sbi);
free_cp_mgr:
	destroy_checkpoint_manager(sbi);
	return retval;
}

static int obtain_init_mm_addr(struct hmfs_sb_info *sbi)
{
    const char name[20] = "init_mm";
    unsigned long long addr;
    int ret=0;
    loff_t pos=0;
    struct file* filp;
    char* buffer;
    int j;
    int p1=0;
    int p2=0;
    set_fs(get_ds());
    buffer = (char*)kmalloc(sizeof(char)*100,GFP_KERNEL);
    filp = filp_open("/proc/kallsyms", O_RDONLY, 0);
    while (ret>=0) {
        for (j=0;j<100;++j) {
            ret = vfs_read(filp, &buffer[j], 1, &pos);
            if (buffer[j]==' ') {p1=j;}
            if (buffer[j]=='\n') {p2=j;buffer[j]='\0';break;}
        }
        if (!strcmp(buffer+p1+1,name)) {
            buffer[p1-2]='\0';
            break;
        }
    }
    ret = kstrtou64(&buffer[0], 16, &addr);
	sbi->init_mm_addr = addr;
    if (ret!=0) {
		hmfs_dbg("[HMFS] : Unsuccessful kstrtou64%d,%llx\n",ret,addr);
		return ret;
	}
    hmfs_dbg("[HMFS] : Successful kstrtou64 for init_mm:%llx\n",addr);
	// hmfs_dbg("zero_page:%llx\n",sbi->map_zero_page);
	return 0;
}

int hmfs_fill_super(struct super_block *sb, void *data, int slient)
{
	int retval = 0;
	struct hmfs_sb_info *sbi;
	struct hmfs_super_block *super;

	/* sbi initialization */
	sbi = kzalloc(sizeof(struct hmfs_sb_info), GFP_KERNEL);
	if (sbi == NULL) {
		return -ENOMEM;
	}

	/* get phys_addr from @data&virt_addr from ioremap */
	sb->s_fs_info = sbi;
	sbi->sb = sb;
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	sbi->s_mount_opt = 0;
	sbi->turn_off_warp = false;
	if (hmfs_parse_options((char *)data, sbi, 0)) {
		retval = -EINVAL;
		goto out;
	}

	super = mount_super_block(sbi);
	if (IS_ERR(super)) {
		retval = PTR_ERR(super);
		goto out;
	}

	read_super_block(sbi, super);
	/* init checkpoint */

	retval = obtain_init_mm_addr(sbi);
	if (retval)
		goto out;
	
	retval = build_manager(sbi);
	if (retval)
		goto out;

	if(!sbi->turn_off_warp) {
		retval = start_warp_thread(sbi);
		if (retval)
			goto out;
	}


	return 0;
out:
	if (sbi->virt_addr)
		hmfs_iounmap(sbi->virt_addr);
	kfree(sbi);
	return retval;
}


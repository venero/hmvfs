#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include "hmfs_fs.h"
#include "hmfs.h"
/*
 * For INODE and NODE manager
 */
/* for directory operations */
/*struct hmfs_dentry_ptr {
	const void *bitmap;
	struct hmfs_dir_entry *dentry;
	__u8 (*filename)[HMFS_SLOT_LEN];
	int max;
};

static inline void make_dentry_ptr(struct hmfs_dentry_ptr *d,
					void *src, int type)
{
	if (type == 1) {
		struct hmfs_dentry_block *t = (struct hmfs_dentry_block *)src;
		d->max = NR_DENTRY_IN_BLOCK;
		d->bitmap = &t->dentry_bitmap;
		d->dentry = t->dentry;
		d->filename = t->filename;
	} else {
		struct hmfs_inline_dentry *t = (struct hmfs_inline_dentry *)src;
		d->max = NR_INLINE_DENTRY;
		d->bitmap = &t->dentry_bitmap;
		d->dentry = t->dentry;
		d->filename = t->filename;
	}
}
*/
static inline void make_dentry_ptr(struct hmfs_dentry_ptr *d,
				   void *src, int type)
{
	if (type == 1) {
		struct hmfs_dentry_block *t = (struct hmfs_dentry_block *)src;
		d->max = NR_DENTRY_IN_BLOCK;
		d->bitmap = &t->dentry_bitmap;
		d->dentry = t->dentry;
		d->filename = t->filename;
	} else {
	}
}

//calculate how many blocks does a file have.
static unsigned long dir_blocks(struct inode *inode)
{
	return ((unsigned long long)(i_size_read(inode) + HMFS_PAGE_SIZE - 1))
	    >> HMFS_PAGE_SIZE_BITS;
}

//calculate how many buckets in a level.
static unsigned int dir_buckets(unsigned int level, int dir_level)
{
	if (level + dir_level < MAX_DIR_HASH_DEPTH / 2)
		return 1 << (level + dir_level);
	else
		return MAX_DIR_BUCKETS;
}

//calculate the number of blocks in a bucket.
static unsigned int bucket_blocks(unsigned int level)
{
	if (level < MAX_DIR_HASH_DEPTH / 2)
		return 2;
	else
		return 4;
}

unsigned char hmfs_filetype_table[HMFS_FT_MAX] = {
	[HMFS_FT_UNKNOWN] = DT_UNKNOWN,
	[HMFS_FT_REG_FILE] = DT_REG,
	[HMFS_FT_DIR] = DT_DIR,
	[HMFS_FT_CHRDEV] = DT_CHR,
	[HMFS_FT_BLKDEV] = DT_BLK,
	[HMFS_FT_FIFO] = DT_FIFO,
	[HMFS_FT_SOCK] = DT_SOCK,
	[HMFS_FT_SYMLINK] = DT_LNK,
};

#define S_SHIFT 12
static unsigned char hmfs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT] = HMFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT] = HMFS_FT_DIR,
	[S_IFCHR >> S_SHIFT] = HMFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT] = HMFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT] = HMFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT] = HMFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT] = HMFS_FT_SYMLINK,
};

void set_de_type(struct hmfs_dir_entry *de, umode_t mode)
{
	de->file_type = hmfs_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

static unsigned long dir_block_index(unsigned int level,
				     int dir_level, unsigned int idx)
{
	unsigned long i;
	unsigned long bidx = 0;

	for (i = 0; i < level; i++)
		bidx += dir_buckets(i, dir_level) * bucket_blocks(i);
	bidx += idx * bucket_blocks(level);
	return bidx;
}

static bool early_match_name(size_t namelen, hmfs_hash_t namehash,
			     struct hmfs_dir_entry *de)
{
	if (le16_to_cpu(de->name_len) != namelen)
		return false;

	if (de->hash_code != namehash)
		return false;

	return true;
}

struct hmfs_dir_entry *find_target_dentry(struct qstr *name, int *max_slots,
					  struct hmfs_dentry_ptr *d)
{
	struct hmfs_dir_entry *de;
	unsigned long bit_pos = 0;
	//TODO after add hash.c here will be valid
	hmfs_hash_t namehash = 0;
	//hmfs_hash_t namehash = hmfs_dentry_hash(name);
	int max_len = 0;

	if (max_slots)
		*max_slots = 0;
	while (bit_pos < d->max) {
		if (!test_bit_le(bit_pos, d->bitmap)) {
			bit_pos++;
			max_len++;
			continue;
		}

		de = &d->dentry[bit_pos];
		if (early_match_name(name->len, namehash, de) &&
		    !memcmp(d->filename[bit_pos], name->name, name->len))
			goto found;

		if (max_slots && max_len > *max_slots)
			*max_slots = max_len;
		max_len = 0;

		/* remain bug on condition */
		if (unlikely(!de->name_len))
			d->max = -1;

		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
	}

	de = NULL;
found:
	if (max_slots && max_len > *max_slots)
		*max_slots = max_len;
	return de;
}

static struct hmfs_dir_entry *find_in_block(struct hmfs_dentry_block
					    *dentry_blk, struct qstr *name,
					    int *max_slots)
{
	struct hmfs_dir_entry *de;
	struct hmfs_dentry_ptr d;

	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	de = find_target_dentry(name, max_slots, &d);

	/*  
	 * For the most part, it should be a bug when name_len is zero.
	 * We stop here for figuring out where the bugs has occurred.
	 */
	//hmfs_bug_on(HMFS_P_SB(dentry_page), d.max < 0);
	return de;
}

static struct hmfs_dir_entry *find_in_level(struct inode *dir,
					    unsigned int level,
					    struct qstr *name,
					    hmfs_hash_t namehash)
{
	int s = GET_DENTRY_SLOTS(name->len);
	unsigned int nbucket, nblock;
	unsigned int bidx, end_block;
	struct hmfs_dir_entry *de = NULL;
	bool room = false;
	void *blocks[4];
	int max_slots;
	int err;
	int size, start_blk;
	struct hmfs_dentry_block *dentry_blk = NULL;

	//shmfs_bug_on(HMFS_I_SB(dir), level > MAX_DIR_HASH_DEPTH);

	nbucket = dir_buckets(level, HMFS_I(dir)->i_dir_level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, HMFS_I(dir)->i_dir_level,
			       le32_to_cpu(namehash) % nbucket);
	end_block = bidx + nblock;

	err = get_data_blocks(dir, bidx, end_block, blocks, &size, RA_END);
	if (err || (size != nblock))
		return NULL;

	for (start_blk = 0; bidx < end_block; bidx++) {
		/* no need to allocate new dentry pages to all the indices */

		dentry_blk = blocks[start_blk++];

		de = find_in_block(dentry_blk, name, &max_slots);
		if (de)
			break;

		if (max_slots >= s)
			room = true;
	}

	if (!de && room && HMFS_I(dir)->chash != namehash) {
		HMFS_I(dir)->chash = namehash;
		HMFS_I(dir)->clevel = level;
	}

	return de;
}

/*
 * Find an entry in the specified directory with the wanted name.
 * It returns the page where the entry was found (as a parameter - res_page),
 * and the entry itself. Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
struct hmfs_dir_entry *hmfs_find_entry(struct inode *dir, struct qstr *child)
{
	unsigned long npages = dir_blocks(dir);
	struct hmfs_dir_entry *de = NULL;
	hmfs_hash_t name_hash = 0;
	unsigned int max_depth;
	unsigned int level;

	// add inline.c here will become valid

	if (npages == 0)
		return NULL;
	//TODO after add hash.c here will be valid
	name_hash = hmfs_dentry_hash(child);
	max_depth = HMFS_I(dir)->i_current_depth;

	for (level = 0; level < max_depth; level++) {
		de = find_in_level(dir, level, child, name_hash);
		if (de)
			break;
	}
	if (!de && HMFS_I(dir)->chash != name_hash) {
		HMFS_I(dir)->chash = name_hash;
		HMFS_I(dir)->clevel = level - 1;
	}
	return de;
}

struct hmfs_dir_entry *hmfs_parent_dir(struct inode *dir, struct page **p)
{
	struct page *page = NULL;
	struct hmfs_dir_entry *de = NULL;
	struct hmfs_dentry_block *dentry_blk = NULL;

	// add inline.c here will become valid
	//if (hmfs_has_inline_dentry(dir))
	//      return hmfs_parent_inline_dir(dir, p);

	// add data.c here will become valid
	//page = get_lock_data_page(dir, 0);
	if (IS_ERR(page))
		return NULL;

	dentry_blk = kmap(page);
	de = &dentry_blk->dentry[1];
	*p = page;
	unlock_page(page);
	return de;
}

ino_t hmfs_inode_by_name(struct inode * dir, struct qstr * qstr)
{
	ino_t res = 0;
	struct hmfs_dir_entry *de;

	de = hmfs_find_entry(dir, qstr);
	if (de) {
		res = le32_to_cpu(de->ino);
	}

	return res;
}

void hmfs_set_link(struct inode *dir, struct hmfs_dir_entry *de,
		   struct page *page, struct inode *inode)
{
	lock_page(page);

	//TODO add segment.c here will be valid
	//hmfs_wait_on_page_writeback(page, type);
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode->i_mode);
	hmfs_dentry_kunmap(dir, page);
	set_page_dirty(page);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty(dir);

	hmfs_put_page(page, 1);
}

static void init_dent_inode(const struct qstr *name, struct hmfs_inode *hi)
{
	/* copy name info. to this inode page */
	hi->i_namelen = cpu_to_le32(name->len);
	memcpy(hi->i_name, name->name, name->len);
}

int update_dent_inode(struct inode *inode, const struct qstr *name)
{
	struct super_block *sb = inode->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct hmfs_node *hn;

	hn = get_node(sbi, inode->i_ino);

	if (IS_ERR(hn))
		return PTR_ERR(hn);

	init_dent_inode(name, &hn->i);

	return 0;
}

void do_make_empty_dir(struct inode *inode, struct inode *parent,
		       struct hmfs_dentry_ptr *d)
{
	struct hmfs_dir_entry *de;
	memset_nt(d->bitmap, 0, SIZE_OF_DENTRY_BITMAP);
	de = &d->dentry[0];
	de->name_len = cpu_to_le16(1);
	de->hash_code = 0;
	de->ino = cpu_to_le32(inode->i_ino);
	memcpy(d->filename[0], ".", 1);
	set_de_type(de, inode->i_mode);

	de = &d->dentry[1];
	de->hash_code = 0;
	de->name_len = cpu_to_le16(2);
	de->ino = cpu_to_le32(parent->i_ino);
	memcpy(d->filename[1], "..", 2);
	set_de_type(de, parent->i_mode);

	test_and_set_bit_le(0, (void *)d->bitmap);
	test_and_set_bit_le(1, (void *)d->bitmap);
}

static int make_empty_dir(struct inode *inode,
			  struct inode *parent, struct hmfs_node *hn)
{
	struct hmfs_dentry_block *dentry_blk = NULL;
	struct hmfs_dentry_ptr d;
	printk(KERN_INFO "make empty dir of:%lu,its parent:%lu\n", inode->i_ino,
	       parent->i_ino);
	dentry_blk = get_new_data_block(inode, 0);
	if (IS_ERR(dentry_blk))
		return PTR_ERR(dentry_blk);

	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	do_make_empty_dir(inode, parent, &d);

	return 0;
}

struct hmfs_node *init_inode_metadata(struct inode *inode, struct inode *dir,
				      const struct qstr *name,
				      struct page *dpage)
{
	struct super_block *sb = inode->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	int err;
	struct hmfs_node *hn;
	printk(KERN_INFO "init inode metadata\n");
	printk(KERN_INFO "new inode:%d\n",
	       is_inode_flag_set(HMFS_I(inode), FI_NEW_INODE));
	if (is_inode_flag_set(HMFS_I(inode), FI_NEW_INODE)) {
		hn = get_new_node(sbi, inode->i_ino, inode->i_ino);
		printk(KERN_INFO "init inode metadata\n");
		if (IS_ERR(hn))
			return hn;

		if (S_ISDIR(inode->i_mode)) {
			err = make_empty_dir(inode, dir, hn);
			if (err)
				goto error;
		}
	} else {
		//TODO after add node.c here will be valid
		//page = get_node_page(HMFS_I_SB(dir), inode->i_ino);
		//TODO after add node.h here will be valid
		//set_cold_node(inode, page);
	}

	if (name)
		init_dent_inode(name, &hn->i);

	/*
	 * This file should be checkpointed during fsync.
	 * We lost i_pino from now on.
	 */
	if (is_inode_flag_set(HMFS_I(inode), FI_INC_LINK)) {
		//TODO after add node.h here will be valid
		//file_lost_pino(inode);
		/*
		 * If link the tmpfile to alias through linkat path,
		 * we should remove this inode from orphan list.
		 */
		//if (inode->i_nlink == 0)
		//TODO after add checkpoint.c here will be valid
		//remove_orphan_inode(HMFS_I_SB(dir), inode->i_ino);
		//TODO after add inode.c here will be valid
		//inc_nlink(inode);
	}
	return hn;

error:
	/* once the failed inode becomes a bad inode, i_mode is S_IFREG */
	//TODO after add truncate.c here will be valid
	//truncate_inode_pages(&inode->i_data, 0);
	//truncate_blocks(inode, 0, false);
	//remove_dirty_dir_inode(inode);
	//remove_inode_page(inode);
	return ERR_PTR(err);
}

void update_parent_metadata(struct inode *dir, struct inode *inode,
			    unsigned int current_depth)
{
	if (inode && is_inode_flag_set(HMFS_I(inode), FI_NEW_INODE)) {
		if (S_ISDIR(inode->i_mode)) {

			//TODO after add inode.c here will be valid
			//inc_nlink(dir);
			set_inode_flag(HMFS_I(dir), FI_UPDATE_DIR);
		}
		clear_inode_flag(HMFS_I(inode), FI_NEW_INODE);
	}
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	struct super_block *sb = dir->i_sb;
	BUG_ON(sb == NULL);
	BUG_ON(sb->s_op == NULL);
	BUG_ON(sb->s_op->dirty_inode == NULL);
	mark_inode_dirty(dir);

	if (HMFS_I(dir)->i_current_depth != current_depth) {
		HMFS_I(dir)->i_current_depth = current_depth;
		set_inode_flag(HMFS_I(dir), FI_UPDATE_DIR);
	}

	if (inode && is_inode_flag_set(HMFS_I(inode), FI_INC_LINK))
		clear_inode_flag(HMFS_I(inode), FI_INC_LINK);
}

int room_for_filename(const void *bitmap, int slots, int max_slots)
{
	int bit_start = 0;
	int zero_start, zero_end;
next:
	zero_start = find_next_zero_bit_le(bitmap, max_slots, bit_start);
	if (zero_start >= max_slots)
		return max_slots;

	zero_end = find_next_bit_le(bitmap, max_slots, zero_start);
	if (zero_end - zero_start >= slots)
		return zero_start;

	bit_start = zero_end + 1;

	if (zero_end + 1 >= max_slots)
		return max_slots;
	goto next;
}

void hmfs_update_dentry(nid_t ino, umode_t mode, struct hmfs_dentry_ptr *d,
			const struct qstr *name, hmfs_hash_t name_hash,
			unsigned int bit_pos)
{
	struct hmfs_dir_entry *de;
	int slots = GET_DENTRY_SLOTS(name->len);
	int i;

	de = &d->dentry[bit_pos];
	de->hash_code = name_hash;
	de->name_len = cpu_to_le16(name->len);
	memcpy(d->filename[bit_pos], name->name, name->len);
	de->ino = cpu_to_le32(ino);
	set_de_type(de, mode);
	for (i = 0; i < slots; i++)
		test_and_set_bit_le(bit_pos + i, (void *)d->bitmap);
}

/*
 * Caller should grab and release a rwsem by calling hmfs_lock_op() and
 * hmfs_unlock_op().
 */
int __hmfs_add_link(struct inode *dir, const struct qstr *name,
		    struct inode *inode)
{
	unsigned int bit_pos;
	unsigned int level;
	unsigned int current_depth;
	unsigned long bidx, block, end_blk;
	hmfs_hash_t dentry_hash = 0;
	unsigned int nbucket, nblock;
	size_t namelen = name->len;
	struct hmfs_dentry_block *dentry_blk = NULL;
	struct hmfs_dentry_ptr d;
	int slots = GET_DENTRY_SLOTS(namelen);
	struct hmfs_node *hn;
	int size = 0;
	int err = 0;
	void *blocks[4];
	printk(KERN_INFO "__hmfs_add_link\n");
	dentry_hash = hmfs_dentry_hash(name);
	level = 0;
	current_depth = HMFS_I(dir)->i_current_depth;
	if (HMFS_I(dir)->chash == dentry_hash) {
		level = HMFS_I(dir)->clevel;
		HMFS_I(dir)->chash = 0;
	}
	end_blk = dir->i_size >> HMFS_PAGE_SIZE_BITS;

start:
	if (unlikely(current_depth == MAX_DIR_HASH_DEPTH))
		return -ENOSPC;

	/* Increase the depth, if required */
	if (level == current_depth)
		++current_depth;

	nbucket = dir_buckets(level, HMFS_I(dir)->i_dir_level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, HMFS_I(dir)->i_dir_level,
			       (le32_to_cpu(dentry_hash) % nbucket));

	for (block = bidx; block <= (bidx + nblock - 1); block++) {
		//TODO after add data.c here will be valid
		//FIXME: use bat process to reduce read time
		if (block > end_blk) {
			dentry_blk = get_new_data_block(dir, block);
			memset_nt(dentry_blk, 0, HMFS_PAGE_SIZE);
			goto add_dentry;
		} else {
			err =
			    get_data_blocks(dir, block, block + 1, blocks,
					    &size, RA_DB_END);
			dentry_blk = blocks[0];
			printk(KERN_INFO "read dir block:%d,result:%d\n", block,
			       err);
			if (err || size <= 0)
				return -EINVAL;
			bit_pos = room_for_filename(&dentry_blk->dentry_bitmap,
						    slots, NR_DENTRY_IN_BLOCK);
			printk("bit pos:%d\n", bit_pos);
			if (bit_pos < NR_DENTRY_IN_BLOCK) {
				dentry_blk = get_new_data_block(dir, block);
				goto add_dentry;
			}

		}

	}

	/* Move to next level to find the empty slot for new dentry */
	++level;
	goto start;
add_dentry:
	//TODO after add segment.c here will be valid
	printk(KERN_INFO "add entry\n");
	if (inode) {
		down_write(&HMFS_I(inode)->i_sem);
		hn = init_inode_metadata(inode, dir, name, NULL);
		if (IS_ERR(hn)) {
			err = PTR_ERR(hn);
			goto fail;
		}
	}
	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	hmfs_update_dentry(inode->i_ino, inode->i_mode, &d, name, dentry_hash,
			   bit_pos);

	if (inode) {
		/* we don't need to mark_inode_dirty now */
		HMFS_I(inode)->i_pino = dir->i_ino;
		//TODO after add inode.c here will be valid
		//update_inode(inode, page);
	}

	update_parent_metadata(dir, inode, current_depth);
fail:
	if (inode)
		up_write(&HMFS_I(inode)->i_sem);

	if (is_inode_flag_set(HMFS_I(dir), FI_UPDATE_DIR)) {
		//TODO after add inode.c here will be valid
		//update_inode_page(dir);
		clear_inode_flag(HMFS_I(dir), FI_UPDATE_DIR);
	}
	return err;
}

int hmfs_do_tmpfile(struct inode *inode, struct inode *dir)
{
	struct hmfs_node *hn = NULL;
	int err = 0;

	down_write(&HMFS_I(inode)->i_sem);
	hn = init_inode_metadata(inode, dir, NULL, NULL);
	if (IS_ERR(hn)) {
		err = PTR_ERR(hn);
		goto fail;
	}
	/* we don't need to mark_inode_dirty now */
	//TODO after add inode.c here will be valid
	//update_inode(inode, page);

	clear_inode_flag(HMFS_I(inode), FI_NEW_INODE);
fail:
	up_write(&HMFS_I(inode)->i_sem);
	return err;
}

void hmfs_drop_nlink(struct inode *dir, struct inode *inode, struct page *page)
{
	down_write(&HMFS_I(inode)->i_sem);

	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
		//if (page)
		//TODO after add inode.c here will be valid
		//update_inode(dir, page);
		//else
		//TODO after add inode.c here will be valid
		//update_inode_page(dir);
	}
	inode->i_ctime = CURRENT_TIME;

	drop_nlink(inode);
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(inode);
		i_size_write(inode, 0);
	}
	up_write(&HMFS_I(inode)->i_sem);
	//TODO after add inode.c here will be valid
	//update_inode_page(inode);

	//TODO after add checkpoint.c here will be valid
	//if (inode->i_nlink == 0)
	//      add_orphan_inode(sbi, inode->i_ino);
	//else
	//      release_orphan_inode(sbi);
}

/*
 * It only removes the dentry from the dentry page, corresponding name
 * entry in name page does not need to be touched during deletion.
 */
void hmfs_delete_entry(struct hmfs_dir_entry *dentry, struct page *page,
		       struct inode *dir, struct inode *inode)
{
	struct hmfs_dentry_block *dentry_blk;
	unsigned int bit_pos;
	int slots = GET_DENTRY_SLOTS(le16_to_cpu(dentry->name_len));
	int i;

	//TODO after add checkpoint.c here will be valid
	//if (hmfs_has_inline_dentry(dir))
	//      return hmfs_delete_inline_entry(dentry, page, dir, inode);

	lock_page(page);
	//TODO after add segment.c here will be valid
	//hmfs_wait_on_page_writeback(page, DATA);

	dentry_blk = page_address(page);
	bit_pos = dentry - dentry_blk->dentry;
	for (i = 0; i < slots; i++)
		clear_bit_le(bit_pos + i, &dentry_blk->dentry_bitmap);

	/* Let's check and deallocate this dentry page */
	bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
				   NR_DENTRY_IN_BLOCK, 0);
	kunmap(page);		/* kunmap - pair of hmfs_find_entry */
	set_page_dirty(page);

	dir->i_ctime = dir->i_mtime = CURRENT_TIME;

	if (inode)
		hmfs_drop_nlink(dir, inode, NULL);

	if (bit_pos == NR_DENTRY_IN_BLOCK) {
		// after add dir.c here will be valid
		//truncate_hole(dir, page->index, page->index + 1);
		clear_page_dirty_for_io(page);
		ClearPagePrivate(page);
		ClearPageUptodate(page);
		//TODO need to add in hmfs.h
		//inode_dec_dirty_pages(dir);
	}
	hmfs_put_page(page, 1);
}

bool hmfs_empty_dir(struct inode *dir)
{
	unsigned long bidx;
	unsigned int bit_pos;
	struct page *dentry_page = NULL;
	struct hmfs_dentry_block *dentry_blk;
	unsigned long nblock = dir_blocks(dir);

	//TODO after add inline.c here will be valid
	//if (hmfs_has_inline_dentry(dir))
	//      return hmfs_empty_inline_dir(dir);

	for (bidx = 0; bidx < nblock; bidx++) {
		//TODO after add data.c here will be valid
		//dentry_page = get_lock_data_page(dir, bidx);
		if (IS_ERR(dentry_page)) {
			if (PTR_ERR(dentry_page) == -ENOENT)
				continue;
			else
				return false;
		}

		dentry_blk = kmap_atomic(dentry_page);
		if (bidx == 0)
			bit_pos = 2;
		else
			bit_pos = 0;
		bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
					   NR_DENTRY_IN_BLOCK, bit_pos);
		kunmap_atomic(dentry_blk);

		hmfs_put_page(dentry_page, 1);

		if (bit_pos < NR_DENTRY_IN_BLOCK)
			return false;
	}
	return true;
}

bool hmfs_fill_dentries(struct dir_context * ctx, struct hmfs_dentry_ptr * d,
			unsigned int start_pos)
{
	unsigned char d_type = DT_UNKNOWN;
	unsigned int bit_pos;
	struct hmfs_dir_entry *de = NULL;

	bit_pos = ((unsigned long)ctx->pos % d->max);

	while (bit_pos < d->max) {
		printk("cur pos:%d\n", bit_pos);
		printk("bitmap:%d\n", *(int *)d->bitmap);
		bit_pos = find_next_bit_le(d->bitmap, d->max, bit_pos);
		printk("next pos:%d\n", bit_pos);
		if (bit_pos >= d->max)
			break;

		printk("get fill\n");
		de = &d->dentry[bit_pos];
		printk("name len:%d\n", de->name_len);
		printk("name:%s\n", d->filename[bit_pos]);
		if (de->file_type < HMFS_FT_MAX)
			d_type = hmfs_filetype_table[de->file_type];
		else
			d_type = DT_UNKNOWN;
		if (!dir_emit(ctx, d->filename[bit_pos],
			      le16_to_cpu(de->name_len),
			      le32_to_cpu(de->ino), d_type))
			return true;

		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
		printk(KERN_INFO "bit ops:%d\n", bit_pos);
		ctx->pos = start_pos + bit_pos;
	}
	return false;
}

static int hmfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	unsigned long npages = dir_blocks(inode);
	struct hmfs_dentry_block *dentry_blk = NULL;
	unsigned int n = ((unsigned long)ctx->pos / NR_DENTRY_IN_BLOCK);
	struct hmfs_dentry_ptr d;
	int size = -1;
	int i = 0;
	int err = 0;
	void **buf;

	buf = vzalloc(HMFS_PAGE_SIZE);
	printk(KERN_INFO "Read dir:%lu\n", inode->i_ino);

	if (!buf)
		return -ENOMEM;

	//TODO after add inline.c here will be valid
	//if (hmfs_has_inline_dentry(inode))
	//      return hmfs_read_inline_dir(file, ctx);
	for (; n < npages; n++) {
		//TODO after add data.c here will be valid
		//dentry_page = get_lock_data_page(inode, n);
		printk(KERN_INFO "n:%d\n", n);
		if (i >= size) {
			err =
			    get_data_blocks(inode, n, npages, buf, &size,
					    RA_DB_END);
			if (err)
				goto stop;
			i = 0;
		}

		dentry_blk = buf[i++];
		make_dentry_ptr(&d, (void *)dentry_blk, 1);

		if (hmfs_fill_dentries(ctx, &d, n * NR_DENTRY_IN_BLOCK))
			goto stop;

		ctx->pos = (n + 1) * NR_DENTRY_IN_BLOCK;
	}
stop:
	vfree(buf);
	return err;
}

const struct file_operations hmfs_dir_operations = {
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	.iterate = hmfs_readdir,
	//.fsync                = hmfs_sync_file,
	//.unlocked_ioctl       = hmfs_ioctl,
};

/*
 * fs/hmfs/dir.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2015 SJTU RadLab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include "hmfs_fs.h"
#include "hmfs.h"

/* calculate how many blocks does a file have. */
static unsigned long dir_blocks(struct inode *inode)
{
	return ((unsigned long long)(i_size_read(inode) + HMFS_PAGE_SIZE - 1)) 
					>> HMFS_PAGE_SIZE_BITS;
}

/* calculate how many buckets in a level. */
static unsigned int dir_buckets(unsigned int level)
{
	if (level < MAX_DIR_HASH_DEPTH / 2)
		return 1 << level;
	else
		return MAX_DIR_BUCKETS;
}

/* calculate the number of blocks in a bucket. */
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

static void set_de_type(struct hmfs_dir_entry *de, umode_t mode)
{
	de->file_type = hmfs_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

/*
 * Return a hmfs_dentry_block for writing. We should not call
 * alloc_new_data_block directly in case of dir might be an inline inode
 */
struct hmfs_dentry_block *get_dentry_block_for_write(struct inode *dir,
				int old_bidx)
{
	struct hmfs_inode *inode_block;
	struct hmfs_sb_info *sbi = HMFS_I_SB(dir);

	if (is_inline_inode(dir)) {
		hmfs_bug_on(sbi, old_bidx > 0);
		inode_block = alloc_new_node(sbi, dir->i_ino, dir, SUM_TYPE_INODE, false);
		if (IS_ERR(inode_block))
			return DENTRY_BLOCK(inode_block);
		return DENTRY_BLOCK(inode_block->inline_content);
	}

	if (dir->i_ino==4)
		hmfs_dbg("%d\n",old_bidx);
	return alloc_new_data_block(sbi, dir, old_bidx);
}

static unsigned long dir_block_index(unsigned int level, unsigned int idx)
{
	unsigned long i;
	unsigned long bidx = 0;

	for (i = 0; i < level; i++)
		bidx += dir_buckets(i) * bucket_blocks(i);
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

static struct hmfs_dir_entry *find_target_dentry(struct qstr *name, 
				int *max_slots, struct hmfs_dentry_ptr *d)
{
	struct hmfs_dir_entry *de;
	unsigned long bit_pos = 0;
	hmfs_hash_t namehash = hmfs_dentry_hash(name);
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
		if (early_match_name(name->len, namehash, de)
				&& !memcmp(d->filename[bit_pos], name->name, name->len))
			goto found;

		if (max_slots && max_len > *max_slots) {
			*max_slots = max_len;
			max_len = 0;
		}
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

/*
 * Find a dentry in a data block or inline inode
 * @dentry_blk: pointer to hmfs_dentry_block
 * @name: name of dentry want to find
 * @max_slots: the maximum index of slot to store dentry
 * @is_normal_inode: whether is a normal inode or inline inode
 */
static struct hmfs_dir_entry *find_in_block(struct hmfs_dentry_block *dentry_blk,
				struct qstr *name, int *max_slots, int is_normal_inode)
{
	struct hmfs_dir_entry *de;
	struct hmfs_dentry_ptr d;

	make_dentry_ptr(&d, (void *)dentry_blk, is_normal_inode);
	de = find_target_dentry(name, max_slots, &d);

	/*  
	 * For the most part, it should be a bug when name_len is zero.
	 * We stop here for figuring out where the bugs has occurred.
	 */
	return de;
}

/*
 * Find a dentry in a specified dir level
 * @dir: directory of dentry
 * @level: level number
 * @name: name of dentry want to find
 * @namehash: hash value of name of dentry
 * @res_bidx: return value, block index of container of dentry. If
 * 		it's an inline inode, res_bidx should be -1
 * @ofs_in_blk: return value, dentry offset in dentry data block(res_bidx)
 */
static struct hmfs_dir_entry *find_in_level(struct inode *dir, 
				unsigned int level,	struct qstr *name, hmfs_hash_t namehash,
				int *res_bidx, int *ofs_in_blk)
{
	int s = GET_DENTRY_SLOTS(name->len);
	unsigned int nbucket, nblock;
	unsigned int bidx, end_block;
	struct hmfs_dir_entry *de = NULL;
	bool room = false;
	/* 4 is ok. Because each bucket has 4 blocks atmost */
	void *blocks[4] = { NULL, NULL, NULL, NULL };
	int max_slots;
	int err;
	int size, start_blk;
	struct hmfs_dentry_block *dentry_blk = NULL;

	nbucket = dir_buckets(level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, le32_to_cpu(namehash) % nbucket);
	end_block = bidx + nblock;

	err = get_data_blocks(dir, bidx, end_block, blocks, &size, RA_END);
	if (size <= 0)
		return NULL;

	for (start_blk = 0; bidx < end_block; bidx++) {
		dentry_blk = blocks[start_blk++];

		if (!dentry_blk)
			continue;

		de = find_in_block(dentry_blk, name, &max_slots, 1);
		if (de) {
			if (res_bidx != NULL)
				*res_bidx = bidx;
			if (ofs_in_blk != NULL)
				*ofs_in_blk = de - dentry_blk->dentry;
			break;
		}
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
 * It returns the block index and entry offset where the entry was found ,
 * and the entry itself. And if it's an inline dir, bidx should be -1 
 */
struct hmfs_dir_entry *hmfs_find_entry(struct inode *dir, struct qstr *child,
				int *bidx, int *ofs_in_blk)
{
	unsigned long npages = dir_blocks(dir);
	struct hmfs_dir_entry *de = NULL;
	hmfs_hash_t name_hash = 0;
	unsigned int max_depth;
	unsigned int level;
	struct hmfs_inode *inode_block;
	struct hmfs_dentry_block *dentry_blk;
	int max_slots;

	if (npages == 0)
		return NULL;

	name_hash = hmfs_dentry_hash(child);
	max_depth = HMFS_I(dir)->i_current_depth;

	if (is_inline_inode(dir)) {
		inode_block = get_node(HMFS_I_SB(dir), dir->i_ino);
		if (IS_ERR(inode_block)) {
			return NULL;
		}
		dentry_blk = DENTRY_BLOCK(inode_block->inline_content);
		de = find_in_block(dentry_blk, child, &max_slots, 0);

		if (de) {
			if (bidx)
				*bidx = -1;
			if (ofs_in_blk)
				*ofs_in_blk = de - dentry_blk->dentry;
		}
		return de;
	}

	for (level = 0; level < max_depth; level++) {
		de = find_in_level(dir, level, child, name_hash, bidx, ofs_in_blk);
		if (de)
			break;
	}

	if (!de && HMFS_I(dir)->chash != name_hash) {
		HMFS_I(dir)->chash = name_hash;
		HMFS_I(dir)->clevel = level - 1;
	}
	return de;
}

/* 
 * Return a writable dentry block of parent dir.
 * It's the first block of normal inode or the inline_content 
 * of inline inode
 */
struct hmfs_dir_entry *hmfs_parent_dir(struct inode *dir)
{
	struct hmfs_dir_entry *de = NULL;
	struct hmfs_dentry_block *dentry_blk = NULL;

	dentry_blk = get_dentry_block_for_write(dir, 0);
	if (IS_ERR(dentry_blk))
		return NULL;

	de = &dentry_blk->dentry[1];
	return de;
}

/*
 * de should be writable
 */
void hmfs_set_link(struct inode *dir, struct hmfs_dir_entry *de,
				struct inode *inode)
{
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode->i_mode);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty(dir);
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

	hn = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE, false);

	if (IS_ERR(hn))
		return PTR_ERR(hn);

	init_dent_inode(name, &hn->i);

	return 0;
}

static void do_make_empty_dir(struct inode *inode, struct inode *parent,
				struct hmfs_dentry_ptr *d)
{
	struct hmfs_dir_entry *de;

	memset_nt((void *)d->bitmap, 0, SIZE_OF_DENTRY_BITMAP);
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

static int make_empty_dir(struct inode *inode, struct inode *parent,
				struct hmfs_node *hn)
{
	struct hmfs_dentry_block *dentry_blk = NULL;
	struct hmfs_dentry_ptr d;

	dentry_blk = get_dentry_block_for_write(inode, 0);
	if (IS_ERR(dentry_blk))
		return PTR_ERR(dentry_blk);

	make_dentry_ptr(&d, (void *)dentry_blk, is_inline_inode(inode));
	do_make_empty_dir(inode, parent, &d);

	return 0;
}

static struct hmfs_node *init_inode_metadata(struct inode *inode, struct inode *dir,
				const struct qstr *name)
{
	struct super_block *sb = inode->i_sb;
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	int err;
	struct hmfs_node *hn = NULL;

	hn = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE, false);
	if (IS_ERR(hn))
		return hn;

	if (is_inode_flag_set(HMFS_I(inode), FI_NEW_INODE)) {
		if (S_ISDIR(inode->i_mode)) {
			err = make_empty_dir(inode, dir, hn);
			if (err)
				goto error;
		}

		err = hmfs_init_acl(inode, dir);
		if (err)
			goto error;
	}

	if (name)
		init_dent_inode(name, &hn->i);

	/*
	 * This file should be checkpointed during fsync.
	 * We lost i_pino from now on.
	 */
	/* For newly created directory, FI_INC_LINK is set in hmfs_new_inode */
	if (is_inode_flag_set(HMFS_I(inode), FI_INC_LINK)) {
		inc_nlink(inode);
		mark_inode_dirty(inode);
	}
	return hn;

error:
	return ERR_PTR(err);
}

static void update_parent_metadata(struct inode *dir, struct inode *inode,
				unsigned int current_depth)
{
	if (inode && is_inode_flag_set(HMFS_I(inode), FI_NEW_INODE)) {
		if (S_ISDIR(inode->i_mode)) {
			inc_nlink(dir);
			set_inode_flag(HMFS_I(dir), FI_UPDATE_DIR);
		}
		clear_inode_flag(HMFS_I(inode), FI_NEW_INODE);
	}
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty(dir);

	if (HMFS_I(dir)->i_current_depth != current_depth) {
		HMFS_I(dir)->i_current_depth = current_depth;
		set_inode_flag(HMFS_I(dir), FI_UPDATE_DIR);
	}

	if (inode && is_inode_flag_set(HMFS_I(inode), FI_INC_LINK))
		clear_inode_flag(HMFS_I(inode), FI_INC_LINK);
}

/* Test whether dir has enough space for new dentry */
static int room_for_filename(const void *bitmap, int slots, int max_slots)
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

/* Update dentry structure after adding a new dentry */
static void hmfs_update_dentry(nid_t ino, umode_t mode, struct hmfs_dentry_ptr *d,
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
 * Caller should grab and release a rwsem by calling mutex_lock_op() and
 * mutex_unlock_op().
 */
int __hmfs_add_link(struct inode *dir, const struct qstr *name,
				struct inode *inode)
{
	unsigned int bit_pos = 0;
	unsigned int level;
	unsigned int current_depth = 0;
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
	struct hmfs_inode *inode_block;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	dentry_hash = hmfs_dentry_hash(name);

	if (is_inline_inode(dir)) {
		inode_block = get_node(sbi, dir->i_ino);
		if (IS_ERR(inode_block)) {
			err = PTR_ERR(inode_block);
			goto out;
		}

		/* Whether inline inode could save new dentry */
		dentry_blk = DENTRY_BLOCK(inode_block->inline_content);
		bit_pos = room_for_filename(dentry_blk->dentry_bitmap, slots,
						NR_DENTRY_IN_INLINE_INODE);
		if (bit_pos < NR_DENTRY_IN_INLINE_INODE) {
			inode_block = alloc_new_node(sbi, dir->i_ino, dir, SUM_TYPE_INODE, false);
			if (IS_ERR(inode_block)) {
				err = PTR_ERR(inode_block);
				goto out;
			}
			dentry_blk = DENTRY_BLOCK(inode_block->inline_content);
			goto add_dentry;
		} else {
			err = hmfs_convert_inline_inode(dir);
			if (err)
				return err;
			dentry_blk = NULL;
		}
	}

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

	nbucket = dir_buckets(level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, (le32_to_cpu(dentry_hash) % nbucket));

	for (block = bidx; block <= (bidx + nblock - 1); block++) {
		//FIXME: use bat process to reduce read time
		if (block >= end_blk) {
			dentry_blk = alloc_new_data_block(sbi, dir, block);

			bit_pos = 0;
			end_blk = block + 1;
			mark_size_dirty(dir, end_blk << HMFS_PAGE_SIZE_BITS);
			goto add_dentry;
		} else {
			err = get_data_blocks(dir, block, block + 1, blocks, &size,
						RA_DB_END);
			dentry_blk = blocks[0];
			if (size <= 0)
				return err;
			err = 0;

			/* There may be a hole in data blocks */
			if (dentry_blk)
				bit_pos = room_for_filename(dentry_blk->dentry_bitmap, slots,
								NR_DENTRY_IN_BLOCK);
			else 
				bit_pos = 0;
			if (bit_pos < NR_DENTRY_IN_BLOCK) {
				dentry_blk = alloc_new_data_block(sbi, dir, block);

				if (IS_ERR(dentry_blk)) {
					err = PTR_ERR(dentry_blk);
					goto out;
				}
				goto add_dentry;
			}
		}
	}

	/* Move to next level to find the empty slot for new dentry */
	++level;
	goto start;
add_dentry:
	if (inode) {
		hn = init_inode_metadata(inode, dir, name);

		if (IS_ERR(hn)) {
			err = PTR_ERR(hn);
			goto out;
		}
	}
	make_dentry_ptr(&d, (void *)dentry_blk, !is_inline_inode(dir));
	hmfs_update_dentry(inode->i_ino, inode->i_mode, &d, name, dentry_hash,
			bit_pos);

	if (inode) {
		/* we don't need to mark_inode_dirty now */
		HMFS_I(inode)->i_pino = dir->i_ino;
	}

	update_parent_metadata(dir, inode, current_depth);
out:
	if (is_inode_flag_set(HMFS_I(dir), FI_UPDATE_DIR)) {
		clear_inode_flag(HMFS_I(dir), FI_UPDATE_DIR);
	}
	return err;
}

void hmfs_drop_nlink(struct inode *dir, struct inode *inode, struct page *page)
{
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
	}
	inode->i_ctime = CURRENT_TIME;

	drop_nlink(inode);
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(inode);
		i_size_write(inode, 0);
	}
}

/*
 * It only removes the dentry from the dentry page, corresponding name
 * entry in name page does not need to be touched during deletion.
 * @dentry: entry in NVM which is to be deleted
 * @dentry_blk: entry's container
 * @dir: directory of entry
 * @inode: vfs inode of entry
 * @bidx: block index of dentry_blk in dir
 */
void hmfs_delete_entry(struct hmfs_dir_entry *dentry,
				struct hmfs_dentry_block *dentry_blk, struct inode *dir,
				struct inode *inode, int bidx)
{
	unsigned int bit_pos;
	struct hmfs_sb_info *sbi = HMFS_I_SB(dir);
	int slots = GET_DENTRY_SLOTS(le16_to_cpu(dentry->name_len));
	int i;
	size_t dir_i_size;

	bit_pos = dentry - dentry_blk->dentry;
	for (i = 0; i < slots; i++)
		clear_bit_le(bit_pos + i, dentry_blk->dentry_bitmap);

	/* Let's check and deallocate this dentry page */
	bit_pos = find_next_bit_le(dentry_blk->dentry_bitmap,
					NR_DENTRY_IN_BLOCK, 0);

	dir->i_ctime = dir->i_mtime = CURRENT_TIME;

	if (inode && S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
	}
	mark_inode_dirty(dir);

	if (inode) {
		inode->i_ctime = CURRENT_TIME;
		drop_nlink(inode);
		if (S_ISDIR(inode->i_mode)) {
			drop_nlink(inode);
			i_size_write(inode, 0);
		}
		mark_inode_dirty(inode);

		if (inode->i_nlink == 0)
			add_orphan_inode(sbi, inode->i_ino);
	}

	if (bit_pos == NR_DENTRY_IN_BLOCK) {
		/* Inline directory should never reach here */
		hmfs_bug_on(sbi, is_inline_inode(dir));

		hmfs_dbg("%d\n",bidx);
		dir_i_size = i_size_read(dir);
		truncate_hole(dir, bidx, bidx + 1);
		if (dir_i_size >> HMFS_PAGE_SIZE_BITS == bidx + 1) {
			dir_i_size = hmfs_dir_seek_data_reverse(dir, bidx + 1)
					<< HMFS_PAGE_SIZE_BITS; 
			mark_size_dirty(dir, dir_i_size + HMFS_PAGE_SIZE);
		}
	}
}

bool hmfs_empty_dir(struct inode *dir)
{
	unsigned long bidx;
	unsigned int bit_pos;
	struct hmfs_dentry_block *dentry_blk;
	unsigned long nblock = dir_blocks(dir);
	struct hmfs_inode *inode_block;
	int pos = -1;
	int size = 0;
	int err = 0;
	void *blocks[16];

	if (is_inline_inode(dir)) {
		inode_block = get_node(HMFS_I_SB(dir), dir->i_ino);
		if (IS_ERR(inode_block))
			return false;
		dentry_blk = DENTRY_BLOCK(inode_block->inline_content);
		bit_pos = find_next_bit_le(dentry_blk->dentry_bitmap,
						NR_DENTRY_IN_INLINE_INODE, 2);
		if (bit_pos < NR_DENTRY_IN_INLINE_INODE)
			return false;
		return true;
	}

	for (bidx = 0; bidx < nblock; bidx++) {
		if (pos < 0 || pos == size) {
			err = get_data_blocks(dir, bidx, nblock, blocks, &size,
						RA_DB_END);
			if (err && (err != -ENODATA || size <= 0))
				return false;
			pos = 0;
		}
		dentry_blk = blocks[pos++];

		if (dentry_blk == NULL) {
			hmfs_bug_on(HMFS_I_SB(dir), bidx == 0);
			continue;
		}

		if (bidx == 0)
			bit_pos = 2;
		else
			bit_pos = 0;
		bit_pos = find_next_bit_le(dentry_blk->dentry_bitmap,
						NR_DENTRY_IN_BLOCK, bit_pos);

		if (bit_pos < NR_DENTRY_IN_BLOCK)
			return false;
	}
	return true;
}

static bool hmfs_fill_dentries(struct hmfs_sb_info *sbi, struct dir_context *ctx, 
				struct hmfs_dentry_ptr *d, unsigned int start_pos)
{
	unsigned char d_type = DT_UNKNOWN;
	unsigned int bit_pos;
	struct hmfs_dir_entry *de = NULL;

	bit_pos = ((unsigned long)ctx->pos % d->max);
	while (bit_pos < d->max) {
		bit_pos = find_next_bit_le(d->bitmap, d->max, bit_pos);
		if (bit_pos >= d->max)
			break;

		de = &d->dentry[bit_pos];
		if (de->file_type < HMFS_FT_MAX)
			d_type = hmfs_filetype_table[de->file_type];
		else
			d_type = DT_UNKNOWN;

		hmfs_bug_on(sbi, !le16_to_cpu(de->name_len));
		if (!dir_emit(ctx, d->filename[bit_pos], le16_to_cpu(de->name_len),
					le32_to_cpu(de->ino), d_type)) {
			return true;
		}

		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
		ctx->pos = start_pos + bit_pos;
	}
	return false;
}

static int hmfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	unsigned long npages = dir_blocks(inode);
	struct hmfs_dentry_block *dentry_blk = NULL;
	struct hmfs_inode *inode_block;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_dentry_ptr d;
	int size = -1;
	int i = 0;
	int err = 0;
	void **buf;
	int is_normal_inode = !is_inline_inode(inode);
	int nr_dentry_in_block = is_normal_inode ? NR_DENTRY_IN_BLOCK :
			NR_DENTRY_IN_INLINE_INODE;
	unsigned int n = ((unsigned long)ctx->pos / nr_dentry_in_block);

	buf = vzalloc(HMFS_PAGE_SIZE);

	if (!buf)
		return -ENOMEM;

	inode_read_lock(inode);
	if (!is_normal_inode) {
		if (n > 0)
			goto stop;
		inode_block = get_node(sbi, inode->i_ino);
		if (IS_ERR(inode_block)) {
			inode_read_unlock(inode);
			return PTR_ERR(inode_block);
		}
		dentry_blk = DENTRY_BLOCK(inode_block->inline_content);
		npages = 0;
		goto fill;
	}

	for (; n < npages; n++) {
		if (i >= size) {
			err = get_data_blocks(inode, n, npages, buf, &size,
						RA_DB_END);
			if (size < 0) {
				hmfs_bug_on(HMFS_I_SB(inode), !err);
				goto stop;
			}
			i = 0;
		}

		dentry_blk = buf[i++];
		if (!dentry_blk)
			continue;
fill:
		make_dentry_ptr(&d, (void *)dentry_blk, is_normal_inode);

		if (hmfs_fill_dentries(HMFS_I_SB(inode), ctx, &d, 
				n * nr_dentry_in_block))
			goto stop;

		ctx->pos = (n + 1) * nr_dentry_in_block;
	}
stop:
	inode_read_unlock(inode);
	vfree(buf);
	return err;
}

const struct file_operations hmfs_dir_operations = {
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	.iterate = hmfs_readdir,
	.fsync = hmfs_sync_file,
	.unlocked_ioctl = hmfs_ioctl,
};

/*
 * fs/hmfs/recovery.c
 *
 * Copyright (c) 2015 SJTU RadLab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"

static void recovery_data_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool modify_vb = false;
	block_t addr_in_par;
	int par_type;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while (1) {
		this = __get_node(sbi, args.cp_i, args.nid);

		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));

		if (IS_ERR(this)) {
			/* the node(args.nid) has been deleted */
			break;
		}

		if (this == last)
			goto next;

		par_type = get_summary_type(par_sum);
		if (par_type == SUM_TYPE_INODE) {
			addr_in_par = le64_to_cpu(this->i.i_addr[args.ofs_in_node]);
		} else {
			addr_in_par = le64_to_cpu(this->dn.addr[args.ofs_in_node]);
		}

		/*
		 * In recovery, the address stored in parent node would be
		 * arg.src_addr or an invalid address. Because GC might terminate
		 * in the loop change this address.
		 * Condition addr_in_par != args.src_addr is not sufficient
		 * to terminate recovery. For example, we delete a node in a
		 * checkpoint and reuse it later. And address in reused node
		 * is not equal to args.src_addr but we could not modify it.
		 * Luckly, the child block in that node is valid and we could
		 * judge this case by the value of address.
		 */
		if (addr_in_par != args.src_addr && is_valid_address(sbi, addr_in_par))
			break;
		
		if (addr_in_par != args.src_addr) {
			/* Recover address in parent node */
			if (par_type == SUM_TYPE_INODE) {
				hmfs_memcpy_atomic(&this->i.i_addr[args.ofs_in_node],
						&args.src_addr, 8);
			} else {
				hmfs_memcpy_atomic(&this->dn.addr[args.ofs_in_node],
						&args.src_addr, 8);
			}

			if (!modify_vb) {
				args.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(args.dest_sum);
				modify_vb = true;
			}
		}

		last = this;
next:
		if (args.cp_i == cm_i->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}
}

static void recovery_xdata_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg arg;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t addr_in_par;
	bool modify_vb = false;
	int x_tag;

	prepare_move_argument(&arg, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while (1) {
		this = __get_node(sbi, arg.cp_i, arg.nid);

		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;

		x_tag = le64_to_cpu(XATTR_HDR(arg.src)->h_magic);
		addr_in_par = XBLOCK_ADDR(this, x_tag);
		
		if (addr_in_par != arg.src_addr && is_valid_address(sbi, addr_in_par)) {
			break;
		}
		
		if (addr_in_par != arg.src_addr) {
			hmfs_memcpy_atomic(JUMP(this, x_tag), &arg.src_addr, 8);
		
			if (!modify_vb) {
				arg.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(arg.dest_sum);
				modify_vb = true;
			}
		}

		last = this;

next:
		if (arg.cp_i == cm_i->last_cp_i)
			break;
		arg.cp_i = get_next_checkpoint_info(sbi, arg.cp_i);
	}
}

static void recovery_node_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    unsigned int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;
	block_t addr_in_par;
	bool modify_vb = false;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	while (1) {
		this = get_nat_entry_block(sbi, args.cp_i->version, args.nid);
		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;

		addr_in_par = le64_to_cpu(this->entries[args.ofs_in_node].block_addr);
		/* Src node has been COW or removed */
		if (addr_in_par != args.src_addr && is_valid_address(sbi, addr_in_par)) {
			break;
		}

		if (addr_in_par != args.src_addr) {
			hmfs_memcpy_atomic(&this->entries[args.ofs_in_node].block_addr,
					&args.src_addr, 8);
			if (!modify_vb) {
				args.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(args.dest_sum);
				modify_vb = true;
			}
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}
}

static void recovery_nat_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
			   struct hmfs_summary *src_sum)
{
	void *last = NULL, *this = NULL;
	struct hmfs_checkpoint *hmfs_cp = NULL;
	struct hmfs_nat_node *nat_node = NULL;
	struct gc_move_arg args;
	bool modify_vb = false;
	nid_t par_nid;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	while (1) {
		if (IS_NAT_ROOT(args.nid))
			this = args.cp_i->cp;
		else {
			par_nid = MAKE_NAT_NODE_NID(GET_NAT_NODE_HEIGHT(args.nid) - 1, 
							GET_NAT_NODE_OFS(args.nid)); 
			this = get_nat_node(sbi, args.cp_i->version, par_nid);
		}

		hmfs_bug_on(sbi, !this);
		if (this == last)
			goto next;

		if (IS_NAT_ROOT(args.nid)) {
			hmfs_cp = HMFS_CHECKPOINT(this);
			addr_in_par = le64_to_cpu(hmfs_cp->nat_addr);
		} else {
			nat_node = HMFS_NAT_NODE(this);
			addr_in_par = le64_to_cpu(nat_node->addr[args.ofs_in_node]);
		}

		if (addr_in_par != args.src_addr && is_valid_address(sbi, addr_in_par)) {
			break;
		}

		if (addr_in_par != args.src_addr) {
			if (IS_NAT_ROOT(args.nid)) {
				hmfs_memcpy_atomic(&hmfs_cp->nat_addr, &args.src_addr, 8);
			} else {
				hmfs_memcpy_atomic(&nat_node->addr[args.ofs_in_node], 
						&args.src_addr, 8);
			}

			if (!modify_vb) {
				args.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(args.dest_sum);
				modify_vb = true;
			}
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}
}

static void recovery_orphan_block(struct hmfs_sb_info *sbi, seg_t src_segno, 
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *hmfs_cp;
	block_t cp_addr, orphan_addr;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_NODE);
	cp_addr = le64_to_cpu(*((__le64 *)args.src));
	hmfs_cp = ADDR(sbi, cp_addr);
	orphan_addr = le64_to_cpu(hmfs_cp->orphan_addrs[get_summary_offset(src_sum)]);

	if (orphan_addr != args.src_addr) {
		hmfs_cp->orphan_addrs[get_summary_offset(src_sum)] = 
				cpu_to_le64(args.src_addr);
		args.dest_sum = get_summary_by_addr(sbi, orphan_addr);
		clear_summary_valid_bit(args.dest_sum);
	}
}

static void recovery_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	block_t addr_in_other, cp_addr;
	struct hmfs_summary *dest_sum;
	int i;
	block_t orphan_addr;
	__le64 *orphan;

	/*
	 * We could not use prepare_move_argument here. Because it might
	 * break the checkpoint list due to checkpoint list is inconsistent
	 * in NVM
	 */
	cp_addr = __cal_page_addr(sbi, src_segno, src_off);
	this_cp = HMFS_CHECKPOINT(cp_addr);
	next_cp = ADDR(sbi, le64_to_cpu(this_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(this_cp->prev_cp_addr));

	addr_in_other = le64_to_cpu(next_cp->prev_cp_addr);
	if (addr_in_other != cp_addr) {
		next_cp->prev_cp_addr = cpu_to_le64(cp_addr);
		prev_cp->next_cp_addr = cpu_to_le64(cp_addr);
		dest_sum = get_summary_by_addr(sbi, addr_in_other);
		clear_summary_valid_bit(dest_sum);
	}

	for (i = 0; i < NUM_ORPHAN_BLOCKS; i++) {
		orphan_addr = le64_to_cpu(this_cp->orphan_addrs[i]);
		if (orphan_addr == NULL_ADDR)
			break;
		orphan = ADDR(sbi, orphan_addr);
		hmfs_memcpy_atomic(orphan, &cp_addr, 8);
	}
}

static void recovery_gc_segment(struct hmfs_sb_info *sbi, seg_t segno)
{
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	struct hmfs_summary *sum;
	block_t seg_addr;

	seg_addr = __cal_page_addr(sbi, segno, 0);
	sum = get_summary_by_addr(sbi, seg_addr);

	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		is_current = get_summary_start_version(sum)	== cm_i->new_version;

		if ((!get_summary_valid_bit(sum) && !is_current) || is_current)
			continue;

		switch (get_summary_type(sum)) {
		case SUM_TYPE_DATA:
			recovery_data_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_XDATA:
			recovery_xdata_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_INODE:
		case SUM_TYPE_DN:
		case SUM_TYPE_IDN:
			recovery_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_NATN:
		case SUM_TYPE_NATD:
			recovery_nat_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_ORPHAN:
			recovery_orphan_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_CP:
			recovery_checkpoint_block(sbi, segno, off, sum);
			break;
		default:
			hmfs_bug_on(sbi, 1);
		}
	}
}

/* 
 * In GC process, we have mark the valid bit in summary. It's hard
 * to redo GC process. But we have an idea which block is mark as
 * valid and we need to reset the valid its of them.
 */
void recovery_gc_crash(struct hmfs_sb_info *sbi, struct hmfs_checkpoint *hmfs_cp)
{
	void *new_gc_logs;
	int nr_gc_segs;
	block_t log_addr;
	int i;
	seg_t segno;

	new_gc_logs = sbi->gc_logs;
	nr_gc_segs = le32_to_cpu(hmfs_cp->nr_gc_segs);
	log_addr = __cal_page_addr(sbi, le32_to_cpu(hmfs_cp->gc_logs), 0);
	sbi->gc_logs = ADDR(sbi, log_addr);
	
	for (i = 0; i < nr_gc_segs; i++, sbi->gc_logs++) {
		segno = le32_to_cpu(*sbi->gc_logs);
		recovery_gc_segment(sbi, segno);
	}

	sbi->gc_logs = new_gc_logs;
}

#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/export.h>

#include <linux/list.h>
#include <linux/init.h>

#include "hmfs.h"
#include "node.h"

MODULE_LICENSE("Dual BSD/GPL");

// extern struct task_struct init_task;
static struct mm_struct *imm;

static pte_t *hmfs_pte_alloc_one_kernel(struct mm_struct *mm, unsigned long addr)
{
	return (pte_t *)__get_free_page((GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO));
}

static int __hmfs_pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		pud_free(mm, new);
	else
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;

}

static pud_t *hmfs_pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long addr)
{
	return (unlikely(pgd_none(*pgd)) && __hmfs_pud_alloc(mm, pgd, addr))?
					NULL: pud_offset(pgd, addr);
}

static int __hmfs_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pud_present(*pud))		/* Another has populated it */
		pmd_free(mm, new);
	else
		pud_populate(mm, pud, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

static pmd_t *hmfs_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __hmfs_pmd_alloc(mm, pud, address))?
				NULL: pmd_offset(pud, address);
}

static pte_t *hmfs_pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{	
	pte_t *new;
	if (likely(!pmd_none(*pmd)))
		return pte_offset_kernel(pmd, address);
	
	new = hmfs_pte_alloc_one_kernel(mm, address);
	if (!new)
		return NULL;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		pmd_populate_kernel(mm, pmd, new);
		new = NULL;
	} else
		VM_BUG_ON(pmd_trans_splitting(*pmd));
	spin_unlock(&mm->page_table_lock);
	if (new)
		pte_free_kernel(mm, new);
	return pte_offset_kernel(pmd, address);
}

static int map_pte_range(struct mm_struct *mm, pmd_t *pmd, unsigned long addr,
				unsigned long end, uint64_t *pfns, const uint8_t seg_type, int *i)
{
	pte_t *pte = hmfs_pte_alloc(mm, pmd, addr);
	uint64_t pfn = pfns[(*i) >> HMFS_BLOCK_SIZE_4K_BITS[seg_type]];
	pfn += (*i) & (HMFS_BLOCK_SIZE_4K[seg_type] - 1);

	if (!pte)
		return -ENOMEM;
	do {
		set_pte_at(mm, addr, pte, pte_mkspecial(pfn_pte(pfn, PAGE_KERNEL)));
		pfn++;
		(*i)++;
		if (!((*i) & (HMFS_BLOCK_SIZE_4K[seg_type] - 1))) {
			pfn = pfns[(*i) >> HMFS_BLOCK_SIZE_4K_BITS[seg_type]];
		}
		BUG_ON(addr > end);
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static int map_pmd_range(struct mm_struct *mm, pud_t *pud, unsigned long addr,
				unsigned long end, uint64_t *pfns, const uint8_t seg_type, int *i)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = hmfs_pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (map_pte_range(mm, pmd, addr, next, pfns, seg_type, i))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static int map_pud_range(struct mm_struct *mm, pgd_t *pgd, unsigned long addr,
				unsigned long end, uint64_t *pfns, const uint8_t seg_type, int *i)
{
	pud_t *pud = NULL;
	unsigned long next;

	pud = hmfs_pud_alloc(mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (map_pmd_range(mm, pud, addr, next, pfns, seg_type, i))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

/* map data blocks with index [start, start + 8) of inode */
int remap_data_blocks_for_write(struct inode *inode, unsigned long st_addr, 
				uint64_t start, uint64_t end)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct mm_struct *mm = current->mm;
	const uint8_t seg_type = HMFS_I(inode)->i_blk_type;
	unsigned long ed_addr = st_addr + ((end - start) << HMFS_BLOCK_SIZE_BITS(seg_type));
	void *data_block;
	pgd_t *pgd = pgd_offset(mm, st_addr);
	unsigned long next, addr = st_addr;
	uint64_t buf[8];
	uint64_t *pfns = buf;
	int i = 0;

	hmfs_bug_on(sbi, end - start > 8);
	while (start < end) {
		data_block = alloc_new_data_block(sbi, inode, start++);
		if (IS_ERR(data_block))
			return PTR_ERR(data_block);
		*pfns++ = pfn_from_vaddr(sbi, data_block);
	}
	pfns = buf;

	flush_cache_vmap(st_addr, ed_addr);
	do {
		next = pgd_addr_end(addr, ed_addr);
		if (map_pud_range(mm, pgd, addr, next, pfns, seg_type, &i))
			return -ENOMEM;
	} while (pgd++, addr = next, addr != ed_addr);

	//FIXME: need flush tlb?
	//flush_tlb_kernel_range(st_addr, ed_addr);
	return 0;
}

static inline uint64_t file_block_bitmap_size(uint64_t nr_map_page)
{
	return	(nr_map_page + 7) >> 3;
}

// How about a vmap for node?
int vmap_file_range(struct inode *inode)
{
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct page **pages;
	uint8_t blk_type = fi->i_blk_type;
	size_t size = i_size_read(inode);
	unsigned long page_buf_sz;
	int ret = 0;
	uint64_t old_nr_map_page = 0;
	
	// Reuse previous mapping bitmap
	// Or allocate a new mapping bitmap according to file size
	if (fi->rw_addr) {
		unsigned char *bitmap = NULL;
		old_nr_map_page = fi->nr_map_page;
		if (fi->nr_map_page < (ULONG_MAX >> 1))
			fi->nr_map_page <<= 1;
		else
			return 1;

		bitmap = kzalloc(file_block_bitmap_size(fi->nr_map_page), GFP_KERNEL);
		if (!bitmap)
			goto out;
		memcpy(bitmap, fi->block_bitmap, fi->bitmap_size);
		fi->bitmap_size = file_block_bitmap_size(fi->nr_map_page);
		kfree(fi->block_bitmap);
		fi->block_bitmap = bitmap;
	} else {
		uint64_t nr_pages;

		// why ">> 1"?
		if (!size)
			size = (NORMAL_ADDRS_PER_INODE >> 1) << HMFS_BLOCK_SIZE_BITS(blk_type);
		
		nr_pages = (size + HMFS_BLOCK_SIZE[blk_type] - 1) >> HMFS_BLOCK_SIZE_BITS(blk_type);
		if (nr_pages > NORMAL_ADDRS_PER_INODE || (nr_pages << 1) < NORMAL_ADDRS_PER_INODE)
			nr_pages <<= 1;
		else
			nr_pages = NORMAL_ADDRS_PER_INODE;
		fi->nr_map_page = nr_pages << (HMFS_BLOCK_SIZE_BITS(blk_type) - PAGE_SHIFT);
		fi->bitmap_size = file_block_bitmap_size(fi->nr_map_page);
		fi->block_bitmap = kzalloc(fi->bitmap_size, GFP_KERNEL);
	}

	if (!fi->block_bitmap)
		goto out;

	// Allocate virtual pages in kernel space according to bitmap size
	// If larger than what SLUB can offer, use vmalloc
	page_buf_sz = fi->nr_map_page * sizeof(struct page *);
	if (page_buf_sz > (1 << (MAX_ORDER - 1) << PAGE_SHIFT)) 
		pages = vmalloc(page_buf_sz);
	else
		pages = kzalloc(page_buf_sz, GFP_KERNEL);

	if (!pages)
		goto free_bitmap;

	// Map the data pages of inode
	ret = get_file_page_struct(inode, pages, 0, fi->nr_map_page,0);

	if (ret && ret != -ENODATA)
		goto free_pages;

	if (fi->rw_addr)
		vm_unmap_ram(fi->rw_addr, old_nr_map_page);

	// PAGE_KERNEL could be PAGE_KERNEL_RO for read only access
	fi->rw_addr = vm_map_ram(pages, fi->nr_map_page, 0, PAGE_KERNEL);
	if (!fi->rw_addr)
		goto free_pages;
#define free_pages(sz, pgs)	do {\
	if (sz > (1 << (MAX_ORDER - 1) << PAGE_SHIFT))	\
		vfree(pgs);	\
	else\
		kfree(pgs);} while (0)
	free_pages(page_buf_sz, pages);
	return 0;
free_pages:
	free_pages(page_buf_sz, pages);
free_bitmap:
	kfree(fi->block_bitmap);
out:
	fi->rw_addr = NULL;
	fi->block_bitmap = NULL;
	fi->bitmap_size = 0;
	fi->nr_map_page = 0;
	return 1;
}

//	pvmap_page_range
//	'p' stands for partial
// 	Basically the same with vmap_page_range in vmalloc.c

pte_t *hmfsp_pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	pte_t *pte;

	pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
	return pte;
}

int _hmfsp__pte_alloc_kernel(pmd_t *pmd, unsigned long address)
{
	pte_t *new = hmfsp_pte_alloc_one_kernel(imm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&(imm->page_table_lock));
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		pmd_populate_kernel(imm, pmd, new);
		new = NULL;
	} else
		VM_BUG_ON(pmd_trans_splitting(*pmd));
	spin_unlock(&(imm->page_table_lock));
	if (new)
		pte_free_kernel(imm, new);
	return 0;
}

int pvmap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr)
{
	pte_t *pte;
	/*
	 * nr is a running index into the array which helps higher level
	 * callers keep track of where we're up to.
	 */

	pte = ((unlikely(pmd_none(*(pmd))) && _hmfsp__pte_alloc_kernel(pmd, addr))? NULL: pte_offset_kernel(pmd, addr));
	// pte = pte_alloc_kernel(pmd, addr);

	if (!pte)
		return -ENOMEM;
	do {
		// hmfs_dbg("[DP]addr:%lx,end:%lx\n",addr,end);
		struct page *page = pages[*nr];
		// Unknown bug here
		// if (WARN_ON(!pte_none(*pte)))
		// 	return -EBUSY;
		if (WARN_ON(!page))
			return -ENOMEM;
		set_pte_at(imm, addr, pte, mk_pte(page, prot));
		(*nr)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

int _hmfsp__pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
#ifndef __ARCH_HAS_4LEVEL_HACK
	if (pud_present(*pud))		/* Another has populated it */
		pmd_free(mm, new);
	else
		pud_populate(mm, pud, new);
#else
	if (pgd_present(*pud))		/* Another has populated it */
		pmd_free(mm, new);
	else
		pgd_populate(mm, pud, new);
#endif /* __ARCH_HAS_4LEVEL_HACK */
	spin_unlock(&mm->page_table_lock);
	return 0;
}

static inline pmd_t *hmfsp_pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && _hmfsp__pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}

int pvmap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = hmfsp_pmd_alloc(imm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (pvmap_pte_range(pmd, addr, next, prot, pages, nr))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

int _hmfsp__pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		pud_free(mm, new);
	else
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

static inline pud_t *hmfsp_pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && _hmfsp__pud_alloc(mm, pgd, address))?
		NULL: pud_offset(pgd, address);
}

int pvmap_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr)
{
	pud_t *pud;
	unsigned long next;

	pud = hmfsp_pud_alloc(imm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (pvmap_pmd_range(pud, addr, next, prot, pages, nr))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

/*
 * Set up page tables in kva (addr, end). The ptes shall have prot "prot", and
 * will have pfns corresponding to the "pages" array.
 *
 * Ie. pte at addr+N*PAGE_SIZE shall point to pfn corresponding to pages[N]
 */
int pvmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = start;
	int err = 0;
	int nr = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset(imm, addr);
	// pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = pvmap_pud_range(pgd, addr, next, prot, pages, &nr);
		if (err)
			return err;
	} while (pgd++, addr = next, addr != end);

	return nr;
}

/*
 * modified from linux/mm/vmalloc.c
 * Set up page tables in kva (addr, end). The ptes shall have prot "prot", and
 * will have pfns corresponding to the "pages" array.
 *
 * Ie. pte at addr+N*PAGE_SIZE shall point to pfn corresponding to pages[N]
 */
int pvmap_page_range(unsigned long start, unsigned long end, pgprot_t prot, struct page **pages)
{
	int ret;
	ret = pvmap_page_range_noflush(start, end, prot, pages);
	flush_cache_vmap(start, end);
	return ret;
}

/*	If length is zero, allocate space and map whole file. (A)
 *	Else
 *		If previously mapped, remap input area. (B)
 *		Else allocate space and map input area. (C)
 *	Check if inode is fully mapped before calling this function
 *	TODO:zsa If we have to update mapping:
 *		1. Change the mapping state from fully mapped to partial mapped,
 *		2. Call this function to partially map the revised area,
 *		3. If all blocks of this file is mapped, change the state back to fully mapped.
 *	TODO:zsa nr_map_page
 *	TODO:bitmap
 */
int vmap_file_read_only(struct inode *inode, pgoff_t index, pgoff_t length)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct page **pages;
	uint8_t blk_type = fi->i_blk_type;
	size_t size = i_size_read(inode);
	unsigned long page_buf_sz;
	int ret = 0;
	bool full = false;
	uint64_t nr_pages;
	uint64_t offset = 0;
	void* start;
	void* end;
	
	if (size==0) return -1;
	// if ( index>(size>>HMFS_BLOCK_SIZE_BITS(blk_type)) || index+length>(size>>HMFS_BLOCK_SIZE_BITS(blk_type)) ) {
	// 	hmfs_dbg("Out of range index:%lu end:%lu size:%lu\n", index, index+length-1,size>>HMFS_BLOCK_SIZE_BITS(blk_type));
	// 	return -1;
	// }

	if (imm==NULL) imm = (struct mm_struct *)sbi->init_mm_addr;
	
	if (length==0) full = true;

	if (full) hmfs_dbg("[Before vmap][A] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);
	else 
		if (fi->rw_addr) hmfs_dbg("[Before vmap][B] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);
		else hmfs_dbg("[Before vmap][C] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);

	// Number of data blocks to be mapped (file size in block)
	nr_pages = (size + HMFS_BLOCK_SIZE[blk_type] - 1) >> HMFS_BLOCK_SIZE_BITS(blk_type);

	// Convert from data blocks(4K,8K,...) in NVM to pages in DRAM(4K) (file size in page)
	fi->nr_map_page = nr_pages << (HMFS_BLOCK_SIZE_BITS(blk_type) - PAGE_SHIFT);
	if (full) length = fi->nr_map_page;

	// Allocate virtual page buffer to contain the page addresses in kernel space according to file size (AC)
	// Always use vmalloc
	if ( !is_partially_mapped_inode(inode) ) {
		page_buf_sz = fi->nr_map_page * sizeof(struct page *);
		pages = vmalloc(page_buf_sz);
		if (!full) get_empty_page_struct(inode, pages, fi->nr_map_page);
	}
	// Allocate virtual page buffer to contain the page addresses in kernel space according to mapping size (B)
	else {
		page_buf_sz = length * sizeof(struct page *);
		pages = vmalloc(page_buf_sz);
		offset = index;
	}
	if (!pages) goto out;

	// Map the data pages of inode (ABC)
	// hmfs_dbg("[DP]page:%llx index:%lld count:%lld pageoff:%lld\n",pages,index,length,offset);
	ret = get_file_page_struct(inode, pages, index, length, offset);

	/* Show **pages */ 
	// hmfs_dbg("[Pages]\n");
	// for (i=0;i<length;++i)	hmfs_dbg("%llx\n",pages[i]);

	if (ret && ret != -ENODATA)
		goto free_pages;	

	// PAGE_KERNEL_RO for read only access (AC)
	if ( !is_partially_mapped_inode(inode) ) {
	hmfs_dbg("nrp %llu\n",fi->nr_map_page);
		fi->rw_addr = vm_map_ram(pages, fi->nr_map_page, 0, PAGE_KERNEL_RO);
		if (!fi->rw_addr)
			goto free_pages;
	}
	else {
		start = (void*)fi->rw_addr + index * HMFS_BLOCK_SIZE[blk_type];
		end = (void*)fi->rw_addr + (index+length) * HMFS_BLOCK_SIZE[blk_type];
		ret = pvmap_page_range((unsigned long)start, (unsigned long)end, PAGE_KERNEL_RO, pages);
		hmfs_dbg("[vmaping][B] remapped %d pages\n",ret);
	}

	if (full) {
		set_inode_flag(fi,FI_MAPPED_FULL);
		hmfs_dbg("[After vmap][A] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);
	}
	else if ( !is_partially_mapped_inode(inode) ) {
		set_inode_flag(fi,FI_MAPPED_PARTIAL);
		hmfs_dbg("[After vmap][C] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);
	}
	else {
		hmfs_dbg("[After vmap][B] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);
	}
	return 0;

free_pages:
	vfree(pages);

out:
	fi->rw_addr = NULL;
	fi->block_bitmap = NULL;
	fi->bitmap_size = 0;
	fi->nr_map_page = 0;
	return ERR_WARP_READ_PRE;
}

int vmap_file_read_only_byte(struct inode *inode, loff_t ppos, size_t len) {
	struct hmfs_inode_info *fi = HMFS_I(inode);
	uint8_t blk_type = fi->i_blk_type;
	pgoff_t sizep = (i_size_read(inode)+HMFS_BLOCK_SIZE[blk_type]-1) >> HMFS_BLOCK_SIZE_BITS(blk_type);
	pgoff_t pgstart = ppos >> HMFS_BLOCK_SIZE_BITS(blk_type);
	pgoff_t pgend = (ppos+len-1) >> HMFS_BLOCK_SIZE_BITS(blk_type);
	pgoff_t pglength = 0;
	if (pgstart>=sizep) return 2;
	if (pgend>sizep) pgend=sizep;
	pglength = pgend - pgstart+1;

	// hmfs_dbg("[DP] ppos:%lu, len:%lu\n", ppos, ppos+len);
	// hmfs_dbg("[DP] sizep:%lu pgstart:%lu, pgend:%lu, pglength:%lu\n", sizep, pgstart, pgend, pglength);
	return vmap_file_read_only(inode,pgstart,pglength);
}


int vmap_file_read_only_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	loff_t pos = (loff_t)ni->index;
	struct inode *ino = hmfs_iget(sbi->sb, ni->ino);
	loff_t isize;
	struct hmfs_inode_info *fi = HMFS_I(ino);
	unsigned int count = 0;
	unsigned char seg_type = fi->i_blk_type;
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);

	struct hmfs_summary *summary = NULL;
	summary = get_summary_by_addr(sbi, ni->blk_addr);
	if (get_summary_type(summary) == SUM_TYPE_DN) count = ADDRS_PER_BLOCK;
	else if (get_summary_type(summary) == SUM_TYPE_INODE) count = NORMAL_ADDRS_PER_INODE;

	isize = i_size_read(ino);
	isize = (( isize + ((1<<block_size_bits)-1) )>> block_size_bits);
	if (isize - pos < count) count = isize - pos;
	hmfs_dbg("vmap count:%u pos:%llu isize:%llu",count,pos,isize);
	return vmap_file_read_only(ino,(unsigned long)ni->index,count);
}
/*
int vmap_file_read_only_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct inode *ino = hmfs_iget(sbi->sb, ni->ino);
	return vmap_file_read_only(ino,(unsigned long)ni->index,ADDRS_PER_BLOCK);
}*/

// TODO:zsa specific unmap points and timing
int unmap_file_read_only(struct inode *inode){
	struct hmfs_inode_info *fi = HMFS_I(inode);
	// hmfs_dbg("[Before unmap] Addr:%llx PageNumber:%llu\n", fi->rw_addr, fi->nr_map_page);
	if (fi->rw_addr!=NULL){
		vm_unmap_ram(fi->rw_addr, fi->nr_map_page);
		fi->rw_addr = NULL;
		fi->nr_map_page = 0;
	}
	clear_inode_flag(fi,FI_MAPPED_PARTIAL);
	clear_inode_flag(fi,FI_MAPPED_FULL);
	// hmfs_dbg("[After unmap] Addr:%llx PageNumber:%llu\n", fi->rw_addr, fi->nr_map_page);
	return 0;
}

int unmap_file_read_only_node_info(struct hmfs_sb_info *sbi, struct node_info *ni){
	loff_t pos = (loff_t)ni->index;
	struct inode *ino = hmfs_iget(sbi->sb, ni->ino);
	loff_t isize;
	struct hmfs_inode_info *fi = HMFS_I(ino);
	unsigned int count = ADDRS_PER_BLOCK;
	unsigned char seg_type = fi->i_blk_type;
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	isize = i_size_read(ino);
	isize = (( isize + ((1<<block_size_bits)-1) )>> block_size_bits);
	// if (isize - pos < count) count = isize - pos;
	// FIXME: If the node is the last node of a file, just return.
	// It should be unmapped properly!
	// if (isize - pos < count) return 0;
	hmfs_dbg("unmap Addr:%p count:%u pos:%llu isize:%llu",fi->rw_addr,count,pos,isize);
	pos = pos << block_size_bits;
	// hmfs_dbg("[Before unmap] Addr:%p PageNumber:%llu\n", fi->rw_addr, fi->nr_map_page);
	// hmfs_dbg("pos:%lld, add:%d\n",pos,ADDRS_PER_BLOCK);
	vm_unmap_ram(fi->rw_addr + pos, count);
	// hmfs_dbg("[After unmap] Addr:%p PageNumber:%llu\n", fi->rw_addr, fi->nr_map_page);
	return 0;
}
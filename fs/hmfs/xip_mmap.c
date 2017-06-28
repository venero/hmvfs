#include <linux/mm.h>
#include <asm/pgtable.h>
#include <linux/fs.h>

#include "hmfs_fs.h"
#include "hmfs.h"
#include "xip_mmap.h"

static struct kmem_cache *xip_mmap_vma_slab;
static struct kmem_cache *xip_mmap_page_slab;

int create_xip_mmap_struct_cache(void)
{
	xip_mmap_vma_slab = hmfs_kmem_cache_create("hmfs_xip_mmap_vma_slab",
        sizeof(struct hmfs_xip_mmap_vma), NULL);
	if (!xip_mmap_vma_slab)
		return -ENOMEM;

    xip_mmap_page_slab = hmfs_kmem_cache_create("hmfs_xip_mmap_page_slab",
        sizeof(struct hmfs_xip_mmap_page), NULL);
    
    if (!xip_mmap_page_slab) 
        return -ENOMEM;
    
	return 0;
}

void destroy_xip_mmap_struct_cache(void)
{
	kmem_cache_destroy(xip_mmap_vma_slab);
    kmem_cache_destroy(xip_mmap_page_slab);
}

struct hmfs_xip_mmap_vma* find_vma_entry(struct hmfs_sb_info *sbi,
                                         struct vm_area_struct* vma) 
{
    struct hmfs_xip_mmap_vma *entry;
    struct list_head *this, *head;
    head = &sbi->mmap_block_list;
    // hmfs_dbg("[XIP_MMAP] : search for vma(0x%lx)\n", vma);
    list_for_each(this, head) {
        entry = list_entry(this, struct hmfs_xip_mmap_vma, vma_list);
        // hmfs_dbg("[XIP_MMAP] : searched : vma = (0x%lx)\n", entry->vma);
        if (entry->vma == vma) return entry;
    }
    return NULL;
}

static int add_vma_page(struct hmfs_sb_info *sbi, struct vm_area_struct* vma, 
                         unsigned long pgoff) 
{
    struct hmfs_xip_mmap_vma* vma_entry = find_vma_entry(sbi, vma);
    struct hmfs_xip_mmap_page* page_entry;

    if (!vma_entry) {
        vma_entry = kmem_cache_alloc(xip_mmap_vma_slab, GFP_ATOMIC);
        if (!vma_entry) {
            return -ENOMEM;
        }

        vma_entry->vma = vma;
        INIT_LIST_HEAD(&vma_entry->vma_list);
        INIT_LIST_HEAD(&vma_entry->pages);

        lock_mmap(sbi);
        list_add_tail(&vma_entry->vma_list, &sbi->mmap_block_list);
        unlock_mmap(sbi);
    }
    hmfs_bug_on(sbi,!vma_entry);

    page_entry = kmem_cache_alloc(xip_mmap_page_slab, GFP_ATOMIC);
    if (!page_entry) {
        return -ENOMEM;
    }
    page_entry->pgoff = pgoff;
    INIT_LIST_HEAD(&page_entry->page_list);

    // hmfs_dbg("[XIP_MMAP] : int add_vma_page() : vma_entry(0x%lx) page_entry(0x%lx)\n", vma_entry, page_entry);
    lock_mmap(sbi);
    list_add_tail(&page_entry->page_list, &vma_entry->pages);
    unlock_mmap(sbi);

    return 0;
}

static void remove_vma_pages(struct hmfs_xip_mmap_vma* hxm_vma) 
{
    struct list_head *this, *next, *head;
    struct hmfs_xip_mmap_page *entry;

    head = &hxm_vma->pages;
    list_for_each_safe(this, next, head) {
        entry = list_entry(this, struct hmfs_xip_mmap_page, page_list);
        hmfs_dbg("[XIP_MMAP] : remove mmap vma : (vma = 0x%lx, pgoff = 0x%lx)\n", hxm_vma->vma, entry->pgoff);
        list_del(&entry->page_list);
        kmem_cache_free(xip_mmap_page_slab, entry);
    }
}

int hmfs_get_xip_mem(struct hmfs_sb_info *sbi, struct inode* inode, pgoff_t index, unsigned long *pfn) 
{
    void *data_block;
	block_t data_block_addr;

    data_block = alloc_new_data_block(sbi, inode, index);
    if (IS_ERR(data_block))
        return PTR_ERR(data_block);
        
	data_block_addr = L_ADDR(sbi, data_block);
	*pfn = (sbi->phys_addr + data_block_addr) >> PAGE_SHIFT;

	return 0;
}

static int __hmfs_xip_file_fault(struct vm_area_struct *vma, struct vm_fault* vmf)
{
    struct address_space *mapping = vma->vm_file->f_mapping;
    struct inode *inode = mapping->host;
    struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
    pgoff_t size;
    unsigned long xip_pfn;
    int err;
    // hmfs_dbg("[XIP_MMAP] : mapping = %lx, inode = %lx, sbi = %lx\n", mapping, inode, sbi);
    size = (i_size_read(inode) + PAGE_SHIFT - 1) >> PAGE_SHIFT;
    if (vmf->pgoff >= size) {
        return VM_FAULT_SIGBUS;
    }

    err = hmfs_get_xip_mem(sbi, inode, vmf->pgoff, &xip_pfn);
    if (unlikely(err)) {
        hmfs_dbg("[XIP_MMAP] : fail to get xip mem, vm_start(0x%lx), vm_end(0x%lx), pgoff(0x%lx)\n",
            vma->vm_start, vma->vm_end, vmf->pgoff);
        return VM_FAULT_SIGBUS;
    }
    // hmfs_dbg("[XIP_MMAP] : vaddr = %lx, xip_pfn = %lu\n", vmf->virtual_address, xip_pfn);

    if (vma->vm_flags & VM_SHARED) {
        add_vma_page(sbi, vma, vmf->pgoff);
    }

    err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, xip_pfn);

    if (err == -ENOMEM) {
        return VM_FAULT_SIGBUS;
    }

    return VM_FAULT_NOPAGE;
}

static int hmfs_xip_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf) 
{
    int ret = 0;

    rcu_read_lock();
    ret = __hmfs_xip_file_fault(vma, vmf);
    rcu_read_unlock();

    return ret;
}

static void hmfs_xip_mmap_close(struct vm_area_struct* vma) 
{
    struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
    struct list_head *this, *next, *head;
    struct hmfs_xip_mmap_vma* entry;

    if (!(vma->vm_flags & VM_SHARED)) return;

    head = &sbi->mmap_block_list;
	lock_mmap(sbi);
	list_for_each_safe(this, next, head) {
		entry = list_entry(this, struct hmfs_xip_mmap_vma, vma_list);
		if (entry->vma == vma) {
			hmfs_dbg("[XIP_MMAP] : remove mmap vma : (vma = 0x%lx)\n", (unsigned long)vma);
            remove_vma_pages(entry);
			list_del(&entry->vma_list);
			kmem_cache_free(xip_mmap_vma_slab, entry);
		}
	}
	unlock_mmap(sbi);
}

static const struct vm_operations_struct hmfs_xip_vm_ops = {
    .fault = hmfs_xip_file_fault,
    .close = hmfs_xip_mmap_close
};

int hmfs_xip_file_mmap(struct file *file, struct vm_area_struct *vma) 
{
    file_accessed(file);
    vma->vm_flags |= VM_MIXEDMAP;
    vma->vm_ops = &hmfs_xip_vm_ops;
    hmfs_dbg("[XIP_MMAP] : vma_start(0x%lx), vma_end(0x%lx), size(%d), inode(%lu)",
        vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) >> PAGE_SHIFT, file->f_path.dentry->d_inode->i_ino);
    hmfs_dbg("[XIP_MMAP] : vm_shared? = %d\n", vma->vm_flags & VM_SHARED);
    return 0;
}


int migrate_mmaped_pages(struct hmfs_sb_info *sbi) 
{
    struct list_head *this_vma, *this_page, *head;
    struct hmfs_xip_mmap_vma *vma_entry;
    struct hmfs_xip_mmap_page *page_entry;
    struct db_info di;
    int err;
    __le64 *old_ptr_dn;
    struct hmfs_node *hn;
    hmfs_dbg("[XIP_MMAP] : start migrate mmapped pages!\n");

    head = &sbi->mmap_block_list;
    list_for_each(this_vma, head) {
        vma_entry = list_entry(this_vma, struct hmfs_xip_mmap_vma, vma_list);
        di.inode = vma_entry->vma->vm_file->f_mapping->host;
        list_for_each(this_page, &vma_entry->pages) {
            page_entry = list_entry(this_page, struct hmfs_xip_mmap_page, page_list);
            err = get_data_block_info(&di, page_entry->pgoff, LOOKUP);
            if (err)
                return ERR_PTR(err);
            hn = di.node_block;
            old_ptr_dn = di.local ? &hn->i.i_addr[di.ofs_in_node] : &hn->dn.addr[di.ofs_in_node];

            hmfs_dbg("[XIP_MMAP] : %luth page in file(inode = %lu) : old_addr(0x%lx), old_ptr(0x%lx)\n",
                page_entry->pgoff, di.inode, *old_ptr_dn, old_ptr_dn);
            page_entry->old_ptr_dn = old_ptr_dn;
        }
    }
    return 0;
}

int after_migrate_mmaped_pages(struct hmfs_sb_info *sbi) 
{
    struct list_head *this_vma, *next_vma, *this_page, *next_page, *head;
    struct hmfs_xip_mmap_vma *vma_entry;
    struct hmfs_xip_mmap_page *page_entry;
    struct db_info di;
    int err;
    block_t new_addr, old_addr;
    __le64 *new_ptr_dn;
    struct hmfs_node *hn;
    unsigned char seg_type;
    struct hmfs_summary *old_summary, *new_summary;

    head = &sbi->mmap_block_list;
    list_for_each_safe(this_vma, next_vma, head) {
        vma_entry = list_entry(this_vma, struct hmfs_xip_mmap_vma, vma_list);
        di.inode = vma_entry->vma->vm_file->f_mapping->host;
        list_for_each_safe(this_page, next_page, &vma_entry->pages) {
            page_entry = list_entry(this_page, struct hmfs_xip_mmap_page, page_list);
            err = get_data_block_info(&di, page_entry->pgoff, ALLOC);
            if (err)
                return ERR_PTR(err);
            hn = di.node_block;
            seg_type = HMFS_I(di.inode)->i_blk_type;
            hmfs_bug_on(sbi, HMFS_BLOCK_SIZE[seg_type] != 1 << PAGE_SHIFT);

            old_addr = *page_entry->old_ptr_dn;
            new_addr = alloc_free_data_block(sbi, seg_type);
            hmfs_memcpy(ADDR(sbi, old_addr), ADDR(sbi, new_addr), PAGE_SIZE);
            new_ptr_dn = di.local ? &hn->i.i_addr[di.ofs_in_node] : &hn->dn.addr[di.ofs_in_node];

            hmfs_dbg("[XIP_MMAP] : %luth page in file(inode = %lu) : new_addr(0x%lx), new_ptr(0x%lx)\n",
                page_entry->pgoff, di.inode, new_addr, new_ptr_dn);

            // swap data block pointers in direct nodes
            *new_ptr_dn = old_addr;
            *page_entry->old_ptr_dn = new_addr;

            // update summary
            old_summary = get_summary_by_addr(sbi, old_addr);
            new_summary = get_summary_by_addr(sbi, new_addr);
            hmfs_memcpy(new_summary, old_summary, sizeof(struct hmfs_summary));
            make_summary_entry(old_summary, di.nid, CM_I(sbi)->new_version, di.ofs_in_node, SUM_TYPE_DATA, 0);

            list_del(&page_entry->page_list);
            kmem_cache_free(xip_mmap_page_slab, page_entry);
        }
    }
    hmfs_dbg("[XIP_MMAP] : after migrate mmapped pages!\n");
    return 0;
}
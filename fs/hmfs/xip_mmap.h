#ifndef HMFS_XIP_MMAP_H
#define HMFS_XIP_MMAP_H

#include <linux/list.h>

#define HMFS_XIP_MMAP

struct hmfs_xip_mmap_vma {
    struct vm_area_struct* vma;
    struct list_head vma_list;
    struct list_head pages;
};

struct hmfs_xip_mmap_page {
    unsigned long pgoff;
    __le64 *old_ptr_dn;
    struct list_head page_list;
};

int create_xip_mmap_struct_cache(void);
void destroy_xip_mmap_struct_cache(void);
int hmfs_xip_file_mmap(struct file *file, struct vm_area_struct *vma);
int migrate_mmaped_pages(struct hmfs_sb_info *sbi);
int after_migrate_mmaped_pages(struct hmfs_sb_info *sbi);

#endif
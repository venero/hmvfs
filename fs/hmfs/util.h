#ifdef CONFIG_HMFS_FAST_READ
#ifndef HMFS_UTIL_H
#define HMFS_UTIL_H

#include <linux/mm.h>

/* mm/memory.c */
static int (*__hmfs_pud_alloc) (struct mm_struct *mm, pgd_t *pgd,
				unsigned long address);
static int (*__hmfs_pmd_alloc) (struct mm_struct *mm, pud_t *pud,
				unsigned long address);
static int (*__hmfs_pte_alloc_kernel) (pmd_t *pmd, unsigned long address);

static struct mm_struct *hmfs_init_mm;

/* mm/vmalloc.c */
static struct vm_struct * (*hmfs_remove_vm_area) (const void *addr);

/* mm/vmalloc.c */
static struct vm_struct * (*hmfs_find_vm_area) (const void *addr);

/* mm/vmalloc.c */
static struct vm_struct * (*hmfs_get_vm_area) (unsigned long size, 
				unsigned long flags);


#define hmfs_pte_alloc_kernel(pmd, address)	1//\
//	((unlikely(pmd_none(*(pmd))) && __hmfs_pte_alloc_kernel(pmd, address))? \
//		NULL: pte_offset_kernel(pmd, address))

#if defined(CONFIG_MMU) && !defined(__ARCH_HAS_4LEVEL_HACK)
static pud_t *hmfs_pud_alloc(struct mm_struct *mm, void *pgd,
				unsigned long address)
{
/*	return (unlikely(pgd_none(*pgd)) && __hmfs_pud_alloc(mm, pgd, address))?
		NULL: pud_offset(pgd, address);
*/
		__hmfs_pud_alloc(NULL,pgd,address);
}

static inline pmd_t *hmfs_pmd_alloc(struct mm_struct *mm, pud_t *pud,
				unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __hmfs_pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#else
#define hmfs_pmd_alloc(mm, pud, address) 1/*\
	((unlikely(pgd_none(*(pud))) && __hmfs_pmd_alloc(mm, pud, address))? \
 		NULL: pmd_offset(pud, address))*/

static inline pud_t *hmfs_pud_alloc(struct mm_struct *mm, pgd_t *pgd,
				unsigned long address)
{/*
	return (unlikely(pgd_none(*pgd)) && __hmfs_pud_alloc(mm, pgd, address))?
		NULL: pud_offset(pgd, address);
*/}
#endif

#endif
#endif

#ifndef HMFS_XATTR_H
#define HMFS_XATTR_H

#include <linux/init.h>
#include <linux/xattr.h>

/* Name Indexes */
#define HMFS_SYSTEM_ADVISE_PREFIX	"system.advise"
#define HMFS_XATTR_INDEX_USER				1
#define HMFS_XATTR_INDEX_POSIX_ACL_ACCESS	2
#define HMFS_XATTR_INDEX_POSIX_ACL_DEFAULT	3
#define HMFS_XATTR_INDEX_TRUSTED			4
#define HMFS_XATTR_INDEX_SECURITY			5
#define HMFS_XATTR_INDEX_ADVISE				6
#define HMFS_XATTR_INDEX_END		10

#define HMFS_XATTR_VALUE_LEN		255

#define HMFS_XATTR_BLOCK_SIZE		HMFS_PAGE_SIZE

#define XATTR_HDR(ptr)		((struct hmfs_xattr_header *)(ptr))
#define XATTR_ENTRY(ptr)	((struct hmfs_xattr_entry *)(ptr))
#define XATTR_FIRST_ENTRY(ptr)	(XATTR_ENTRY(XATTR_HDR(ptr) + 1))

#define XATTR_RAW_SIZE			sizeof(struct hmfs_xattr_entry)

#define XATTR_ENTRY_SIZE(entry)	(sizeof(struct hmfs_xattr_entry) + \
				entry->e_name_len + entry->e_value_len)

#define XATTR_NEXT_ENTRY(entry)		\
		XATTR_ENTRY((char*)entry + XATTR_ENTRY_SIZE(entry))

#define IS_XATTR_LAST_ENTRY(entry)	(entry->e_name_index !=\
				HMFS_XATTR_INDEX_END)

#define list_for_each_xattr(entry, addr)	\
		for (entry = XATTR_FIRST_ENTRY(addr);\
				!IS_XATTR_LAST_ENTRY(entry);\
				entry = XATTR_NEXT_ENTRY(entry))


struct hmfs_xattr_entry {
	__u8 e_name_index;
	__u8 e_name_len;		/* Name len */
	__u8 e_value_len;		/* Value len */
	char e_name[0];			/* Name and Value */
} __attribute__ ((packed));

struct hmfs_xattr_header {
	__le16 h_magic;
} __attribute__ ((packed));

#ifdef CONFIG_HMFS_XATTR
extern const struct xattr_handler hmfs_acl_access_handler;
extern const struct xattr_handler hmfs_acl_default_handler;
extern const struct xattr_handler *hmfs_xattr_handlers[];
#else
#define hmfs_xattr_handlers NULL
#endif

#endif

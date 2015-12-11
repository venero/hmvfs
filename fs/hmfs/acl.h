#ifndef HMFS_ACL_H
#define HMFS_ACL_H

#include <linux/posix_acl_xattr.h>

#define HMFS_ACL_VERSION	0x0001

struct hmfs_acl_entry {
	__le16 e_tag;
	__le16 e_perm;
	__le32 e_id;
} __attribute__ ((packed));

struct hmfs_acl_entry_short {
	__le16 e_tag;
	__le16 e_perm;
} __attribute__ ((packed));

struct hmfs_acl_header {
	__le16 a_magic;
	__le32 a_version;
	__le16 acl_access_ofs;
	__le16 acl_default_ofs;
	__le16 acl_end;
} __attribute__ ((packed));

#define ACL_HEADER(ptr)			((struct hmfs_acl_header *)(ptr))
#define ACL_ENTRY(ptr)			((struct hmfs_acl_entry *)(ptr))
#define ACL_SHORT_ENTRY_SIZE	sizeof(struct hmfs_acl_entry_short)
#define ACL_ENTRY_SIZE			sizeof(struct hmfs_acl_entry)
#define ACL_HEADER_SIZE			sizeof(struct hmfs_acl_header)
#endif

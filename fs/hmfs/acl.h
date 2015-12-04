#ifndef HMFS_ACL_H
#define HMFS_ACL_H

#include <linux/posix_acl_xattr.h>

#define HMFS_ACL_VERSION	0x0001
#define HMFS_X_BLOCK_TAG_ACL		((unsigned long)\
				(&(((struct hmfs_inode *)NULL)->i_acl_addr)))

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

#endif

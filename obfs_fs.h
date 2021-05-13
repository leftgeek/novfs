#ifndef _OBFS_DEF_H
#define _OBFS_DEF_H

#include <linux/types.h>
#include <linux/fs.h>

#define OBFS_MOUNT_PROTECT 0x000001  /*use memory protection*/
#define OBFS_MOUNT_XATTR_USER 0x000002 /*extended user attributes*/
#define OBFS_MOUNT_POSIX_ACL 0x000004  /*POSIX ACL*/
#define OBFS_MOUNT_XIP 0x000008  /*execute in place*/
#define OBFS_MOUNT_ERRORS_CONT 0x000010  /*continue on errors*/
#define OBFS_MOUNT_ERRORS_RO 0x000020  /*remount fs ro on errors*/
#define OBFS_MOUNT_ERRORS_PANIC 0x000040 /*panic on errors*/

//journal mode only affect obfs_sync_write() txn, other txns are still data=ordered
#define OBFS_MOUNT_STRONG_XMODE		0x000080  /* journal mode, 1 for data=journal,0 for data=ordered */

#define OBFS_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL |\
             FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL | \
             FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_JOURNAL_DATA_FL |\
             FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define OBFS_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define OBFS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)

#define OBFS_INODE_SIZE 128
#define OBFS_INODE_BITS 7
#define OBFS_SUPER_MAGIC 0x2015
#define OBFS_NAME_LEN  63 //FIXME: may be longer

struct obfs_dentry {
  __le64 d_next;
  //__le64 d_prev;
  __le64 d_parent;
  char d_name[OBFS_NAME_LEN + 1];
};

//inode's ino is its object number
struct obfs_inode {
	__le32	i_sum;          /* checksum of this inode */
	__le16	i_links_count;	/* Links count */
	__le16	padding;	/* padding */
	__le32	i_generation;	/* File version (for NFS) */
	__le32	i_flags;	/* Inode flags */

	union {
		struct {
			__le64 head; /* first entry objno in this directory */
			__le64 tail; /* last entry objno in this directory */
		} dir;
		struct {
			__le32 rdev; /* major/minor # */
		} dev;   /* device inode */
	} i_type;

	struct obfs_dentry i_d;
};
/*
 * Structure of the super block in OBFS
 */
struct obfs_super_block {
	__le32	s_sum;          /* checksum of this sb, including padding */
	__le64	s_size;         /* total size of fs in bytes */
	__le32	s_blocksize;    /* blocksize in bytes */
	__le32	s_inodes_count;	/* total inodes count (used or free) */
	//__le32	s_free_inodes_count;/* free inodes count */
	//__le32	s_free_inode_hint;  /* start hint for locating free inodes */
	__le32	s_blocks_count;	/* total data blocks count (used or free) */
	//__le32	s_free_blocks_count;/* free data blocks count */
	//__le32	s_free_blocknr_hint;/* free data blocks count */
	//__le64	s_bitmap_start; /* data block in-use bitmap location */
	//__le32	s_bitmap_blocks;/* size of bitmap in number of blocks */
  __le64  s_root_ino; //root inode number / inode object number
	__le32	s_mtime;	/* Mount time */
	__le32	s_wtime;	/* Write time */
	__le16	s_magic;	/* Magic signature */
	char	s_volume_name[16]; /* volume name */
};

//no duplicate of super block

//#define OBFS_NAME_LEN (OBFS_INODE_SIZE - offsetof(struct obfs_inode, i_d.d_name) - 1)

#define OBFS_SB_SIZE 128

#endif

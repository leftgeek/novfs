#ifndef _OBFS_H
#define _OBFS_H

//#include <linux/module.h>
#include <linux/crc32.h>
#include <linux/mutex.h>
#include <linux/obj.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/syscalls.h>
#include <linux/obj.h>
#include "obfs_fs.h"
#include "../internal.h"

/*
 * debug code
 * */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#define obfs_dbg(s, args...) pr_debug(s, ## args)
#define obfs_warn(s, args...) pr_warning(s, ## args)
#define obfs_info(s, args...) pr_info(s, ## args)

#define obfs_set_bit			ext2_set_bit
#define obfs_clear_bit			ext2_clear_bit
#define obfs_find_next_zero_bit		ext2_find_next_zero_bit

#define clear_opt(o, opt) (o &= ~OBFS_MOUNT_ ## opt)
#define set_opt(o, opt) (o |= OBFS_MOUNT_ ## opt)
#define test_opt(sbi, opt) (sbi->s_mount_opt & OBFS_MOUNT_ ## opt)
//
//runtime dentry and inode structure
struct obfs_dentry_info{
  struct {
    struct obj_stat stat; //basic attributes
    struct obfs_inode xattr;  //Extended attributes
  }d_inode;
  //struct obfs_inode d_inode;  //contain the obfs_inode structure, not the pointer
  //inode-info
  struct mutex i_mutex;//protect i_ino and d_inode
  //spinlock_t i_lock;  //FIXME: protect i_blocks, i_bytes, maybe i_size
  struct mutex i_link_mutex;//protect i_links_count
  unsigned long i_ino;
  unsigned long i_state;
  struct hlist_node i_hash; //inode lookup hash list(ino),protected by i_mutex?

  //dentry-info
  unsigned int d_flags;
  seqcount_t d_seq; //per dentry seqlock
  struct hlist_bl_node d_hash; //lookup hash list(dname)
  struct obfs_dentry_info *d_parent;
  struct obfs_dentry_info *d_prev;
  struct obfs_dentry_info *d_next;
  struct qstr d_name;//d_name.name = oi.i_d.d_name;

  //2 hash
  //i_ino hash and d_name hash
  struct lockref d_lockref; //per-dentry lock and refcount

  struct list_head d_lru; //dentry lru list

  union {
    struct list_head d_child; //child of parent list_head
    struct rcu_head d_rcu;
  } d_u;
  struct list_head d_subdirs; //our children
  //struct list_head d_alias; //FIXME: do we need inode alias list?
};

/*
 * OBFS super block data in memory
 * */
struct obfs_sb_info{
  struct obfs_super_block super;
  unsigned long start_objno;//start obj number which stores super_block and inode tables

  /*mount options*/
  //unsigned long bpi;
  //unsigned long num_inodes;
  unsigned char blocksize_bits;//inode table blocksize bits
  unsigned long blocksize;//inode table blocksize
  unsigned long initsize;
  unsigned long s_mount_opt;
  kuid_t uid; /*mount uid for root directory*/
  kgid_t gid; /*mount gid for root directory*/
  umode_t mode; /*mount mode for root directory*/
  atomic_t next_generation;
  struct mutex s_lock;

  struct list_head s_dentry_lru;//unused dentry lru
  int s_nr_dentry_unused;//# of dentry on lru
  char *mount_point;//mount point:/mnt/obfs
  struct obfs_dentry_info *s_root;//root dentry
  //unsigned long s_flags;//FIXME: when to use this?
};
extern struct obfs_sb_info *obfs_sbi;
//0 for data=ordered, 1 for data=journal
static inline int obfs_xmode(void){
  return obfs_sbi->s_mount_opt & OBFS_MOUNT_STRONG_XMODE? OBJMS_XSTRONG: OBJMS_XWEAK;
}
//balloc.c
extern void obfs_init_bitmap(struct obfs_sb_info *sbi);
/*super.c*/
static inline struct obfs_super_block *obfs_get_super(struct obfs_sb_info *sbi){
  return &sbi->super;
} 
/*
static inline void *obfs_get_bitmap(struct obfs_sb_info *sbi){
  struct obfs_super_block *ssb = obfs_get_super(sbi);
  return (void *)ssb + le64_to_cpu(ssb->s_bitmap_start);
}*/

static inline struct obfs_inode *obfs_get_inode(struct obfs_dentry_info *dentry){
  return &(dentry->d_inode.xattr);
}

//read an inode from objms by it's offset(ino) in inode object
/*static inline const struct obfs_inode *obfs_get_inode(ino_t ino){
  //unsigned long iblknr = ino >> 12;//get the inode's block number: ino / 4k
  //int offset = ino & 0xfff;//get the inode's offset in block
  int blocksize_mask = obfs_sbi->blocksize - 1;
  int blocknr = ino >> obfs_sbi->blocksize_bits;
  const void *blkaddr = objms_block_address(obfs_sbi->start_objno, blocknr);
  if (blkaddr){
    return (const struct obfs_inode *)(blkaddr + (ino & blocksize_mask));
  } else {
    return NULL;
  }
}*/

static inline __le32 obfs_mask_flags(umode_t mode, __le32 flags){
  flags &= cpu_to_le32(OBFS_FL_INHERITED);
  if (S_ISDIR(mode)){
    return flags;
  } else if (S_ISREG(mode)){
    return flags & cpu_to_le32(OBFS_REG_FLMASK);
  } else {
    return flags & cpu_to_le32(OBFS_OTHER_FLMASK);
  }
}

static inline int obfs_calc_checksum(u8 *data, int n){
  u32 crc = 0;
  crc = crc32(~0, (__u8 *)data + sizeof(__le32), n - sizeof(__le32));
  if (*((__le32 *)data) == cpu_to_le32(crc)){
    return 0;
  } else {
    return 1;
  }
}

//get 1 xattr of obfs_inode
static inline int obfs_get_inode_xattr(ino_t ino, void *value,
    loff_t offset, size_t size){
  int ret;
  mm_segment_t fs = get_fs();
  set_fs(get_ds());
  ret = sys_objms_getxattr(0, ino, (char *)value, offset, size);
  set_fs(fs);
  return ret;
}
//set 1 xattr of obfs_inode
static inline int obfs_set_inode_xattr(unsigned long tid, ino_t ino, void *value,
    loff_t offset, size_t size){
  int ret;
  mm_segment_t fs = get_fs();
  set_fs(get_ds());
  ret = sys_objms_setxattr(tid, ino, (const char *)value, offset, size);
  set_fs(fs);
  return ret;
}
//lock before call this
static inline void obfs_sync_super(unsigned long tid, struct obfs_sb_info *sbi){
  u32 crc = 0;
  struct obfs_super_block *super = obfs_get_super(sbi);
  mm_segment_t fs = get_fs();
  super->s_wtime = cpu_to_le32(get_seconds());
  super->s_sum = 0;
  crc = crc32(~0, (__u8 *)super + sizeof(__le32), OBFS_SB_SIZE - sizeof(__le32));
  super->s_sum = cpu_to_le32(crc);
  //memcpy((void *)ssb + OBFS_SB_SIZE, (void *)ssb, OBFS_SB_SIZE);
  set_fs(get_ds());
  sys_objms_write(tid, sbi->start_objno,
      (const char *)super, sizeof(*super), 0);
  set_fs(fs);
}
//don't need inode->i_sum
/*static inline void obfs_sync_inode(struct obfs_inode *si){
  u32 crc = 0;
  si->i_sum = 0;
  crc = crc32(~0, (__u8 *)si + sizeof(__le32), OBFS_INODE_SIZE - sizeof(__le32));
  si->i_sum = cpu_to_le32(crc);
}*/

static inline struct dentry *obfs_convert_to_vfs_dentry(struct obfs_dentry_info *o_dentry){
  return (struct dentry *)o_dentry;
}
//convert a vfs dentry to obfs_dentry_info
static inline struct obfs_dentry_info *obfs_convert_to_obfs_dentry(struct dentry *v_dentry){
  return (struct obfs_dentry_info *)v_dentry;
}
//
//open.c
extern int obfs_finish_open(struct file *file, struct obfs_dentry_info *dentry,
    int *opened);
//namei.c
//extern struct file *obfs_do_filp_open(int dfd, struct filename *pathname,
//    const struct open_flags *op);
//inode.c
//extern const struct obfs_inode *obfs_get_inode(ino_t ino);
extern int obfs_get_inode_stat(ino_t ino, struct obj_stat *stat);
extern int obfs_get_xattrs(ino_t ino, struct obfs_inode *pi);
extern int obfs_update_xattrs(unsigned long tid, ino_t ino, struct obfs_inode *pi);
extern int obfs_update_inode_xattr(unsigned long tid, ino_t ino, struct obfs_inode *pi);
extern int obfs_update_dentry_xattr(unsigned long tid, ino_t ino, struct obfs_dentry *pd);
extern int obfs_user_path_at(int dfd, const char __user *name, unsigned flags,
    struct obfs_dentry_info **path);

extern void obfs_insert_ino_hash(struct obfs_dentry_info *dentry);
extern void obfs_remove_ino_hash(struct obfs_dentry_info *dentry);
extern struct obfs_dentry_info *obfs_find_dentry_by_ino(unsigned long ino);
//dcache.c
extern int __init obfs_init_dcache(void);
extern int __init obfs_init_ihashtable(void);
extern void obfs_destroy_dcache(void);
//dir.c
extern int obfs_add_link(unsigned long tid, struct obfs_dentry_info *dentry);
extern int obfs_remove_link(unsigned long tid, struct obfs_dentry_info *dentry);
#endif

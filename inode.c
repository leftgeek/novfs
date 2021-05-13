#include <linux/obj.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/bootmem.h>
#include <linux/obfs_def.h>
#include <linux/uidgid.h>
#include "obfs.h"
#include "namei.h"
#include "dcache.h"

#define OBFS_I_HASHBITS  obfs_i_hash_shift
#define OBFS_I_HASHMASK  obfs_i_hash_mask

static unsigned int obfs_i_hash_mask __read_mostly;
static unsigned int obfs_i_hash_shift __read_mostly;

struct hlist_head *obfs_ino_hashtable __read_mostly;
static __initdata unsigned long obfs_ihash_entries = 0;

//a simple spinlock to protect the list manipulations
//also protects i_state
DEFINE_SPINLOCK(obfs_ihash_lock);

//read an inode's basic attr(stat) from objms
int obfs_get_inode_stat(ino_t ino, struct obj_stat *stat){
  int ret;
  mm_segment_t fs = get_fs();//to use kernel version of objms_read_obj
  set_fs(get_ds());
  ret = sys_objms_obj_stat(ino, stat);
  set_fs(fs);
    //printk(KERN_ERR "#obfs_get_inode_stat: ret=%d\n", ret);
  return ret < 0 ? ret : 0;
}
//FIXME
//read an inode('s xattrs) from objms by it's offset(ino) in inode object
int obfs_get_xattrs(ino_t ino, struct obfs_inode *pi){
  int ret;
  mm_segment_t fs = get_fs();//to use kernel version of objms_read_obj
  set_fs(get_ds());
  ret = sys_objms_getxattr(0, ino, pi, 0, sizeof(struct obfs_inode));
  set_fs(fs);
  //printk(KERN_ERR "@obfs_get_xattrs: ret=%d\n", ret);
  return ret < 0 ? ret : 0;
}
//FIXME
//write an inode's xattrs(include inode's and dentry's) to objms
int obfs_update_xattrs(unsigned long tid, ino_t ino, struct obfs_inode *pi){
  int ret;
  mm_segment_t fs = get_fs();
  set_fs(get_ds());
  ret = sys_objms_setxattr(tid, ino, pi, 0, sizeof(struct obfs_inode));
  set_fs(fs);
  return ret < 0 ? ret : 0;
}

//xattr of the inode contains extra fields of an inode and its dentry
//update the xattr of the inode(i_mode, i_links_count...)
int obfs_update_inode_xattr(unsigned long tid, ino_t ino, struct obfs_inode *pi){
  int ret;
  mm_segment_t fs = get_fs();
  //FIXME
  set_fs(get_ds());
  ret = sys_objms_setxattr(tid, ino, (const char *)pi, 0, offsetof(struct obfs_inode, i_d));
  set_fs(fs);
  return ret < 0 ? ret : 0;
}
//FIXME
//just write an inode's dentry xattr to objms
int obfs_update_dentry_xattr(unsigned long tid, ino_t ino, struct obfs_dentry *pd){
  int ret;
  mm_segment_t fs = get_fs();
  //FIXME
  set_fs(get_ds());
  ret = sys_objms_setxattr(tid, ino, (const char *)pd, 
      offsetof(struct obfs_inode, i_d), sizeof(struct obfs_dentry));
  set_fs(fs);
  return ret < 0 ? ret : 0;
}


//ino hash table
//@ayu: FIXME
static inline unsigned long obfs_hash(unsigned long hashval){
  /*unsigned long tmp;
  tmp = (hashval * (unsigned long)obfs_sbi) ^ (GOLDEN_RATIO_PRIME + hashval)
    / L1_CACHE_BYTES;
  tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> OBFS_I_HASHBITS);
  return tmp & OBFS_I_HASHMASK;*/
  return hashval & OBFS_I_HASHMASK;
}

int __init obfs_init_ihashtable(void){
  int loop;

    obfs_ino_hashtable = alloc_large_system_hash(
        "obfs-ino-hash",
        sizeof(struct hlist_head),
        obfs_ihash_entries,
        14,
        0,//HASH_EARLY,
        &obfs_i_hash_shift,
        &obfs_i_hash_mask,
        0, 0);

  if (obfs_ino_hashtable == NULL){
    printk(KERN_ERR "@obfs: init_ino_hashtable: failed!\n");
    return -ENOMEM;
  }
  for (loop = 0; loop < (1U << obfs_i_hash_shift); loop++){
    INIT_HLIST_HEAD(&obfs_ino_hashtable[loop]);
  }
  return 0;
}

void obfs_insert_ino_hash(struct obfs_dentry_info *dentry){
  //__obfs_insert_ino_hash(dentry, dentry->i_ino);
  struct hlist_head *head = obfs_ino_hashtable + obfs_hash(dentry->i_ino);
  spin_lock(&obfs_ihash_lock);
  //spin_lock(&dentry->i_lock);
  hlist_add_head(&dentry->i_hash, head);
  //spin_unlock(&dentry->i_lock);
  spin_unlock(&obfs_ihash_lock);
}

static inline int obfs_ino_unhashed(struct obfs_dentry_info *dentry){
  return hlist_unhashed(&dentry->i_hash);
}

//remove an dentry from the hash
void obfs_remove_ino_hash(struct obfs_dentry_info *dentry){
  if (!obfs_ino_unhashed(dentry)){
    //printk(KERN_ERR "@obfs_remove_ino_hash: ino=%lu\n", dentry->i_ino);
    spin_lock(&obfs_ihash_lock);
    //spin_lock(&dentry->i_lock);
    hlist_del_init(&dentry->i_hash);
    //spin_unlock(&dentry->i_lock);
    spin_unlock(&obfs_ihash_lock);
  }
}

//@ayu: FIXME
struct obfs_dentry_info *obfs_find_dentry_by_ino(unsigned long ino){
  struct hlist_head *head = obfs_ino_hashtable + obfs_hash(ino);
  struct obfs_dentry_info *dentry = NULL;

  spin_lock(&obfs_ihash_lock);
  hlist_for_each_entry(dentry, head, i_hash){
    //printk(KERN_ERR "@obfs_find_dentry_by_ino: ino=%lu\n", dentry->i_ino);
    if (dentry->i_ino != ino){
      continue;
    }
    spin_unlock(&obfs_ihash_lock);
    return dentry;
  }
  spin_unlock(&obfs_ihash_lock);
  return NULL;
}
//get attr from dentry and fill it in stat
int obfs_getattr(struct obfs_dentry_info *dentry, struct kstat *stat){
  struct obj_stat *os = &(dentry->d_inode.stat);
  //if we have not read the inode stat from objms, read it
  if (!os->st_objno){
    obfs_get_inode_stat(dentry->i_ino, os);
  }
  stat->dev = 0;
  stat->ino = dentry->i_ino;
	stat->mode = dentry->d_inode.stat.st_mode;
	stat->nlink = dentry->d_inode.xattr.i_links_count;
	stat->uid = KUIDT_INIT(dentry->d_inode.stat.st_uid);//FIXME
	stat->gid = KGIDT_INIT(dentry->d_inode.stat.st_gid);
	stat->rdev = 0;
	stat->size = dentry->d_inode.stat.st_size;
	stat->atime.tv_sec = dentry->d_inode.stat.st_atime;
	stat->mtime.tv_sec = dentry->d_inode.stat.st_mtime;
	stat->ctime.tv_sec = dentry->d_inode.stat.st_ctime;
	stat->blksize = dentry->d_inode.stat.st_blksize;
	stat->blocks = dentry->d_inode.stat.st_blocks;

  return 0;
}

//@ayu: obfs_def
//FIXME: unfinished
int obfs_stat(const char __user *filename, struct kstat *stat){
  struct obfs_dentry_info *path;
  int error = -EINVAL;
  unsigned int lookup_flags = 0;

  lookup_flags |= LOOKUP_FOLLOW;
  
retry:
  error = obfs_user_path_at(AT_FDCWD, filename, lookup_flags, &path);
  if (error){
    goto out;
  }

  error = obfs_getattr(path, stat);
  obfs_path_put(0, path);
  //if (retry_estale(error, lookup_flags)){
  if (error == -ESTALE && !(lookup_flags & LOOKUP_REVAL)){
    lookup_flags |= LOOKUP_REVAL;
    goto retry;
  }
out:
  return error;
}
EXPORT_SYMBOL(obfs_stat);
//@ayu: obfs_def
/*unsigned long obfs_mmap_pgoff(struct file *file, unsigned long addr,
    unsigned long len, unsigned long prot,
    unsigned long flags, unsigned long pgoff){
  unsigned long ret;
  struct obfs_dentry_info *dentry = obfs_convert_to_obfs_dentry(file->f_path.dentry);
  ret = sys_objms_mmap(addr, len, prot, flags, dentry->i_ino, pgoff);
  return ret;
}
EXPORT_SYMBOL(obfs_mmap_pgoff);*/

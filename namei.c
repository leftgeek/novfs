#include <linux/fs.h>
#include <linux/ima.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/dcache.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/statfs.h>
#include <linux/obfs_def.h>
#include "obfs.h"
#include "namei.h"
#include "dcache.h"

#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

static inline unsigned int fold_hash(unsigned long hash)
{
	hash += hash >> (8*sizeof(int));
	return hash;
}

/*
 * Calculate the length and hash of the path component, and
 * return the length of the component;
 */
static inline unsigned long hash_name(const char *name, unsigned int *hashp)
{
	unsigned long a, b, adata, bdata, mask, hash, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	hash = a = 0;
	len = -sizeof(unsigned long);
	do {
		hash = (hash + a) * 9;
		len += sizeof(unsigned long);
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);

	mask = create_zero_mask(adata | bdata);

	hash += a & zero_bytemask(mask);
	*hashp = fold_hash(hash);

	return len + find_zero(mask);
}

#else
/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline unsigned long hash_name(const char *name, unsigned int *hashp)
{
	unsigned long hash = init_name_hash();
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	*hashp = end_name_hash(hash);
	return len;
}

#endif
//whether an inode is a symbol link file
static inline int obfs_is_link(struct obfs_dentry_info *dentry){
  return S_ISLNK(dentry->d_inode.stat.st_mode);
}

static inline int obfs_is_dir(struct obfs_dentry_info *dentry){
  return S_ISDIR(dentry->d_inode.stat.st_mode);
}

//called in mkdir and rename
static inline void obfs_inc_count(unsigned long tid, struct obfs_dentry_info *dentry){
  struct obfs_inode *oi = obfs_get_inode(dentry);
  oi->i_links_count++;
  obfs_set_inode_xattr(tid, dentry->i_ino, &(oi->i_links_count),
      offsetof(struct obfs_inode, i_links_count), sizeof(__le16));
}

static inline void obfs_dec_count(unsigned long tid, struct obfs_dentry_info *dentry){
  struct obfs_inode *oi = obfs_get_inode(dentry);
	if (oi->i_links_count){
    oi->i_links_count--;
    obfs_set_inode_xattr(tid, dentry->i_ino, &(oi->i_links_count),
        offsetof(struct obfs_inode, i_links_count), sizeof(__le16));
	}
}
//FIXME: unfinished
//dentry->i_mutex is locked by caller
static inline int obfs_add_nondir(unsigned long tid, struct obfs_dentry_info *dentry){
  int err = obfs_add_link(tid, dentry);
  if (likely(!err)){
    mutex_unlock(&dentry->i_mutex);
    //printk(KERN_ERR "@obfs_add_nondir obfs_d_instantiate start!\n");
    obfs_d_instantiate(dentry, dentry->i_ino);//dentry and its inode has already been connected,
    //so we only call this to add dentry to hlist
    return 0;
  }
  //printk(KERN_ERR "@obfs_add_nondir obfs_add_link failed!\n");
  obfs_dec_count(tid, dentry);
  mutex_unlock(&dentry->i_mutex);
  //obfs_iput(inode);//if connection failed, delete the inode
  return err;
}

//find a inode by its dname from objms and store it in dentry->d_inode
//FIXME: dentry->i_node's content will be erased!
static ino_t obfs_inode_by_name(struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry){
	struct obfs_inode *oi;
	ino_t ino;
	int namelen;

  oi = obfs_get_inode(dir);
	ino = le64_to_cpu(oi->i_type.dir.head);
  //use dentry->d_inode as buffer
  oi = obfs_get_inode(dentry);

  //printk(KERN_ERR "@obfs_inode_by_name: begin, dentry name=%s\n", dentry->d_name.name);
	//mutex_lock(&vi->i_link_mutex);
  struct obfs_dentry_info *mem_de;
	while (ino) {
    //printk(KERN_ERR "@obfs_inode_by_name: ino=%lu\n", ino);
    //read object's xattrs into inode's dentry for compare
    mem_de = obfs_find_dentry_by_ino(ino);//FIXME: TODO, here comes the BUG!
    if (unlikely(!mem_de)){//only when it's not in dcache, we find it in fs
      if (unlikely(obfs_get_xattrs(ino, oi))){
        //printk(KERN_ERR "@obfs_inode_by_name: bad ino=%lu\n", ino);
        return 0;
      }

      if (oi->i_links_count) {
        namelen = strlen(oi->i_d.d_name);
        //printk(KERN_ERR "@obfs_inode_by_name: name1=%s,len1=%d,name2=%s,len2=%d\n",
        //   oi->i_d.d_name, namelen, dentry->d_name.name, dentry->d_name.len);

        if ((namelen == dentry->d_name.len) &&
            (!strncmp(dentry->d_name.name,
                      oi->i_d.d_name, dentry->d_name.len))){
          //read object's stat into inode
          obfs_get_inode_stat(ino, &(dentry->d_inode.stat));
          //printk(KERN_ERR "@obfs_inode_by_name: ino found\n");
          break;
        }
      }
    } else {
      //the dentry is already in dcache and we have compared it before
      oi = obfs_get_inode(mem_de);
    }

    if (ino == obfs_get_inode(dentry)->i_type.dir.tail){
      ino = 0;
      break;
    }
		ino = le64_to_cpu(oi->i_d.d_next);
      //printk(KERN_ERR "@obfs_inode_by_name: next_ino=%lu\n", ino);
	}
	//mutex_unlock(&vi->i_link_mutex);
	return ino;
}

//FIXME: unfinished
//lookup a dentry by its name in fs
static struct obfs_dentry_info *obfs_lookup(struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry, unsigned int flags){
  ino_t ino;
  struct obfs_dentry_info *new = NULL;

  if (unlikely(dentry->d_name.len > OBFS_NAME_LEN)){
    return ERR_PTR(-ENAMETOOLONG);
  }
  //@ayu: FIXME, uncomment this
  //ino = obfs_inode_by_name(dir, dentry);
  ino = 0;
  if (ino){
    //printk(KERN_ERR "@obfs_lookup: ino=%lu\n", ino);
    new = dentry;
    //dentry's inode has already been filled
    //connect dentry with ino and insert it to the dentry hash table
  }
  obfs_d_instantiate(dentry, ino);//instead of d_splice_alias(dentry);//FIXME: multi-thread BUG comes from here
  if (obfs_d_unhashed(dentry)){
    obfs_d_rehash(dentry);
  }
  return new;
  //return dentry;
}

//FIXME: unfinished
//copy from generic_permission
//parent directory permission check
int obfs_inode_permission(struct obfs_dentry_info *dentry, int mask){
  /*struct obfs_sb_info *sbi = obfs_sbi;
  int retval;
  //super block permission check
  //nobody gets write access to a read-only fs
  if ((sbi->s_flags & MS_RDONLY)
      && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))){
    return -EROFS;
  }

  //nobody gets write to an immutable file
  if (unlikely(mask & MAY_WRITE)){
    if (IS_IMMUTABLE(dentry)){
      return -EACCES;
    }
  }

  //FIXME: copy from posix_acl_permission()
  retval = obfs_acl_permission_check(dentry, mask);
  if (retval != -EACCES){
    return retval;
  }
  if (S_ISDIR(dentry->d_inode.i_mode)){
    if (inode_capable(inode, CAP_DAC_OVERRIDE)){//FIXME
      return 0;
    }
    if (!(mask & MAY_WRITE)){
      if (inode_capable(inode, CAP_DAC_READ_SEARCH)){
        return 0;
      }
    }
    return -EACCES;
  }

  if (!(mask & MAY_EXEC) || (dentry->d_inode->i_flags & S_IXUGO)){
    if (inode_capable(inode, CAP_DAC_OVERRIDE)){
      return 0;
    }
  }

  mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
  if (mask == MAY_READ){
    if (inode_capable(inode, CAP_DAC_READ_SEARCH)){
      return 0;
    }
  }*/
  return 0;
}
//FIXME: currently we only support absolute path
static int path_init(int dfd, const char *name, unsigned int flags,
    struct obfs_nameidata *nd, struct file **fp){
  struct obfs_sb_info *sbi = obfs_sbi;
  int retval = 0;
  nd->last_type = LAST_ROOT;
  nd->flags = flags | LOOKUP_JUMPED;
  nd->depth = 0;
  //FIXME: unfinished
  /*if (flags & LOOKUP_ROOT){
    struct obfs_dentry_info *dentry = sbi->s_root;
    if (*name){
      if (!can_lookup(dentry)){
        return -ENOTDIR;
      }
      retval = obfs_inode_permission(dentry, MAY_EXEC);
      if (retval){
        return retval;
      }
    }
    nd->path = sbi->s_root;
    if (flags & LOOKUP_RCU){
      lock_rcu_walk();
      nd->seq = __read_seqcount_begin(&nd->path->d_seq);
    } else {
      obfs_dget(&nd->path);
    }
    return 0;
  }*/

  if (*name == '/'){
    //name must start with scmfs_sbi->mount_point
    //has already been checked in file system syscall
    //int len = strlen(sbi->mount_point);
    //if (memcmp(sbi->mount_point, name, len)){//not equal
    //  retval = -EBADF;
    //  //printk(KERN_ERR "#obfs: obfs_path_init: absolute path wrong!\n");
    //} else {
      obfs_dget(sbi->s_root);
      nd->path = sbi->s_root;
      //printk(KERN_ERR "#obfs: obfs_path_init: absolute path right!\n");
    //}
  }/* else if (dfd == AT_FDCWD){//FIXME
    if (flags & LOOKUP_RCU){
      struct fs_struct *fs = current->fs;
      unsigned seq;

      lock_rcu_walk();

      do {
        seq = read_seqcount_begin(&fs->seq);
        nd->path = fs->pwd;//FIXME
        nd->seq = __read_seqcount_begin(&nd->path->d_seq);
      } while (read_seqcount_retry(&fs->seq, seq));
    } else {
      get_fs_pwd(current->fs, &nd->path);
    }
  }*/ else {
    return -EBADF;
    /*
    //init path from dfd
    struct fd f = fdget_raw(dfd);
    struct obfs_dentry_info *dentry;
    if (!f.file){
      return -EBADF;
    }

    dentry = f.file->f_path.dentry;//FIXME

    if (*name){
      if (!can_lookup(dentry)){
        fdput(f);
        return -ENOTDIR;
      }
    }

    nd->path = f.file->f_path;
    if (flags & LOOKUP_RCU){
      if (f.need_put){
        *fp = f.file;
      }
      nd->seq = __read_seqcount_begin(&nd->path->d_seq);
      lock_rcu_walk();
    } else {
      obfs_dget(&nd->path);
      fdput(f);
    }
    */
  }
  return 0;
}

static void follow_dotdot(struct obfs_nameidata *nd){
  struct obfs_dentry_info *old = nd->path;

  if (nd->path!= obfs_sbi->s_root){
    nd->path = obfs_dget_parent(nd->path);
    obfs_dput(0, old);
  }
}

//allocate a dentry with name and parent, and perform a parent directory ->lookup on it
/*static struct scmfs_dentry_info *scmfs_d_alloc_and_lookup(
    struct scmfs_dentry_info *parent, struct qstr *name,
    struct scmfs_nameidata *nd){
  struct scmfs_dentry_info *dentry;
  struct scmfs_dentry_info *old;

  //don't create child dentry for a dead directory
  //if (unlikely(IS_DEADDIR(inode->s_inode))){//i_flags has beed transfered from inode to dentry 
  if (unlikely(IS_DEADDIR(parent))){
    return ERR_PTR(-ENOENT);
  }

  printk(KERN_ERR "#scmfs: scmfs_d_alloc start!\n");
  //FIXME:@ayu here comes the BUG!
  dentry = scmfs_d_alloc(parent, name);
  printk(KERN_ERR "#scmfs: scmfs_d_alloc end!\n");
  if (unlikely(!dentry)){
    printk(KERN_ERR "#scmfs: scmfs_d_alloc denrry=NULL\n");
    return ERR_PTR(-ENOMEM);
  }

  old = scmfs_lookup(parent->i_ino, dentry, nd);
  if (unlikely(old)){
    printk(KERN_ERR "#scmfs: unlikely?\n");
    scmfs_dput(dentry);
    dentry = old;
  }
  return dentry;
}*/

static inline void path_to_nameidata(struct obfs_dentry_info *path,
    struct obfs_nameidata *nd){
  if (!(nd->flags & LOOKUP_RCU)){
    obfs_dput(0, nd->path);
  }
  nd->path = path;
}

static int link_path_walk(const char *, struct obfs_nameidata *);

static int __obfs_follow_link(struct obfs_nameidata *nd, const char *link){
  struct obfs_sb_info *sbi = obfs_sbi;
  int ret;

  if (IS_ERR(link)){
    goto fail;
  }

  if (*link == '/'){
    nd->path = sbi->s_root;
    obfs_dget(sbi->s_root);
    nd->flags |= LOOKUP_JUMPED;
  }
  ret = link_path_walk(link, nd);
  return ret;
fail:
  obfs_dput(0, nd->path);
  return PTR_ERR(link);
}

static void *obfs_follow_link(struct obfs_dentry_info *dentry,
    struct obfs_nameidata *nd){
  off_t block;
  int status;
  char *blockp = kmalloc(dentry->d_inode.stat.st_size, GFP_KERNEL);
  mm_segment_t fs = get_fs();//to use kernel version of objms_read_obj
  //the symbol link's data content is the path name it points to
  set_fs(get_ds());
  status = sys_objms_read(0, dentry->i_ino, blockp, dentry->d_inode.stat.st_size, 0);
  set_fs(fs);
  //FIXME, decide status's value
  status = __obfs_follow_link(nd, blockp);
  return ERR_PTR(status);
}
//
static struct obfs_dentry_info *obfs_lookup_dcache(struct qstr *name,
    struct obfs_dentry_info *dir, bool *need_lookup){
  struct obfs_dentry_info *dentry;

  *need_lookup = false;
  dentry = obfs_d_lookup(dir, name);
  if (!dentry){
    dentry = obfs_d_alloc(dir, name);
    if (unlikely(!dentry)){
      return ERR_PTR(-ENOMEM);
    }
    *need_lookup = true;//dentry is not in dcache, so we need to lookup it in fs
  }
  return dentry;
}
//call obfs_lookup on the dentry, the dentry must be negative
//dir_inode->i_mutex must be held
//lookup dentry in fs
//FIXME, TODO, how to avoid this to speedup dentry lookup?
static struct obfs_dentry_info *obfs_lookup_real(struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry, unsigned int flags){
  struct obfs_dentry_info *old;

  //don't create child dentry for a dead directory
  if (unlikely(IS_DEADDIR(obfs_get_inode(dir)))){
    obfs_dput(0, dentry);
    return ERR_PTR(-ENOENT);
  }

  //lookup dentry's inode in fs and fill the dentry's inode
  old = obfs_lookup(dir, dentry, flags);//FIXME: some different
  //printk(KERN_ERR "@obfs_lookup_real: obfs_lookup end\n");
  if (unlikely(old)){//why do this? just find if the dentry's name has already been used?
    obfs_dput(0, dentry);
    dentry = old;
  }
  return dentry;
}

static struct obfs_dentry_info *__obfs_lookup_hash(struct qstr *name,
    struct obfs_dentry_info *base, unsigned int flags){
  bool need_lookup;
  struct obfs_dentry_info *dentry;

  dentry = obfs_lookup_dcache(name, base, &need_lookup);
  if (!need_lookup){
    return dentry;
  }

  return obfs_lookup_real(base, dentry, flags);
}

static inline struct obfs_dentry_info *obfs_lookup_hash(struct obfs_nameidata *nd){
  return __obfs_lookup_hash(&nd->last, nd->path, nd->flags);
}

//check whether we ca create an object with dentry child in directory dir
//FIXME
static inline int may_create(struct obfs_dentry_info *dir,
    struct obfs_dentry_info *child){
  /*if (child->i_ino){
    printk(KERN_ERR "#obfs: obfs_may_create child->i_ino > 0!\n");
    return -EEXIST;
  }*/
  if (IS_DEADDIR(obfs_get_inode(dir))){
  	//printk("@obfs_may_create is_deaddir\n");
    return -ENOENT;
  }
  return obfs_inode_permission(dir, MAY_WRITE | MAY_EXEC);
}
//FIXME: current_fsuid() may need mofidication
/*static void obfs_inode_init_owner(struct obfs_inode *oi,
    const struct obfs_inode *dir_inode, umode_t mode){
  oi->i_uid = cpu_to_le32(current_fsuid());
  if (dir_inode && (dir_inode->i_mode & S_ISGID)){
    oi->i_gid = dir_inode->i_gid;
    if (S_ISDIR(mode)){
      mode |= S_ISGID;
    }
  } else {
    oi->i_gid = cpu_to_le32(current_fsgid());
  }
  oi->i_mode = cpu_to_le16(mode);
}*/
//FIXME: unfinished
//create an inode(write it to objms) and connect it with dentry
//caller create transaction
//FIXME: return the locked inode
int obfs_new_inode(unsigned long tid, struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry, int mode){
  struct obfs_sb_info *sbi = obfs_sbi;
  struct obfs_inode *oi = NULL;
  int i, errval;
  ino_t ino = 0;
  struct obj_stat *os;

  //mutex_lock(&sbi->s_lock);
  mutex_lock(&dentry->i_mutex);
  //use dentry's d_inode as a inode buf
  oi = obfs_get_inode(dentry);
  
  ino = sys_objms_create(tid, NULL, mode);

  //TODO: set inode's in-memory stat
  os = &(dentry->d_inode.stat);
  os->st_mode = mode;
  //chosen inode is in ino
  dentry->i_ino = ino;
  //init inode's owner
  //inode_init_owner(oi, dir, mode);//FIXME: unfinished
  oi->i_d.d_next = 0;
  //oi->i_d.d_prev = 0;
  oi->i_flags = obfs_mask_flags(mode, obfs_get_inode(dir)->i_flags);
  if (mode & S_IFDIR){//directory's link_count=2
    oi->i_links_count = cpu_to_le16(2);
  } else {
    oi->i_links_count = cpu_to_le16(1);
  }

  //printk(KERN_ERR "@obfs_new_inode: ino=%lu\n", ino);
  //FIXME: do not update inode's extra fields here,
  //update it in add_link together with dentry
  //obfs_update_inode_xattr(ino, oi);

  /*errval = obfs_init_acl(inode, dir);//FIXME: acl permission not finished yet
  if (errval){
    goto fail2;
  }*/

//  obfs_sync_super(sbi);//update super to objms
  //mutex_unlock(&sbi->s_lock); //return the locked inode directly
  return 0;//success
fail2:
  printk(KERN_ERR "@obfs_new_inode: fail2!\n");
  //mutex_unlock(&sbi->s_lock);
  mutex_unlock(&dentry->i_mutex);
  dentry->i_ino = 0;//ino = 0 means invalid inode
  return errval;
fail1:
  printk(KERN_ERR "@obfs_new_inode: fail1!\n");
  //mutex_unlock(&sbi->s_lock);
  mutex_unlock(&dentry->i_mutex);
  dentry->i_ino = 0;//ino = 0 means invalid inode
  return errval;
}
//FIXME
//regular file creation
//caller create txn
int obfs_create(unsigned long tid, struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry, int mode, bool flags){
  int error;
  unsigned long ino;
  
  error = may_create(dir, dentry);
  if (error){
    //printk(KERN_ERR "@obfs: obfs_may_create return failed!\n");
    return error;
  }

  mode &= S_IALLUGO;
  mode |= S_IFREG;


  //printk(KERN_ERR "#obfs_create obfs_new_inode start!\n");
  /*char *dname = kmalloc(dentry->d_name.len + 1, GFP_KERNEL);
  if (!dname){
    return -ENOMEM;
  }
  memcpy(dname, dentry->d_name.name, dentry->d_name.len);
  dname[dentry->d_name.len] = 0;*/

  error = obfs_new_inode(tid, dir, dentry, mode);
  /*memcpy(dentry->d_inode.i_d.d_name, d_name, strlen(dname));
  dentry->d_inode.i_d.dname[strlen(dname)] = 0;
  kfree(dname);*/
  //printk(KERN_ERR "#obfs_create: dentry name = %s\n", dentry->d_name.name);
  //printk(KERN_ERR "#obfs_create: dentry ino = %lu\n", dentry->i_ino);
  if (!error){
    error = obfs_add_nondir(tid, dentry);
  }
  
  /*if (!error){
    fsnotify_create(dir, dentry);//FIXME: fsnotify is used to watch the fs change
  }*/
  return error;
}

//FIXME: unfinished
static int may_open(struct obfs_dentry_info *path, int acc_mode, int flag){
  int error;

  if (!acc_mode){
    return 0;
  }

  if (!path->i_ino){
    return -ENOENT;
  }

  switch (path->d_inode.stat.st_mode & S_IFMT){
    case S_IFLNK:
      return -ELOOP;
    case S_IFDIR:
      if (acc_mode & MAY_WRITE){
        return -EISDIR;
      }
      break;
    case S_IFBLK:
    case S_IFCHR:
    case S_IFIFO:
    case S_IFSOCK:
      flag &= ~O_TRUNC;
      break;
  }

  error = obfs_inode_permission(path, acc_mode);
  if (error){
    return error;
  }

  //an append-only file must be opened in append mode for writing
  if (IS_APPEND(obfs_get_inode(path))){
    if ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND)){
      return -EPERM;
    }
    if (flag & O_TRUNC){
      return -EPERM;
    }
  }

  //if (flag & O_NOATIME && !inode_owner_or_capable(&path->d_inode)){//FIXME: unfinished
   // return -EPERM;
  //}
  return 0;
}

//FIXME: unfinished
static int handle_truncate(struct file *filp){
  return 0;
}

//used in atomic_open()
/*static inline int open_to_namei_flags(int flag){
  if ((flag + 1) & O_ACCMODE){
    flag++;
  }
  return flag;
}*/

static inline int handle_dots(struct obfs_nameidata *nd, int type){
  if (type == LAST_DOTDOT){
    /*if (nd->flags & LOOKUP_RCU){
      if (follow_dotdot_rcu(nd)){
        return -ECHILD;
      }
    } else {
    */
      follow_dotdot(nd);
    //}
  }
  return 0;
}

static void terminate_walk(struct obfs_nameidata *nd){
  //if (nd->flags & LOOKUP_RCU){
    //FIXME
    //nd->flags &= ~LOOKUP_RCU;
    //unlock_rcu_walk();
  //} else {
    obfs_dput(0, nd->path);
  //}
}
//only symlink can follow link
//TODO: currently we *disabled* symlink
static inline int should_follow_link(struct obfs_dentry_info *dentry,
    int follow){
  //return obfs_is_link(dentry) && follow;
  return 0;
}

//copy from vfs's follow_link
static __always_inline int follow_link(struct obfs_dentry_info *link,
    struct obfs_nameidata *nd, void **p){
  int error;
  char *s;

  BUG_ON(nd->flags & LOOKUP_RCU);
  error = -ELOOP;
/*
  if (unlikely(current->total_link_count >= 40)){
    goto out_put_nd_path;
  }
*/
  cond_resched();

  //touch_atime(link);//FIXME
  obfs_nd_set_link(nd, NULL);

  nd->last_type = LAST_BIND;
  *p = obfs_follow_link(link, nd);
  error = PTR_ERR(*p);
  if (IS_ERR(*p)){
    goto out_put_nd_path;
  }

  error = 0;
  s = obfs_nd_get_link(nd);
  if (s){
    error = __obfs_follow_link(nd, s);
    if (unlikely(error)){
      obfs_dput(0, link);
    }
  }

  return error;

out_put_nd_path:
  *p = NULL;
  obfs_dput(0, nd->path);
  obfs_dput(0, link);
  return error;
}

//FIXME: it seems that we don't need this
static int follow_managed(struct obfs_dentry_info **pathp, unsigned flags){
  return 0;
}

static int lookup_fast(struct obfs_nameidata *nd, struct obfs_dentry_info **pathp){
  struct obfs_dentry_info *dentry, *parent = nd->path;
  int need_reval = 1;
  int status = 1;
  int err;

  if (nd->flags & LOOKUP_RCU){
    //FIXME: unfinished
    /*unsigned seq;
    dentry = __d_lookup_rcu(parent, &nd->last, &seq);
    if (!dentry){
      goto unlazy;
    }
    if (read_seqcount_retry(&dentry->d_seq, seq)){
      return -ECHILD;
    }

    if (__read_seqcount_retry(&parent->d_seq, nd->seq)){
      return -ECHILD;
    }
    nd->seq = seq;

    if (unlikely(dentry->d_flags & DCACHE_OP_REVVALIDATE)){
      status = d_revalidate(dentry, nd->flags);
      if (unlikely(status <= 0)){
        if (status != -ECHILD){
          need_reval = 0;
        }
        goto unlazy;
      }
    }
    *pathp = dentry;
    if (unlikely(!__follow_mount_rcu(nd, path, dentry->d_inode))){
      goto unlazy;
    }
    if (unlikely(*pathp->d_flags & DCACHE_NEED_AUTOMOUNT)){
      goto unlazy;
    }
    return 0;
unlazy:
    if (unlazy_walk(nd, dentry)){
      return -ECHILD;
    }*/
  } else {
    dentry = __obfs_d_lookup(parent, &nd->last);//dcache.c
  }

  if (unlikely(!dentry)){
    goto need_lookup;
  }
/*
  //don't need this because we have none of DCACHE_OP_*
  if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE) && need_reval){
    status = d_revalidate(dentry, nd->flags);
  }
  if (unlikely(status <= 0)){
    if (status < 0){
      obfs_dput(dentry);
      return status;
    }
    if (!d_invalidate(dentry)){
      obfs_dput(dentry);
      goto need_lookup;
    }
  }*/

  *pathp = dentry;
  err = follow_managed(pathp, nd->flags);
  if (unlikely(err < 0)){
    obfs_dput(0, *pathp);
    return err;
  }
  if (err){
    nd->flags |= LOOKUP_JUMPED;
  }
  return 0;

need_lookup:
  return 1;
}

static int lookup_slow(struct obfs_nameidata *nd, struct obfs_dentry_info **pathp){
  struct obfs_dentry_info *dentry, *parent;
  int err;

  parent = nd->path;

  mutex_lock(&parent->i_mutex);
  dentry = __obfs_lookup_hash(&nd->last, parent, nd->flags);
  mutex_unlock(&parent->i_mutex);
  if (IS_ERR(dentry)){
    printk(KERN_ERR "@obfs_lookup_slow: __lookup_hash failed\n");
    return PTR_ERR(dentry);
  }
  *pathp = dentry;
  err = follow_managed(pathp, nd->flags);
  if (unlikely(err < 0)){
    obfs_dput(0, *pathp);
    return err;
  }

  if (err){
    nd->flags |= LOOKUP_JUMPED;
  }
  return 0;
}

static inline int walk_component(struct obfs_nameidata *nd,
    struct obfs_dentry_info **pathp, int follow){
  int err;

  if (unlikely(nd->last_type != LAST_NORM)){
    return handle_dots(nd, nd->last_type);
  }
  err = lookup_fast(nd, pathp);
  if (unlikely(err)){
    if (err < 0){
      goto out_err;
    }

    err = lookup_slow(nd, pathp);
    if (err < 0){
      printk(KERN_ERR "@walk_component: lookup_slow failed\n");
      goto out_err;
    }
  }
  err = -ENOENT;
  if (!(*pathp)->i_ino){
    goto out_path_put;
  }

  if (should_follow_link(*pathp, follow)){
    /*if (nd->flags & LOOKUP_RCU){
      if (unlikely(unlazy_walk(nd, *pathp))){
        err = -ECHILD;
        goto out_err;
      }
    }*/
    return 1;
  }
  path_to_nameidata(*pathp, nd);
  return 0;

out_path_put:
  path_to_nameidata(*pathp, nd);
out_err:
  terminate_walk(nd);
  return err;
}
/*
static inline int nested_symlink(struct obfs_dentry_info **pathp,
    struct obfs_nameidata *nd){
  int res;

  if (unlikely(current->link_count >= MAX_NESTED_LINKS)){
    obfs_dput(0, *pathp);
    obfs_dput(0, nd->path);
    return -ELOOP;
  }
  BUG_ON(nd->depth >= MAX_NESTED_LINKS);

  nd->depth++;
  current->link_count++;

  do {
    struct obfs_dentry_info *link = *pathp;
    void *cookie;

    res = follow_link(link, nd, &cookie);
    if (res){
      break;
    }
    res = walk_component(nd, pathp, LOOKUP_FOLLOW);
    obfs_dput(0, link);
  } while (res > 0);

  current->link_count--;
  nd->depth--;
  return res;
}*/
//only dir can lookup
static inline int can_lookup(struct obfs_dentry_info *dentry){
  return obfs_is_dir(dentry);
}
//FIXME
static int unlazy_walk(struct obfs_nameidata *nd, struct obfs_dentry_info *dentry){
  return 0;
}

static inline int may_lookup(struct obfs_nameidata *nd){
  /*if (nd->flags & LOOKUP_RCU){
    int err = obfs_inode_permission(nd->path, MAY_EXEC | MAY_NOT_BLOCK);
    if (err != -ECHILD){
      return err;
    }
    if (unlazy_walk(nd, NULL)){
      return -ECHILD;
    }
  }*/
  return obfs_inode_permission(nd->path, MAY_EXEC);
}


static int complete_walk(struct obfs_nameidata *nd){
  struct obfs_dentry_info *dentry = nd->path;
  int status;

  /*if (nd->flags & LOOKUP_RCU){
  }*/
  if (likely(!(nd->flags & LOOKUP_JUMPED))){
    return 0;
  }

  //we don't have DCACHE_OP_*
  //if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE))){
    return 0;
  //}

  //status = -ESTALE;
  //obfs_dput(nd->path);
  //return status;
}

static int link_path_walk(const char *name, struct obfs_nameidata *nd){
  struct obfs_dentry_info *next = NULL;
  int err;

  name += strlen(obfs_sbi->mount_point);//bypass the mount_point: /obfs
  while (*name == '/'){
    name++;
  }
  if (!(*name)){
    return 0;
  }

  //at this point we know we have a real path component
  for (;;){
    struct qstr this;
    long len;
    int type;

    err = may_lookup(nd);//permission check
    if (err){
      break;
    }

    len = hash_name(name, &this.hash);//just copy from system
    this.name = name;
    this.len = len;

    type = LAST_NORM;
    if (name[0] == '.'){
      switch (len){
        case 2:
          if (name[1] == '.'){
            type = LAST_DOTDOT;
            nd->flags |= LOOKUP_JUMPED;
          }
          break;
        case 1:
          type = LAST_DOT;
      }
    }
    if (likely(type == LAST_NORM)){
      nd->flags &= ~LOOKUP_JUMPED;
    }

    nd->last = this;
    nd->last_type = type;
    if (!name[len]){
      return 0;
    }

    //if it wasnt NULL, we know it was '/', skip that slash, and continue until no more slashes
    while (unlikely(name[++len] == '/'));
    if (!name[len]){
      return 0;
    }

    name += len;

    err = walk_component(nd, &next, LOOKUP_FOLLOW);
    if (err < 0){
      //printk(KERN_ERR "@obfs_link_path_walk: walk_component failed\n");
      return err;
    }
    //printk(KERN_ERR "@obfs_link_path_walk: walk_component succeed\n");

    //because symlink is disabled, so we will never run into this
    /*if (err){//if should_follow_link err = 1
      err = nested_symlink(&next, nd);
      if (err){
        return err;
      }
    }*/
    if (!can_lookup(nd->path)){
      err = -ENOTDIR;
      break;
    }
  }
  //printk(KERN_ERR "@obfs_link_path_walk: terminate_walk begin\n");
  terminate_walk(nd);
  return err;
}

//lookup and maybe create and open the last component
//must be called with i_mutex held on parent
static int lookup_open(struct obfs_nameidata *nd, struct obfs_dentry_info **pathp,
    struct file *file, const struct open_flags *op, int *opened){
  struct obfs_dentry_info *dir = nd->path;
  struct obfs_dentry_info *dentry;
  int error;
  bool need_lookup;
  unsigned long tid;

  *opened &= ~FILE_CREATED;
  dentry = obfs_lookup_dcache(&nd->last, dir, &need_lookup);
  if (IS_ERR(dentry)){
    return PTR_ERR(dentry);
  }

  //cached positive dentry: will open in f_op->open
  if (!need_lookup && dentry->i_ino){
    //printk(KERN_ERR "@obfs_lookup_open: out_no_open\n");
    goto out_no_open;
  }
  
  if (need_lookup){
    //not in dcache or newly created dentry(no inode connected),
    //lookup in fs
    //printk(KERN_ERR "@obfs_lookup_open: lookup_real begin\n");
    dentry = obfs_lookup_real(dir, dentry, nd->flags);
    if (IS_ERR(dentry)){
      return PTR_ERR(dentry);
    }
  }

  //negative dentry, just create the file
  if (!dentry->i_ino && (op->open_flag & O_CREAT)){
    umode_t mode = op->mode;
    /*if (!IS_POSIXACL(dir->d_inode)){
      mode &= ~current_umask();
    }*/
/*    if (!got_write){
      error = -EROFS;
      goto out_dput;
    }*/

    *opened |= FILE_CREATED;
    //printk(KERN_ERR "@obfs_lookup_open: obfs_create begin\n");
    tid = sys_objms_new_txn(obfs_xmode());
    error = obfs_create(tid, dir, dentry, mode,
        nd->flags & LOOKUP_EXCL);//TODO: some different
    if (likely(!error)){
      //sys_objms_commit_txn(tid);
      file->private_data = (void *)tid;
      sys_objms_xcntl(tid, OBJMS_XMODE_SET, obfs_xmode() | OBJMS_XAUTO);
    } else {
      sys_objms_abort_txn(tid);
      goto out_dput;
    }
  }
out_no_open:
  *pathp = dentry;
  return 1;

out_dput:
  obfs_dput(0, dentry);
  return error;
}

//handle the last step of open()
static int do_last(struct obfs_nameidata *nd, struct obfs_dentry_info **pathp,
    struct file *file, const struct open_flags *op,
    int *opened, struct filename *name){
  struct obfs_dentry_info *dir = nd->path;
  int open_flag = op->open_flag;
  bool will_truncate = (open_flag & O_TRUNC) != 0;
  //bool got_write = false;
  int acc_mode = op->acc_mode;
  bool symlink_ok = false;
  struct obfs_dentry_info *save_parent = NULL;
  bool retried = false;
  int error;

  nd->flags &= ~LOOKUP_PARENT;
  nd->flags |= op->intent;

  if (nd->last_type != LAST_NORM){
    //printk(KERN_ERR "#obfs_do_last: nd->last_type != LAST_NORM\n");
    error = handle_dots(nd, nd->last_type);
    if (error){
      return error;
    }
    goto finish_open;
  }

  if (!(open_flag & O_CREAT)){
    //printk(KERN_ERR "@obfs_do_last: !(open_flag & O_CREAT)\n");
    if (nd->last.name[nd->last.len]){
      nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
    }
    if (open_flag & O_PATH && !(nd->flags & LOOKUP_FOLLOW)){
      symlink_ok = true;
    }
    error = lookup_fast(nd, pathp);
    if (likely(!error)){
      goto finish_lookup;
    }
    if (error < 0){
      goto out;
    }
  } else {
    //printk(KERN_ERR "@obfs_do_last: (open_flag & O_CREAT) complete_walk start\n");
    error = complete_walk(nd);
    if (error){
      return error;
    }
    //audit_inode(name, dir, LOOKUP_PARENT);//FIXME
    error = -EISDIR;
    //trailing slashes?
    if (nd->last.name[nd->last.len]){
      goto out;
    }
  }

retry_lookup:
    //printk(KERN_ERR "#obfs_do_last: retry_lookup\n");
  /*if (op->open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)){
    //error = mnt_want_write(nd->path.mnt);
    //if (!error){
      got_write = true;
    //}
  }*/
  mutex_lock(&dir->i_mutex);
  //error = lookup_open(nd, pathp, file, op, got_write, opened);
  error = lookup_open(nd, pathp, file, op, opened);
  mutex_unlock(&dir->i_mutex);

  if (error <= 0){
    if (error){
      goto out;
    }

    /*if ((*opened & FILE_CREATED)
        || !S_ISREG(file_inode(file)->i_mode)){//FIXME
      will_truncate = false;
    }
    audit_inode(name, file->f_path.dentry, 0);//FIXME
    */
    goto opened;
  }

  if (*opened & FILE_CREATED){
    open_flag &= ~O_TRUNC;
    will_truncate = false;
    acc_mode = MAY_OPEN;
    path_to_nameidata(*pathp, nd);
    goto finish_open_created;
  }

  //FIXME
  //if ((*pathp)->i_ino){
   // audit_inode(name, *pathp, 0);
  //}
/*
  if (got_write){
    //mnt_drop_write(nd->path.mnt);
    got_write = false;
  }
 */ 
  error = -EEXIST;
  if ((open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT)){
    goto exit_dput;
  }

  error = follow_managed(pathp, nd->flags);
  if (error < 0){
    goto exit_dput;
  }
  if (error){
    nd->flags |= LOOKUP_JUMPED;
  }

  BUG_ON(nd->flags & LOOKUP_RCU);
finish_lookup:
    //printk(KERN_ERR "#obfs_do_last: finish_lookup\n");
  //we can be in RCU mode here
  error = -ENOENT;
  if (!(*pathp)->i_ino){
    path_to_nameidata(*pathp, nd);
    goto out;
  }

  if (should_follow_link(*pathp, !symlink_ok)){
    /*if (nd->flags & LOOKUP_RCU){
      if (unlikely(unlazy_walk(nd, pathp))){
        error = -ECHILD;
        goto out;
      }
    }*/
    return 1;
  }
  //if (nd->flags & LOOKUP_RCU){
   // path_to_nameidata(*pathp, nd);
  //} else {
    save_parent = nd->path;
    nd->path = *pathp;
  //}
finish_open:
    //printk(KERN_ERR "#obfs_do_last: finish_open\n");
  error = complete_walk(nd);
  if (error){
    obfs_dput(0, save_parent);
  }
  //audit_inode(name, nd->path, 0);
  error = -EISDIR;
  if ((open_flag & O_CREAT) && S_ISDIR(nd->path->d_inode.stat.st_mode)){
    goto out;
  }
  error = -ENOTDIR;
  if ((nd->flags & LOOKUP_DIRECTORY) && !can_lookup(nd->path)){
    goto out;
  }
  if (!S_ISREG(nd->path->d_inode.stat.st_mode)){
    will_truncate = false;
  }
/*  if (will_truncate){
    //error = mnt_want_write(nd->path.mnt);
    //if (error){
     // goto out;
    //}
    got_write = true;
  }*/
finish_open_created:
    //printk(KERN_ERR "@obfs_do_last: finish_open_created\n");
    //FIXME: handle the permission check to objms
  /*error = may_open(nd->path, acc_mode, open_flag);
  if (error){
    goto out;
  }*/
  //file->f_path.mnt = nd->path.mnt;
  error = obfs_finish_open(file, nd->path, opened);//connect file with dentry
  if (error){
    if (error == -EOPENSTALE){
      goto stale_open;
    }
    goto out;
  }
opened:
    //printk(KERN_ERR "#obfs_do_last: opened\n");
  /*error = open_check_o_direct(file);//no need
  if (error){
    goto exit_fput;
  }*/
  /*error = ima_file_check(file, op->acc_mode);//FIXME: unfinished, can't just use vfs'
  if (error){
    goto exit_fput;
  }*/

  if (will_truncate){
    error = handle_truncate(file);//FIXME: unfinished
    if (error){
      goto exit_fput;
    }
  }
out:
    //printk(KERN_ERR "@obfs_do_last: out\n");
  //if (got_write){
   // mnt_drop_write(nd->path.mnt);
  //}
  obfs_dput(0, save_parent);
  terminate_walk(nd);
  return error;

exit_dput:
  obfs_dput(0, *pathp);
  goto out;
exit_fput:
  fput(file);
  goto out;

stale_open:
    //printk(KERN_ERR "#obfs_do_last: stale_open\n");
  //if no saved parent or already retried then can't retry
  if (!save_parent || retried){
    goto out;
  }

  BUG_ON(save_parent != dir);
  obfs_dput(0, nd->path);
  nd->path = save_parent;
  //if (got_write){
   // mnt_drop_write(nd->path.mnt);
    //got_write = false;
  //}
  retried = true;
  goto retry_lookup;
}

static struct file *path_openat(int dfd, struct filename *pathname,
    struct obfs_nameidata *nd, const struct open_flags *op, int flags){
  struct file *base = NULL;
  struct file *file;
  struct obfs_dentry_info *path;
  int opened = 0;
  int error;

  file = get_empty_filp();
  if (IS_ERR(file)){
    return file;
  }

  file->f_flags = op->open_flag;

  /*if (unlikely(file->f_flags & __O_TMPFILE)){
    error = do_tmpfile(dfd, pathname, nd, flags, op, flag, &opened);//FIXME: unfinished
    goto out;
  }*/

  error = path_init(dfd, pathname->name, flags | LOOKUP_PARENT, nd, &base);
  if (unlikely(error)){
    goto out;
  }

  //current->total_link_count = 0;
  error = link_path_walk(pathname->name, nd);
  if (unlikely(error)){
    printk(KERN_ERR "@obfs: link_path_walk failed\n");
    goto out;
  }
  //printk(KERN_ERR "#obfs: link_path_walk succeed\n");
  
  error = do_last(nd, &path, file, op, &opened, pathname);
  while (unlikely(error > 0)){
    struct obfs_dentry_info *link = path;
    void *cookie;
    if (!(nd->flags & LOOKUP_FOLLOW)){
      obfs_dput(0, path);
      obfs_dput(0, nd->path);
      error = -ELOOP;
      break;
    }
    //error = may_follow_link(link, nd);//FIXME: unfinished
    //if (unlikely(error)){
     // break;
    //}
    nd->flags |= LOOKUP_PARENT;
    nd->flags &= ~(LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_EXCL);
    error = follow_link(link, nd, &cookie);
    if (unlikely(error)){
      break;
    }
    error = do_last(nd, &path, file, op, &opened, pathname);
    obfs_dput(0, link);
  }
out:
  if (base){
    fput(base);
  }
  if (!(opened & FILE_OPENED)){
    BUG_ON(!error);
    put_filp(file);
  }
  if (unlikely(error)){
    if (error == -EOPENSTALE){
      if (flags & LOOKUP_RCU){
        error = -ECHILD;
      } else {
        error = -ESTALE;
      }
    }
    file = ERR_PTR(error);
  }
  return file;
}

struct file *obfs_do_filp_open(int dfd, struct filename *pathname,
    const struct open_flags *op){
  struct obfs_nameidata nd;
  int flags = op->lookup_flags;
  struct file *filp;

  //filp = path_openat(dfd, pathname, &nd, op, flags | LOOKUP_RCU);
  //if (unlikely(filp == ERR_PTR(-ECHILD))){
    filp = path_openat(dfd, pathname, &nd, op, flags);
  /*}
  if (unlikely(filp == ERR_PTR(-ESTALE))){
    filp = path_openat(dfd, pathname, &nd, op, flags | LOOKUP_REVAL);
  }*/
  return filp;
}
EXPORT_SYMBOL(obfs_do_filp_open);
//FIXME: unfinished
static int may_delete(struct obfs_dentry_info *dir,
    struct obfs_dentry_info *victim, int isdir){
  return 0;
}

static inline int obfs_do_unlink(unsigned long tid, struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry){
  int error = may_delete(dir, dentry, 0);
  if (error){
    return error;
  }

  //printk(KERN_ERR "@obfs_do_unlink: ino=%lu,mode=%o\n", dentry->i_ino, dentry->d_inode.stat.st_mode);
  obfs_remove_ino_hash(dentry);
  mutex_lock(&dentry->i_mutex);
  //FIXME: do it here instead of dentry_unlink_inode
    obfs_remove_link(tid, dentry);//update dentry's parent and prev and next
  mutex_unlock(&dentry->i_mutex);
  //@ayu: FIXME
  sys_objms_delete(tid, dentry->i_ino);//remove the inode and its dentry

  dentry->i_ino = 0;
  obfs_d_delete(tid, dentry);

  return error;
}

static inline int lookup_last(struct obfs_nameidata *nd,
    struct obfs_dentry_info **path){
  if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len]){
    nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
  }
  nd->flags &= ~LOOKUP_PARENT;
  return walk_component(nd, path, nd->flags & LOOKUP_FOLLOW);
}

static int path_lookupat(int dfd, const char *name,
    unsigned int flags, struct obfs_nameidata *nd){
  struct file *base = NULL;
  struct obfs_dentry_info *path;
  int err;

  err = path_init(dfd, name, flags | LOOKUP_PARENT, nd, &base);
  if (unlikely(err)){
    return err;
  }

  //current->total_link_count = 0;
  err = link_path_walk(name, nd);

  if (!err && !(flags & LOOKUP_PARENT)){
    err = lookup_last(nd, &path);
    while (err > 0){
      void *cookie;
      struct obfs_dentry_info *link = path;
      /*err = may_follow_link(link, nd, &cookie);
      if (unlikely(err)){
        break;
      }*///FIXME
      nd->flags |= LOOKUP_PARENT;
      err = follow_link(link, nd, &cookie);
      if (err){
        break;
      }
      err = lookup_last(nd, &path);
      obfs_dput(0, link);
    }
  }

  if (!err){
    err = complete_walk(nd);
  }
  if (!err && nd->flags & LOOKUP_DIRECTORY){
    if (!can_lookup(nd->path)){
      obfs_path_put(0, nd->path);
      err = -ENOTDIR;
    }
  }

  if (base){
    fput(base);
  }

  return err;
}

static int filename_lookup(int dfd, struct filename *name,
    unsigned int flags, struct obfs_nameidata *nd){
  int retval = path_lookupat(dfd, name->name, flags, nd);
  return retval;
}

//FIXME: what's this for?
int obfs_user_path_at_empty(int dfd, const char __user *name, unsigned flags,
    struct obfs_dentry_info **path, int *empty){
  struct obfs_nameidata nd;
  //struct filename *tmp = getname_flags(name, flags, empty);
  struct filename *tmp = getname(name);//FIXME: getname will call getname_flags but less parameters
  int err = PTR_ERR(tmp);

  if (!IS_ERR(tmp)){
    err = filename_lookup(dfd, tmp, flags, &nd);
    putname(tmp);
    if (!err){
      *path = nd.path;
    }
  }
  return err;
}

//FIXME
int obfs_user_path_at(int dfd, const char __user *name, unsigned flags,
    struct obfs_dentry_info **path){
  return obfs_user_path_at_empty(dfd, name, flags, path, NULL);
}

static struct filename *user_path_parent(int dfd, const char __user *path,
    struct obfs_nameidata *nd, unsigned int flags){
  struct filename *s = getname(path);
  int error;

  flags &= LOOKUP_REVAL;
  if (IS_ERR(s)){
    return s;
  }

  error = filename_lookup(dfd, s, flags | LOOKUP_PARENT, nd);
  if (error){
    putname(s);
    return ERR_PTR(error);
  }

  return s;
}

int obfs_unlink(int dfd, const char __user *pathname){
  int error;
  struct filename *name;
  struct obfs_dentry_info *dentry;
  struct obfs_nameidata nd;
  unsigned int lookup_flags = 0;
retry:
  name = user_path_parent(dfd, pathname, &nd, lookup_flags);
  if (IS_ERR(name)){
    return PTR_ERR(name);
  }

  error = -EISDIR;
  if (nd.last_type != LAST_NORM){
    goto exit1;
  }

  nd.flags &= ~LOOKUP_PARENT;

  mutex_lock_nested(&nd.path->i_mutex, I_MUTEX_PARENT);
  dentry = obfs_lookup_hash(&nd);
  error = PTR_ERR(dentry);
  if (!IS_ERR(dentry)){
    if (nd.last.name[nd.last.len]){
      goto slashes;
    }
    if (!dentry->i_ino){
      goto slashes;
    }

    unsigned long tid = sys_objms_new_txn(obfs_xmode());
    error = obfs_do_unlink(tid, nd.path, dentry);//FIXME
    sys_objms_commit_txn(tid);
    //printk(KERN_ERR "@obfs_unlink: succeed\n");
exit2:
    obfs_dput(0, dentry);
  }
  mutex_unlock(&nd.path->i_mutex);

exit1:
  obfs_path_put(0, nd.path);
  putname(name);
  //if (retry_estale(error, lookup_flags)){
  if (error == -ESTALE && !(lookup_flags & LOOKUP_REVAL)){
    lookup_flags |= LOOKUP_REVAL;
    goto retry;
  }
  return error;

slashes:
  goto exit2;
}
EXPORT_SYMBOL(obfs_unlink);
//obfs_def
/*
SYSCALL_DEFINE1(obfs_unlink, const char __user *, pathname){
  return obfs_do_unlinkat(AT_FDCWD, pathname);
}
*/

//when creating a directory, its link_count=2, and its parent's link_count++
static int obfs_do_mkdir(struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry, umode_t mode){
  struct inode *inode;
	struct obfs_inode *oi;
  int err;
  unsigned long tid;

  err = may_create(dir, dentry);
  if (err){
    return err;
  }
  //printk(KERN_ERR "@obfs_mkdir: sys_objms_new_transaction begin\n");
  tid = sys_objms_new_txn(obfs_xmode());
//increase the count of parent dir
	obfs_inc_count(tid, dir);

	err = obfs_new_inode(tid, dir, dentry, S_IFDIR | mode);
  if (err){
    goto out_dir;
  }
//do not need to increase the count of newly created dir
//because it has already be done in new_inode
	//obfs_inc_count(dentry);

	// make the new directory empty 
  oi = obfs_get_inode(dentry);
	oi->i_type.dir.head = oi->i_type.dir.tail = 0;

	err = obfs_add_link(tid, dentry);
	if (err)
		goto out_fail;

  //printk(KERN_ERR "@obfs_mkdir: sys_objms_commit_transaction end\n");
  //unlock the new inode
  mutex_unlock(&dentry->i_mutex);
	obfs_d_instantiate(dentry, dentry->i_ino);
  //printk(KERN_ERR "@obfs_mkdir: success\n");
  sys_objms_commit_txn(tid);
out:
	return err;

out_fail:
	obfs_dec_count(tid, dentry);
	obfs_dec_count(tid, dentry);
	
  mutex_unlock(&dentry->i_mutex);
  //obfs_dput(dentry);//FIXME: if connection failed, delete the inode, we just need to abort the txn
out_dir:
	obfs_dec_count(tid, dir);
	
  sys_objms_abort_txn(tid);
  goto out;
}

static int obfs_do_rmdir(unsigned long tid, struct obfs_dentry_info *dir,
    struct obfs_dentry_info *dentry){
	struct obfs_inode *oi;
	int err = -ENOTEMPTY;

  err = may_delete(dir, dentry, 1);
  if (err){
    return err;
  }
  obfs_dget(dentry);
  mutex_lock(&dentry->i_mutex);

	oi = obfs_get_inode(dentry);

	// directory to delete is empty? 
	if (oi->i_type.dir.tail == 0) {
		//clear_nlink(inode);
    
    //just update the nlink of inode
    //printk(KERN_ERR "@pram_rmdir: sys_objms_new_transaction begin\n");
    //decrease the links count of the parent dir
		obfs_dec_count(tid, dir);
    //printk(KERN_ERR "@obfs_rmdir: sys_objms_commit_transaction end\n");
		err = 0;
    //printk(KERN_ERR "@obfs_rmdir: succeed\n");
	}
  mutex_unlock(&dentry->i_mutex);
  obfs_dput(tid, dentry);
  if (!err){
    printk(KERN_ERR "@obfs_do_rmdir: ino=%lu\n", dir->i_ino);
    obfs_d_delete(tid, dentry);
  }

	return err;
}

static int do_path_lookup(int dfd, const char *name,
    unsigned int flags, struct obfs_nameidata *nd){
  struct filename filename = {.name = name};
  return filename_lookup(dfd, &filename, flags, nd);
}

struct obfs_dentry_info *obfs_kern_path_create(int dfd, const char *pathname,
    struct obfs_dentry_info **path, unsigned int lookup_flags){
  struct obfs_dentry_info *dentry = ERR_PTR(-EEXIST);
  struct obfs_nameidata nd;
  int err2;
  int error;
  bool is_dir = (lookup_flags & LOOKUP_DIRECTORY);

  lookup_flags &= LOOKUP_REVAL;
  error = do_path_lookup(dfd, pathname, LOOKUP_PARENT | lookup_flags, &nd);
  if (error){
    return ERR_PTR(error);
  }

  if (nd.last_type != LAST_NORM){
    goto out;
  }
  nd.flags &= ~LOOKUP_PARENT;
  nd.flags |= LOOKUP_CREATE | LOOKUP_EXCL;

  mutex_lock_nested(&nd.path->i_mutex, I_MUTEX_PARENT);
  dentry = obfs_lookup_hash(&nd);
  if (IS_ERR(dentry)){
    goto unlock;
  }

  error = -EEXIST;
  if (dentry->i_ino){
    goto fail;
  }

  if (unlikely(!is_dir && nd.last.name[nd.last.len])){
    error = -ENOENT;
    goto fail;
  }
  *path = nd.path;
  return dentry;
fail:
  obfs_dput(0, dentry);
  dentry = ERR_PTR(error);
unlock:
  mutex_unlock(&nd.path->i_mutex);
out:
  obfs_path_put(0, nd.path);
  return dentry;
}

struct obfs_dentry_info *obfs_user_path_create(int dfd, const char __user *pathname,
    struct obfs_dentry_info **path, unsigned int lookup_flags){
  struct filename *tmp = getname(pathname);
  struct obfs_dentry_info *res;
  if (IS_ERR(tmp)){
    return ERR_CAST(tmp);
  }
  res = obfs_kern_path_create(dfd, tmp->name, path, lookup_flags);
  putname(tmp);
  return res;
}

int obfs_mkdir(int dfd, const char __user *pathname, umode_t mode){
  struct obfs_dentry_info *dentry;
  struct obfs_dentry_info *path;
  int error;
  unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
  dentry = obfs_user_path_create(dfd, pathname, &path, lookup_flags);//FIXME: do we create txn here?
  if (IS_ERR(dentry)){
    return PTR_ERR(dentry);
  }

  error = obfs_do_mkdir(path, dentry, mode);
  obfs_dput(0, dentry);
  mutex_unlock(&path->i_mutex);//FIXME: locked in kern_path_create
  obfs_path_put(0, path);

  if ((error == -ESTALE) && !(lookup_flags & LOOKUP_REVAL)){
    lookup_flags |= LOOKUP_REVAL;
    goto retry;
  }

  return error;
}
EXPORT_SYMBOL(obfs_mkdir);

int obfs_rmdir(int dfd, const char __user *pathname){
  int error = 0;
  struct filename *name;
  struct obfs_dentry_info *dentry;
  struct obfs_nameidata nd;
  unsigned int lookup_flags = 0;
retry:
  name = user_path_parent(dfd, pathname, &nd, lookup_flags);
  if (IS_ERR(name)){
    return PTR_ERR(name);
  }

  switch (nd.last_type){
    case LAST_DOTDOT:
      error = -ENOTEMPTY;
      goto exit1;
    case LAST_DOT:
      error = -EINVAL;
      goto exit1;
    case LAST_ROOT:
      error = -EBUSY;
      goto exit1;
  }

  nd.flags &= ~LOOKUP_PARENT;

  mutex_lock_nested(&nd.path->i_mutex, I_MUTEX_PARENT);
  dentry = obfs_lookup_hash(&nd);
  error = PTR_ERR(dentry);
  if (IS_ERR(dentry)){
    goto exit2;
  }
  if (!dentry->i_ino){
    error = -ENOENT;
    goto exit3;
  }

  unsigned long tid = sys_objms_new_txn(obfs_xmode());
  error = obfs_do_rmdir(tid, nd.path, dentry);
  sys_objms_commit_txn(tid);//FIXME
exit3:
  obfs_dput(0, dentry);
exit2:
  mutex_unlock(&nd.path->i_mutex);
exit1:
  obfs_path_put(0, nd.path);
  putname(name);
  
  if (error == -ESTALE && !(lookup_flags & LOOKUP_REVAL)){
    lookup_flags |= LOOKUP_REVAL;
    goto retry;
  }
  return error;
}
EXPORT_SYMBOL(obfs_rmdir);

//add by zj
static int obfs_do_statfs(struct obfs_dentry_info *path,struct kstatfs *buf){
 // int retval;
  struct obfs_sb_info *sbi = obfs_sbi;

  printk(KERN_ERR "@obfs_do_statfs: begin\n");
  memset(buf,0,sizeof(*buf));
//buf->f_type = OBFS_SUPER;
 buf->f_bsize = sbi->blocksize;
 buf->f_blocks = 128;
 buf->f_bfree = buf->f_bavail = 10000000;
 buf->f_files = 32;
 buf->f_ffree = 10000000;
 buf->f_namelen =64;
 buf->f_flags = 128;

  if(buf->f_frsize ==0)
    buf->f_frsize = buf->f_bsize;
  return 0;
  
}
int obfs_statfs(const char __user *pathname,struct kstatfs *st){
  struct obfs_dentry_info *path;
  int error;
  unsigned int lookup_flags = LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT;
  retry:
   error = obfs_user_path_at(AT_FDCWD,pathname,lookup_flags,&path);
   if(!error){
     error = obfs_do_statfs(path,st);
     obfs_path_put(0, path);
    
  if (error == -ESTALE && !(lookup_flags & LOOKUP_REVAL)){
    lookup_flags |= LOOKUP_REVAL;
    goto retry;
    }
 }
  return error;
}
EXPORT_SYMBOL(obfs_statfs);


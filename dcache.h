#ifndef _DCACHE_H
#define _DCACHE_H
//#include <linux/dcache.h>
#include "obfs.h"
#include <linux/seqlock.h>
#include <linux/spinlock.h>

//FIXME: let's define our own flags and not used dcache.h of vfs!
//#define DCACHE_REFERENCED 0x0008
//#define DCACHE_UNHASHED 0x0010

#define obfs_path_get(tid, path) obfs_dget(tid, path)
#define obfs_path_put(tid, path) obfs_dput(tid, path)

//extern seqlock_t obfs_rename_lock;

extern struct obfs_dentry_info *obfs_d_lookup(struct obfs_dentry_info *, struct qstr *);
extern struct obfs_dentry_info *__obfs_d_lookup(struct obfs_dentry_info *, struct qstr *);
//alloc a dentry cache
inline struct obfs_dentry_info *obfs_alloc_dcache(void);
//free a dentry cache
inline void obfs_free_dcache(struct obfs_dentry_info *dentry);

static inline int obfs_d_unhashed(struct obfs_dentry_info *dentry){
  //return (dentry->d_flags & DCACHE_UNHASHED);
  return hlist_bl_unhashed(&dentry->d_hash);
}

static inline struct obfs_dentry_info *obfs_dget(struct obfs_dentry_info *dentry){
  if (dentry){
    lockref_get(&dentry->d_lockref);
  }
  return dentry;
}

static inline struct obfs_dentry_info *obfs_dget_parent(struct obfs_dentry_info *dentry){
  struct obfs_dentry_info *ret;

repeat:
  rcu_read_lock();
  ret = dentry->d_parent;
  spin_lock(&ret->d_lock);
  if (unlikely(ret != dentry->d_parent)){
    spin_unlock(&ret->d_lock);
    rcu_read_unlock();
    goto repeat;
  }
  rcu_read_unlock();
  ret->d_lockref.count++;
  spin_unlock(&ret->d_lock);
  return ret;
}

extern void obfs_dput(unsigned long tid, struct obfs_dentry_info *);
extern void obfs_d_instantiate(struct obfs_dentry_info *entry,
    unsigned long ino);

//allocate/de-allocate
extern struct obfs_dentry_info *obfs_d_alloc(struct obfs_dentry_info *,
    const struct qstr *);
extern void obfs_d_delete(unsigned long tid, struct obfs_dentry_info *dentry);
extern void obfs_d_rehash(struct obfs_dentry_info *dentry);
//only used at mount-time
extern struct obfs_dentry_info *obfs_d_make_root(unsigned long ino);
#endif

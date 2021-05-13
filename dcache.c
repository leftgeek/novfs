#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/bootmem.h>
#include <linux/rculist_bl.h>
#include "obfs.h"
#include "dcache.h"
__cacheline_aligned_in_smp DEFINE_SPINLOCK(obfs_dcache_lru_lock);
__cacheline_aligned_in_smp DEFINE_SEQLOCK(obfs_rename_lock);

static struct kmem_cache *obfs_dentry_cache __read_mostly;
#define OBFS_D_HASHBITS  obfs_d_hash_shift
#define OBFS_D_HASHMASK  obfs_d_hash_mask

static unsigned int obfs_d_hash_mask __read_mostly;
static unsigned int obfs_d_hash_shift __read_mostly;
static struct hlist_bl_head *obfs_dentry_hashtable __read_mostly;
static __initdata unsigned long obfs_dhash_entries = 0;

struct dentry_stat_t obfs_dentry_stat = {
  .age_limit = 45,
};

static DEFINE_PER_CPU(unsigned int, obfs_nr_dentry);

inline void obfs_free_dcache(struct obfs_dentry_info *dentry){
  kmem_cache_free(obfs_dentry_cache, dentry);
}
inline struct obfs_dentry_info *obfs_alloc_dcache(){
  return kmem_cache_alloc(obfs_dentry_cache, GFP_KERNEL);
}

static void __obfs_d_free(struct rcu_head *head){
  struct obfs_dentry_info *dentry = container_of(head, struct obfs_dentry_info, d_u.d_rcu);

  //kfree(dentry->d_name.name);//FIXME: need to remove when d_alloc is fixed 
  kmem_cache_free(obfs_dentry_cache, dentry);
}
//FIXME
static void obfs_d_free(struct obfs_dentry_info *dentry){
  //obfs_dentry_stat.nr_dentry--;
  this_cpu_dec(obfs_nr_dentry);
  if (!(dentry->d_flags & DCACHE_RCUACCESS)){
    __obfs_d_free(&dentry->d_u.d_rcu);
  } else {
    call_rcu(&dentry->d_u.d_rcu, __obfs_d_free);  
  }
}

static inline void obfs_dentry_rcuwalk_barrier(struct obfs_dentry_info *dentry){
  assert_spin_locked(&dentry->d_lock);
  write_seqcount_invalidate(&dentry->d_seq);
}

static inline struct hlist_bl_head *obfs_d_hash(struct obfs_dentry_info *parent,
    unsigned long hash){
  hash += ((unsigned long)parent ^ GOLDEN_RATIO_PRIME) / L1_CACHE_BYTES;
  hash = hash ^ ((hash ^ GOLDEN_RATIO_PRIME) >> OBFS_D_HASHBITS);
  return obfs_dentry_hashtable + (hash & OBFS_D_HASHMASK);
}

static inline void __obfs_d_drop(struct obfs_dentry_info *dentry){
  if (!obfs_d_unhashed(dentry)){
    struct hlist_bl_head *b;
    b = obfs_d_hash(dentry->d_parent, dentry->d_name.hash);

    hlist_bl_lock(b);
    __hlist_bl_del(&dentry->d_hash);
    dentry->d_hash.pprev = NULL;
    hlist_bl_unlock(b);
    obfs_dentry_rcuwalk_barrier(dentry);
  }
}

static inline void obfs_d_drop(struct obfs_dentry_info *dentry){
  spin_lock(&dentry->d_lock);
  __obfs_d_drop(dentry);
  spin_unlock(&dentry->d_lock);
}
//FIXME: mix of 3.11 and 2.6.36 version
//alloc a new dentry, its inode is empty, its d_count=1
struct obfs_dentry_info *__obfs_d_alloc(const struct qstr *name){
  struct obfs_dentry_info *dentry;
  //char *dname;

  dentry = kmem_cache_alloc(obfs_dentry_cache, GFP_KERNEL);
  if (!dentry){
    return NULL;
  }
  //FIXME: it's better not to use this
  /*  dname = kmalloc(name->len + 1, GFP_KERNEL);
    if (!dname){
      kmem_cache_free(obfs_dentry_cache, dentry);
      return NULL;
    }*/
  //FIXME: it's better to use this
  memcpy(dentry->d_inode.xattr.i_d.d_name, name->name, name->len);
  dentry->d_inode.xattr.i_d.d_name[name->len] = '\0';
  dentry->d_name.name = dentry->d_inode.xattr.i_d.d_name;//d_name.name points to d_inode.i_d.d_name

    //clear the objno
  dentry->d_inode.stat.st_objno = 0;
  dentry->d_name.len = name->len;
  dentry->d_name.hash = name->hash;
  /*memcpy(dname, name->name, name->len);
  dname[name->len] = 0;*/

  smp_wmb();
  //dentry->d_name.name = dname;
  //printk(KERN_ERR "@__obfs_d_alloc: dname=%s\n", dentry->d_name.name);

  dentry->d_lockref.count = 1;
  dentry->d_flags = 0;
  spin_lock_init(&dentry->d_lock);
  seqcount_init(&dentry->d_seq);
  mutex_init(&dentry->i_mutex);
  mutex_init(&dentry->i_link_mutex);
  //spin_lock_init(&dentry->i_lock);
  dentry->i_ino = 0;//this means the inode that dentry point to = NULL
  dentry->d_parent = dentry;
  dentry->d_next = dentry->d_prev = NULL;
  
  INIT_HLIST_NODE(&dentry->i_hash);
  INIT_HLIST_BL_NODE(&dentry->d_hash);
  INIT_LIST_HEAD(&dentry->d_lru);
  INIT_LIST_HEAD(&dentry->d_subdirs);
  INIT_LIST_HEAD(&dentry->d_u.d_child);
  //INIT_LIST_HEAD(&dentry->d_alias);//FIXME: do we need this?

  //obfs_dentry_stat.nr_dentry++;
  this_cpu_inc(obfs_nr_dentry);
  return dentry;
}

struct obfs_dentry_info *obfs_d_alloc(struct obfs_dentry_info *parent,
    const struct qstr *name){
  struct obfs_dentry_info *dentry = __obfs_d_alloc(name);
  if (!dentry){
    return NULL;
  }
  spin_lock(&parent->d_lock);
  //increase the parent's d_count
  parent->d_lockref.count++;
  dentry->d_parent = parent;
  list_add(&dentry->d_u.d_child, &parent->d_subdirs);
  spin_unlock(&parent->d_lock);

  return dentry;
}

//release the dentry's inode
//delete the inode from fs
//release the dentry's inode, dentry has no refcount and is unhashed
static void obfs_dentry_iput(unsigned long tid, struct obfs_dentry_info *dentry)
  __releases(dentry->d_lock){
  //__releases(dentry->i_lock){
    unsigned long ino = dentry->i_ino;
    //dentry->i_ino = 0;
    spin_unlock(&dentry->d_lock);//FIXME
    if (ino){
      obfs_remove_ino_hash(dentry);//remove the ino hash
      //printk(KERN_ERR "@obfs_dentry_iput: delete_obj, ino=%lu\n", dentry->i_ino);
      if (!tid){//if we are not in transaction, create one
        tid = sys_objms_new_txn(obfs_xmode());
        mutex_lock(&dentry->i_mutex);//FIXME
        obfs_remove_link(tid, dentry);//update dentry's parent and prev and next
        dentry->i_ino = 0;
        mutex_unlock(&dentry->i_mutex);//FIXME
        sys_objms_delete(tid, ino);
        sys_objms_commit_txn(tid);
      } else {
        mutex_lock(&dentry->i_mutex);//FIXME
        obfs_remove_link(tid, dentry);//update dentry's parent and prev and next
        dentry->i_ino = 0;
        mutex_unlock(&dentry->i_mutex);
        sys_objms_delete(tid, ino);//remove the inode and its dentry
      }
    }
      //spin_unlock(&dentry->i_lock);
}

//release the dentry's inode, dentry remains in-use
static void obfs_dentry_unlink_inode(unsigned long tid, struct obfs_dentry_info *dentry)
  __releases(dentry->d_lock){
  //__releases(dentry->i_lock){
    unsigned long ino = dentry->i_ino;
    //dentry->i_ino = 0;
    //printk(KERN_ERR "@obfs_dentry_unlink_inode: delete_obj, ino=%lu\n", dentry->i_ino);
    obfs_dentry_rcuwalk_barrier(dentry);
    spin_unlock(&dentry->d_lock);//FIXME
    if (ino){
      obfs_remove_ino_hash(dentry);//remove the ino hash
      if (!tid){//if we are not in transaction, create one
        tid = sys_objms_new_txn(obfs_xmode());
        mutex_lock(&dentry->i_mutex);//FIXME
        obfs_remove_link(tid, dentry);//update dentry's parent and prev and next
    dentry->i_ino = 0;
        mutex_unlock(&dentry->i_mutex);//FIXME
        sys_objms_delete(tid, ino);
        sys_objms_commit_txn(tid);
      } else {
        mutex_lock(&dentry->i_mutex);//FIXME
        obfs_remove_link(tid, dentry);//update dentry's parent and prev and next
    dentry->i_ino = 0;
        mutex_unlock(&dentry->i_mutex);//FIXME
        sys_objms_delete(tid, ino);//remove the inode and its dentry
      }
    }

    //spin_unlock(&dentry->i_lock);
}

static void obfs_dentry_lru_add(struct obfs_dentry_info *dentry){
  if (!list_empty(&dentry->d_lru)){
    spin_lock(&obfs_dcache_lru_lock);
    list_add(&dentry->d_lru, &obfs_sbi->s_dentry_lru);
    obfs_sbi->s_nr_dentry_unused++; 
    obfs_dentry_stat.nr_unused++;
    spin_unlock(&obfs_dcache_lru_lock);
  }
}

static void __obfs_dentry_lru_del(struct obfs_dentry_info *dentry){
  list_del_init(&dentry->d_lru);
  obfs_sbi->s_nr_dentry_unused--;
  obfs_dentry_stat.nr_unused--;
}

static void obfs_dentry_lru_del(struct obfs_dentry_info *dentry){
  if (!list_empty(&dentry->d_lru)){
    spin_lock(&obfs_dcache_lru_lock);
    __obfs_dentry_lru_del(dentry);
    spin_unlock(&obfs_dcache_lru_lock);
  }
}

static struct obfs_dentry_info *obfs_d_kill(unsigned long tid, struct obfs_dentry_info *dentry,
    struct obfs_dentry_info *parent)
  __releases(dentry->d_lock)
  __releases(parent->d_lock){
  //__releases(dentry->i_lock){
  list_del(&dentry->d_u.d_child);

  dentry->d_flags |= DCACHE_DENTRY_KILLED;
  if (parent){
    spin_unlock(&parent->d_lock);
  }
  obfs_dentry_iput(tid, dentry);

  obfs_d_free(dentry);
  return parent;
}

//the caller must hold obfs_dcache_lru_lock
//FIXME
//connect dentry with its inode and insert it into the hash list
static void __obfs_d_instantiate(struct obfs_dentry_info *dentry,
    unsigned long ino){
  spin_lock(&dentry->d_lock);
  dentry->i_ino = ino;
  obfs_dentry_rcuwalk_barrier(dentry);
  spin_unlock(&dentry->d_lock);
  //fsnotify_d_instantiate(dentry, inode);//FIXME
}

void obfs_d_instantiate(struct obfs_dentry_info *dentry,
    unsigned long ino){
  //add ino to ino_hashtable
  if (ino){
    obfs_insert_ino_hash(dentry);    
  }
  //if (ino)
  //  spin_lock(&dentry->i_lock);
  __obfs_d_instantiate(dentry, ino);
  //if (ino)
  //  spin_unlock(&dentry->i_lock);
}

void obfs_d_delete(unsigned long tid, struct obfs_dentry_info *dentry){
  //are we the only user?
again:
  spin_lock(&dentry->d_lock);
  if (dentry->d_lockref.count == 1){
    /*if (!spin_trylock(&dentry->i_lock)){
      spin_unlock(&dentry->d_lock);
      cpu_relax();
      goto again;
    }*/
    obfs_dentry_unlink_inode(tid, dentry);
    return;
  }

  if (!obfs_d_unhashed(dentry)){
    __obfs_d_drop(dentry);
  }
  spin_unlock(&dentry->d_lock);
}

static void __obfs_d_rehash(struct obfs_dentry_info *dentry,
    struct hlist_bl_head *b){
  hlist_bl_lock(b);
  dentry->d_flags |= DCACHE_RCUACCESS;
  hlist_bl_add_head_rcu(&dentry->d_hash, b);
  hlist_bl_unlock(b);
}

static void _obfs_d_rehash(struct obfs_dentry_info *dentry){
  __obfs_d_rehash(dentry, obfs_d_hash(dentry->d_parent, dentry->d_name.hash));
}

void obfs_d_rehash(struct obfs_dentry_info *dentry){
  spin_lock(&dentry->d_lock);
  _obfs_d_rehash(dentry);
  spin_unlock(&dentry->d_lock);
}

//FIXME
//alloc a root dentry for the inode number given
struct obfs_dentry_info *obfs_d_make_root(unsigned long root_ino){
  struct obfs_dentry_info *res = NULL;
  if (root_ino){
    static const struct qstr name = QSTR_INIT("/", 1);//mount_point/
    res = __obfs_d_alloc(&name);
    if (res){
      //obfs_d_instantiate(res, root_ino);
      res->i_ino = root_ino;
      obfs_insert_ino_hash(res);
    }
  }
  return res;
}

//lookup dentry in the dentry cache
//the dentry's d_count will be increased
//FIXME: this is 2.6's kernel version
struct obfs_dentry_info * __obfs_d_lookup(struct obfs_dentry_info *parent,
    struct qstr *name){
  unsigned int len = name->len;
  unsigned int hash = name->hash;
  const unsigned char *str = name->name;
  struct hlist_bl_head *head = obfs_d_hash(parent, hash);//head of the hash bucket
  struct hlist_bl_node *node;
  struct obfs_dentry_info *found = NULL;
  struct obfs_dentry_info *dentry;
  //printk(KERN_ERR "@__obfs_d_lookup: name=%s,len=%d\n", name->name, len);

  rcu_read_lock();
  hlist_bl_for_each_entry_rcu(dentry, node, head, d_hash){
    if (dentry->d_name.hash != hash){
      continue;
    }

    spin_lock(&dentry->d_lock);
    if (dentry->d_parent != parent){
      goto next;
    }
    //non-existing due to RCU?
    if (obfs_d_unhashed(dentry)){//if dentry is not in the hash list
      goto next;
    }

    if (dentry->d_name.len != len){
      goto next;
    }
    if (memcmp(dentry->d_name.name, str, len)){//TODO: can be more efficient
      goto next;
    }

    dentry->d_lockref.count++;
    found = dentry;
    //printk(KERN_ERR "@__obfs_d_lookup: dentry->i_ino=%lu,mode=%o\n", dentry->i_ino, dentry->d_inode.stat.st_mode);
    spin_unlock(&dentry->d_lock);
    break;
next:
    //printk(KERN_ERR "@__obfs_d_lookup: next\n");
    spin_unlock(&dentry->d_lock);
  }
  rcu_read_unlock();

  return found;
}

//search the children of  the parent dentry for the name
struct obfs_dentry_info * obfs_d_lookup(struct obfs_dentry_info *parent,
    struct qstr *name){
  struct obfs_dentry_info *dentry = NULL;
  unsigned long seq;

  do{
    seq = read_seqbegin(&obfs_rename_lock);
    dentry = __obfs_d_lookup(parent, name);
    if (dentry){
      break;
    }
  } while (read_seqretry(&obfs_rename_lock, seq));
  return dentry;
}

static inline struct obfs_dentry_info *obfs_dentry_kill(unsigned long tid, struct obfs_dentry_info *dentry, int ref)
  __releases(dentry->d_lock){
 struct obfs_dentry_info *parent;

/* if (dentry->i_ino && !spin_trylock(&dentry->i_lock)){
relock:
   spin_unlock(&dentry->d_lock);
   cpu_relax();
   return dentry;
 }*/
 if (IS_ROOT(dentry)){
   parent = NULL;
 } else {
   parent = dentry->d_parent;
 }
 if (parent && !spin_trylock(&parent->d_lock)){
   /*if (dentry->i_ino){
     spin_unlock(&dentry->i_lock);
   }
   goto relock;*/
   spin_unlock(&dentry->d_lock);
   cpu_relax();
   return dentry;
 }

 if (ref){
   dentry->d_lockref.count--;
 }

 obfs_dentry_lru_del(dentry);
 //if it was on the hash then remove it
 __obfs_d_drop(dentry);
 return obfs_d_kill(tid, dentry, parent);
}

void obfs_dput(unsigned long tid, struct obfs_dentry_info *dentry){
  if (!dentry){
    return;
  }

  //printk(KERN_ERR "@obfs_dput: begin,ino=%lu,d_count=%d\n", dentry->i_ino, atomic_read(&dentry->d_count));
repeat:
  if (dentry->d_lockref.count == 1){
    might_sleep();
  }
  if (lockref_put_or_lock(&dentry->d_lockref)){
    return;
  }

  //now we delete the dentry
  //unreachable? get rid of it
  if (obfs_d_unhashed(dentry)){
    goto kill_it;
  }

  dentry->d_flags |= DCACHE_REFERENCED;
  obfs_dentry_lru_add(dentry); 

  dentry->d_lockref.count--;
  spin_unlock(&dentry->d_lock);
  return;

kill_it:
  //@ayu: FIXME
  //printk(KERN_ERR "@obfs_dput: kill_it,ino=%lu,name=%s\n",
  //    dentry->i_ino, dentry->d_name.name);
  dentry = obfs_dentry_kill(tid, dentry, 1);
  if (dentry){
    goto repeat;
  }
}

int __init obfs_init_dcache(){
  int loop;

  obfs_dentry_cache = KMEM_CACHE(obfs_dentry_info,
      SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | SLAB_MEM_SPREAD);
  if (obfs_dentry_cache == NULL){
    printk(KERN_ERR "#obfs: obfs_inode_init: obfs_dentry_cache init failed!\n");
    return -ENOMEM;
  } 
  //register_shrinker(&obfs_dcache_shrinker);
  obfs_dentry_hashtable = 
    alloc_large_system_hash("obfs-dentry-cache",
        sizeof(struct hlist_bl_head),
        obfs_dhash_entries,
        13,
        0,//HASH_EARLY,
        &obfs_d_hash_shift,
        &obfs_d_hash_mask,
        0, 0);

  if (obfs_dentry_hashtable == NULL){
    printk(KERN_ERR "#obfs: obfs_inode_init: obfs_dentry_hashtable init failed!\n");
    return -ENOMEM;
  }
  for (loop = 0; loop < (1U << obfs_d_hash_shift); loop++){
    INIT_HLIST_BL_HEAD(&obfs_dentry_hashtable[loop]);
  }
  return 0;
}

void obfs_destroy_dcache(){
  kmem_cache_destroy(obfs_dentry_cache);
}

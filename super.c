#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/parser.h>
#include <linux/io.h>
#include <linux/ctype.h>
#include <linux/cred.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/mman.h>
//#include <linux/fs.h>
//#include <linux/ioport.h>
#include <linux/crc32.h>
#include "obfs.h"
#include "dcache.h"

struct obfs_sb_info *obfs_sbi = NULL;
EXPORT_SYMBOL(obfs_sbi);

enum {
  Opt_size,
  Opt_xmode, Opt_mode, Opt_uid,
  Opt_gid, Opt_blocksize,
  //Opt_acl, Opt_noacl, Opt_xip,
  Opt_err_cont, Opt_err_panic, Opt_err_ro,
  Opt_err
};

static const match_table_t tokens = {
  {Opt_size, "init=%s"},
  {Opt_xmode, "xmode=strong"},
  {Opt_mode, "mode=%o"},
  {Opt_uid, "uid=%u"},
  {Opt_gid, "gid=%u"},
  //{Opt_acl, "acl"},
  //{Opt_acl, "noacl"},
  //{Opt_xip, "xip"},
  {Opt_err_cont, "errors=continue"},
  {Opt_err_panic, "errors=panic"},
  {Opt_err_ro, "errors=remount-ro"},
  {Opt_err, NULL},
};

static int obfs_parse_options(char *options, struct obfs_sb_info *sbi, bool remount){
  char *p, *rest;
  substring_t args[MAX_OPT_ARGS];
  int option;
  
  if (!options){
    return 0;
  }

  while ((p = strsep(&options, ",")) != NULL){
    int token;
    if (!(*p)){
      continue;
    }

    token = match_token(p, tokens, args);
    switch (token){
      case Opt_uid:
        if (remount){
          goto bad_opt;
        }
        if (match_int(&args[0], &option)){
          goto bad_val;
        }
        sbi->uid = make_kuid(current_user_ns(), option);
        break;
      case Opt_gid:
        if (match_int(&args[0], &option)){
          goto bad_val;
        }
        sbi->gid = make_kgid(current_user_ns(), option);
        break;
      case Opt_mode:
        if (match_octal(&args[0], &option)){
          goto bad_val;
        }
        sbi->mode = option &01777U;
        break;
      case Opt_size:
        if (remount){
          goto bad_opt;
        }
        if (!isdigit(*args[0].from)){
          goto bad_val;
        }
        sbi->initsize = memparse(args[0].from, &rest);
        //printk(KERN_ERR "@obfs:initsize=%lu\n", sbi->initsize);
        break;
      case Opt_xmode:
        set_opt(sbi->s_mount_opt, STRONG_XMODE);
        //printk(KERN_ERR "@obfs:xmode=strong\n");
        break;
      case Opt_err_panic:
        clear_opt(sbi->s_mount_opt, ERRORS_CONT);
        clear_opt(sbi->s_mount_opt, ERRORS_RO);
        set_opt(sbi->s_mount_opt, ERRORS_PANIC);
        break;
      case Opt_err_ro:
        clear_opt(sbi->s_mount_opt, ERRORS_CONT);
        clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
        set_opt(sbi->s_mount_opt, ERRORS_RO);
        break;
      case Opt_err_cont:
        clear_opt(sbi->s_mount_opt, ERRORS_RO);
        clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
        set_opt(sbi->s_mount_opt, ERRORS_CONT);
        break;
/*#ifdef CONFIG_OBFS_POSIX_ACL
      case Opt_acl:
        set_opt(sbi->s_mount_opt, POSIX_ACL);
        break;
      case Opt_noacl:
        clear_opt(sbi->s_mount_opt POSIX_ACL);
        break;
#else
      case Opt_acl:
      case Opt_noacl:
        obfs_info("(no)acl options not supported\n");
        break;
#endif
      case Opt_xip:
#ifdef CONFIG_OBFS_XIP
        if (remount){
          goto bad_opt;
        }
        set_opt(sbi->s_mount_opt, XIP);
        break;
#else
        obfs_info("xip option not supported\n");
        break;
#endif*/
      default:
        goto bad_opt;
        break;
    }
  }
  return 0;
  
bad_val:
  printk(KERN_ERR "Bad value '%s' for mount option '%s'\n", args[0].from, p);
  return -EINVAL;
bad_opt:
  printk(KERN_ERR "Bad mount option: \"%s\"\n", p);
  return -EINVAL;
}
/*
static bool obfs_check_size(struct obfs_sb_info *sbi, unsigned long size){
  unsigned long minimum_size, num_blocks;
  //space required for super block
  minimum_size = 2 << 12;
  //space required for inode table
  if (sbi->num_inodes > 0){
    num_blocks = (sbi->num_inodes >> 5) + 1;
  } else {
    num_blocks = 1;
  }
  minimum_size += num_blocks << 12;

  if (size < minimum_size){
    return false;
  } else {
    return true;
  }
}*/
/*
 * obfs_init()
 * */
static struct obfs_inode *obfs_init(struct obfs_sb_info *sbi, unsigned long size){
  unsigned long bpi, num_inodes;//, start_obj_size;
  //u64 bitmap_start;
  struct obfs_dentry_info *root_dentry;
  struct obfs_inode *root_i;
  struct obfs_super_block *super;
  int ret;
  unsigned long root_ino;
  mm_segment_t fs = get_fs();
  unsigned long tid;
 /* 
  if (!obfs_check_size(sbi, size)){
    printk(KERN_ERR "@obfs: invalid fs size\n");
    return ERR_PTR(-EINVAL);
  }

  if (!sbi->num_inodes){
    num_inodes = size / bpi;
  } else {
    num_inodes = sbi->num_inodes;
  }

  if (sbi->num_inodes && (num_inodes != sbi->num_inodes)){
    sbi->num_inodes = num_inodes;
  }*/

  tid = sys_objms_new_txn(0);
  
  //create an object for super block and name it
  set_fs(get_ds());
  sbi->start_objno = sys_objms_create(tid, NULL, 0640);
  if (!sbi->start_objno){//failed
    set_fs(fs);
    printk(KERN_ERR "@obfs: new_obj failed\n");
    ret = -ENOMEM;
    goto abort_txn;
  }
  sys_objms_set_name(tid, sbi->start_objno, "obfs");
  set_fs(fs);
  
  root_ino = sys_objms_create(tid, NULL, sbi->mode | S_IFDIR);
  if (!root_ino){
    printk(KERN_ERR "@obfs_init: new_obj failed\n");
    ret = -ENOMEM;
    goto abort_txn;
  }
  printk(KERN_ERR "@obfs_init: super_ino=%lu, root_ino=%lu\n",
      sbi->start_objno, root_ino);
  /*initialize super block*/
  super = obfs_get_super(sbi);

  /*clear out super block and inode table*/
  //memset(super, 0, start_obj_size);//FIXME: need clear out object content in allocate_obj
  //super->s_size = cpu_to_le64(size);
  //super->s_inodes_count = cpu_to_le32(num_inodes);
  //super->s_free_inodes_count = cpu_to_le32(num_inodes - 1);
  //super->s_free_inode_hint = cpu_to_le32(1);
  super->s_root_ino = cpu_to_le64(root_ino);
  super->s_magic = cpu_to_le16(OBFS_SUPER_MAGIC);
  //write super to objms
  obfs_sync_super(tid, sbi);

  //alloc root dentry in dentry cache
  root_dentry = obfs_d_make_root(root_ino);
  root_i = obfs_get_inode(root_dentry);
  //root_i->i_objno = sbi->start_objno;//initial object is inode table/root inode
  //root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
  //root_i->i_uid = cpu_to_le32(sbi->uid);
  //root_i->i_gid = cpu_to_le32(sbi->gid);
  //set the inode xattr info
  root_i->i_flags = 0;
  root_i->i_links_count = cpu_to_le16(2);
  root_i->i_type.dir.head = root_i->i_type.dir.tail = 0;
  root_i->i_d.d_parent = cpu_to_le64(root_ino);
  //obfs_sync_inode(root_i);
  //write root inode to objms
  //obfs_update_inode(root_ino, root_i);
  obfs_update_xattrs(tid, root_ino, root_i);
  //finally commit the transaction
  sys_objms_commit_txn(tid);
  //read root object's stat to root inode
  obfs_get_inode_stat(root_ino, &(root_dentry->d_inode.stat));

  sbi->s_root = root_dentry;

  return root_i;

abort_txn:
  sys_objms_abort_txn(tid);
  return ERR_PTR(ret);
}

static inline void set_default_opts(struct obfs_sb_info *sbi){
  set_opt(sbi->s_mount_opt, ERRORS_CONT);
}

static void obfs_root_check(struct obfs_inode *root_oi){
  if (root_oi->i_d.d_next){
    obfs_warn("root->next not NULL, trying to fix\n");
    goto fail1;
  }
/*
  if (!S_ISDIR(le16_to_cpu(root_oi->i_mode))){
    obfs_warn("root is not a directory, trying to fix\n");
    goto fail2;
  }

  if (obfs_calc_checksum((u8 *)root_oi, OBFS_INODE_SIZE)){
    obfs_warn("checksum error in root inode, trying to fix\n");
    goto fail3;
  }*/
fail1:
  root_oi->i_d.d_next = 0;
/*fail2:
  root_oi->i_mode = cpu_to_le16(S_IRWXUGO | S_ISVTX | S_IFDIR);
fail3:
  root_oi->i_d.d_parent = cpu_to_le64(OBFS_ROOT_INO);*/
}

//data: mount options
//dir_name: mount point
static int obfs_fill_super(void *data, const char *dir_name){
//static int obfs_fill_super(void *data, unsigned long silent){
  //u32 random = 0;
  struct obfs_sb_info *sbi;
  struct obfs_super_block *super;
  struct obfs_inode *root_oi;
  unsigned long initsize = 0;
  int retval = -EINVAL;
  unsigned long root_ino = 0;
  mm_segment_t fs = get_fs();

  obfs_sbi = kzalloc(sizeof(struct obfs_sb_info), GFP_KERNEL);
  if (!obfs_sbi){
    return -ENOMEM;
  }
  sbi = obfs_sbi;

  set_default_opts(sbi);

  mutex_init(&sbi->s_lock);
  INIT_LIST_HEAD(&sbi->s_dentry_lru);

  //get_random_bytes(&random, sizeof(u32));
  //atomic_set(&sbi->next_generation, random);

  /*init with default values*/
  sbi->mode = (S_IRWXUGO | S_ISVTX);
  sbi->uid = current_fsuid();
  sbi->gid = current_fsgid();
  sbi->mount_point = kmalloc(strlen(dir_name) + 1, GFP_KERNEL);
  if (!sbi->mount_point){
    retval = -ENOMEM; 
    goto out;
  } else {
    memcpy(sbi->mount_point, dir_name, strlen(dir_name) + 1);
    printk(KERN_ERR "@obfs: sbi->mount_point = %s\n", sbi->mount_point);
  }

  if (obfs_parse_options(data, sbi, 0)){
    goto out;
  }

  initsize = sbi->initsize;
  //printk(KERN_ERR "@obfs:initsize=%lu\n", initsize);

  /*init a new obfs instance*/
  if (initsize){
    root_oi = obfs_init(sbi, initsize);
    if (IS_ERR(root_oi)){
      printk(KERN_ERR "@obfs: obfs_init failed!\n");
      goto out;
    }
    goto check_obfs;//ok
  }
  //get super block object by its name
  set_fs(get_ds());
  sbi->start_objno = sys_objms_get_objno("obfs");
  set_fs(fs);
  if (!sbi->start_objno){//not found
    printk(KERN_ERR "@obfs: obfs not found!\n");
    retval = -1;
    goto out;
  } else {//read the attributes of the root object(super and inode table)
    struct obj_stat stat;
    set_fs(get_ds());
    sys_objms_obj_stat(sbi->start_objno, &stat);
    set_fs(fs);
    sbi->blocksize = stat.st_blksize;
    sbi->blocksize_bits = fls(sbi->blocksize) - 1;
  }
  printk(KERN_ERR "@obfs: obfs found, sbi->blocksize=%lu", sbi->blocksize);
  super = obfs_get_super(sbi);
  set_fs(get_ds());
  sys_objms_read(0, sbi->start_objno, (char *)super, sizeof(struct obfs_super_block), 0);
  set_fs(fs);

  root_ino = le64_to_cpu(super->s_root_ino);
  //FIXME: should we read root obj in this function?
  sbi->s_root = obfs_d_make_root(root_ino);
  if (!sbi->s_root){
    printk(KERN_ERR "@obfs: s_root = NULL!\n");
    retval = -ENOMEM;
    goto out;
  } else {
    printk(KERN_ERR "@obfs: s_root != NULL!\n");
    root_oi = obfs_get_inode(sbi->s_root);
    obfs_get_inode_stat(root_ino, &(sbi->s_root->d_inode.stat));
  }
  obfs_root_check(root_oi);

  printk(KERN_ERR "@obfs_fill_super: super_ino=%lu, root_ino=%lu\n",
      sbi->start_objno, root_ino);
check_obfs:
 
  printk(KERN_ERR "@obfs: obfs_fill_super returned successfully!\n");
  retval = 0;
  return retval;

out:
  kfree(sbi);
  return retval;
}

/*
 * syscall: sys_obfsmount()
 * */
//SYSCALL_DEFINE5(obfsmount, char __user *, dev_name, char __user *, dir_name, char __user *, type, unsigned long, flags, void __user *, data){
//SYSCALL_DEFINE2(obfs_mount, void __user *, data, char __user *, dir_name){
int obfs_mount(const char __user *dir_name, void *data){
  int ret;
	struct filename *kernel_dir;
  //unsigned long data_page;

  kernel_dir = getname(dir_name);
	if (IS_ERR(kernel_dir)) {
		ret = PTR_ERR(kernel_dir);
		goto out_dir;
	}
 /* 
  ret = copy_mount_options(data, &data_page);
  if (ret < 0){
    goto out_data;
  }
*/
  ret = obfs_fill_super(data, kernel_dir->name);
  printk(KERN_ERR "@obfs_fill_super: dir_name = %s\n", kernel_dir->name);
/*
  free_page(data_page);
out_data:*/
	putname(kernel_dir);
out_dir:
  return ret;
}
EXPORT_SYMBOL(obfs_mount);

static int __init init_obfs(void){
  int rc = 0;

  printk(KERN_ERR "@obfs: init_obfs() start\n");
  rc = obfs_init_dcache();
  rc = obfs_init_ihashtable();
  if (rc){
    printk(KERN_ERR "@obfs: failed!\n");
  } else {
    printk(KERN_ERR "@obfs: init_obfs() succeed!\n");
  }
  return rc;
}

static void __exit exit_obfs(void){
  obfs_destroy_dcache();
}

MODULE_AUTHOR("Ayu");
MODULE_DESCRIPTION("Object based File System");
MODULE_LICENSE("GPL");

module_init(init_obfs)
module_exit(exit_obfs)

//File operations for directories
//
#include <linux/slab.h>
#include "obfs.h"
#include "dcache.h"

//FIXME: parent is locked
//add dentry to the head of its parent
int obfs_add_link(unsigned long tid, struct obfs_dentry_info *dentry){
	struct obfs_dentry_info *dir = obfs_dget_parent(dentry);
	struct obfs_inode *oidir, *oi;
	unsigned long head_ino, next_ino;
  int ret;
	mm_segment_t fs = get_fs();

	const char *name = dentry->d_name.name;

	int namelen = min_t(unsigned int, dentry->d_name.len, OBFS_NAME_LEN);

  oidir = obfs_get_inode(dir);
  //printk(KERN_ERR "@obfs_add_link:pino=%lu,head_ino=%lu,tail_ino=%lu,ino=%lu\n", 
  //    dir->i_ino, oidir->i_type.dir.head, oidir->i_type.dir.tail, dentry->i_ino);
	//obfs_get_xattrs(dir->i_ino, oidir);//re-read parent inode content from fs
	mutex_lock(&dir->i_link_mutex);

	//dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	head_ino = le64_to_cpu(oidir->i_type.dir.head);
  set_fs(get_ds());

  if (head_ino != 0) {
    //if next inode is in memory, we need to update it to point to the new head
    struct obfs_dentry_info *next_de = obfs_find_dentry_by_ino(head_ino);
    if (next_de){
      //printk(KERN_ERR "@obfs_add_link: next dentry exist in memory:next_ino=%lu\n", head_ino);
      next_de->d_prev = dentry;
      dentry->d_next = next_de;
    }

    next_ino = head_ino;

    //update parent directory's head_ino
		oidir->i_type.dir.head = cpu_to_le64(dentry->i_ino);

    //ret = sys_objms_setxattr(tid, dir->i_ino, &(oidir->i_type.dir.head),
    //    offsetof(struct obfs_inode, i_type.dir.head), sizeof(__le64));
	} else {
    //update parent directory's head_ino and tail_ino
		/* the directory is empty */
		next_ino = 0;

		oidir->i_type.dir.head = cpu_to_le64(dentry->i_ino);
		oidir->i_type.dir.tail = cpu_to_le64(dentry->i_ino);
    //ret = sys_objms_setxattr(tid, dir->i_ino, &(oidir->i_type.dir),
    //    offsetof(struct obfs_inode, i_type.dir), sizeof(oidir->i_type.dir));
	}
  //printk(KERN_ERR "@obfs_add_link: name=%s, namelen=%d,next_ino=%lu\n",
   //   name, namelen, next_ino);
  //use oi as obfs_inode xattr's write buffer
  oi = obfs_get_inode(dentry);
  oi->i_d.d_next = cpu_to_le64(next_ino);
	oi->i_d.d_parent = cpu_to_le64(dir->i_ino);
	memcpy(oi->i_d.d_name, name, namelen);
	oi->i_d.d_name[namelen] = '\0';

  //obfs_update_dentry_xattr(dentry->i_ino, &(oi->i_d));
  //we need to write the last '\0'?
  //update inode's extra fields and dentry together
  ret = sys_objms_setxattr(tid, dentry->i_ino, oi,
      0, offsetof(struct obfs_inode, i_d.d_name) + namelen + 1);

  //update dentry before parent dir
  if (next_ino){
    ret = sys_objms_setxattr(tid, dir->i_ino, &(oidir->i_type.dir.head),
        offsetof(struct obfs_inode, i_type.dir.head), sizeof(__le64));
  } else {
    ret = sys_objms_setxattr(tid, dir->i_ino, &(oidir->i_type.dir),
        offsetof(struct obfs_inode, i_type.dir), sizeof(oidir->i_type.dir));
  }
  set_fs(fs);
  //printk(KERN_ERR "@obfs_add_link_end: head=%lu,tail=%lu,ret=%d\n",
   //   oidir->i_type.dir.head, oidir->i_type.dir.tail, ret);
	mutex_unlock(&dir->i_link_mutex);
  obfs_dput(tid, dir);
	return 0;
}
//FIXME: update inode in-memory and in-fs
int obfs_remove_link(unsigned long tid, struct obfs_dentry_info *dentry)
{
	//struct super_block *sb = inode->i_sb;
	//struct obfs_inode *prev = NULL;
	//struct obfs_inode *next = NULL;
	struct obfs_inode *oidir, *oi;
	struct obfs_dentry_info *dir = NULL;
  //unsigned long dentry_ino = dentry->d_inode.stat.st_objno;
  int ret;
	mm_segment_t fs = get_fs();

  oi = obfs_get_inode(dentry);

	//dir = obfs_dget(inode->i_sb, le64_to_cpu(oi->i_d.d_parent));
	dir = obfs_dget_parent(dentry);

  oidir = obfs_get_inode(dir);
  //printk(KERN_ERR "@obfs_remove_link begin:pino=%lu, ino=%lu,head=%lu,tail=%lu\n",
  //    dir->i_ino, dentry->i_ino, oidir->i_type.dir.head, oidir->i_type.dir.tail);
  //TODO: lock the parent
	mutex_lock(&dir->i_link_mutex);

  set_fs(get_ds());
  //@ayu: data=ordered mode, we need to log the pointers
  /*if (!obfs_xmode()){
    sys_objms_xcntl(OBJMS_XMODE_SET, OBJMS_XSTRONG);
  }*/
	if (dentry->i_ino == le64_to_cpu(oidir->i_type.dir.head)) {
		/* first inode in directory */
    //printk(KERN_ERR "@ino=head:%lu,next=%lu,prev=%lu\n",
     //   dentry->i_ino, oi->i_d.d_next, oi->i_d.d_prev);
     //if it is not the only subdir
     //printk(KERN_ERR "@ino=%lu,tail=%lu\n", dentry->i_ino, le64_to_cpu(oidir->i_type.dir.tail));
		if (dentry->i_ino != le64_to_cpu(oidir->i_type.dir.tail)) {//inode's next dentry be the oidir's head subdentry
      //if next inode is in memory, then we need to update it too
      //struct obfs_dentry_info *next_de = obfs_find_dentry_by_ino(oi->i_d.d_next);
      struct obfs_dentry_info *next_de = dentry->d_next;
      if (next_de){
        next_de->d_prev = NULL;
      }

			oidir->i_type.dir.head = oi->i_d.d_next;
      ret = sys_objms_setxattr(tid, dir->i_ino, &(oi->i_d.d_next),
          offsetof(struct obfs_inode, i_type.dir.head), sizeof(__le64));
		} else {
      oidir->i_type.dir.head = oidir->i_type.dir.tail = 0;
      ret = sys_objms_setxattr(tid, dir->i_ino, &(oidir->i_type.dir),
          offsetof(struct obfs_inode, i_type.dir), sizeof(oidir->i_type.dir));
    }
	} else if (dentry->i_ino == le64_to_cpu(oidir->i_type.dir.tail)) {
		/* last inode in directory */
    //if previous inode is in memory, then we need to update it too
    struct obfs_dentry_info *prev_de = dentry->d_prev;
    if (prev_de){
      prev_de->d_next = NULL;
    }

    //printk(KERN_ERR "@ino=tail:%lu,next=%lu,prev=%lu\n",
     //   inode->i_ino, oi->i_d.d_next, oi->i_d.d_prev);

		oidir->i_type.dir.tail = prev_de->i_ino;
    ret = sys_objms_setxattr(tid, dir->i_ino, &(prev_de->i_ino),
        offsetof(struct obfs_inode, i_type.dir.tail), sizeof(__le64));
	} else {
		/* somewhere in the middle */
    //printk(KERN_ERR "@obfs_remove_link: ino=middle:%lu,next=%lu,prev=%lu\n",
    //    dentry->i_ino, oi->i_d.d_next, oi->i_d.d_prev);
		//if (oi->i_d.d_next) {//always true
      //if previous inode is in memory, then we need to update it too
      struct obfs_dentry_info *prev_de = dentry->d_prev;
      struct obfs_dentry_info *next_de = dentry->d_next;
      struct obfs_inode *prev_oi = obfs_get_inode(prev_de);
      if (prev_de){
        prev_de->d_next = next_de;
      }
      if (next_de){
        next_de->d_prev = prev_de;
      }
      prev_oi->i_d.d_next = next_de->i_ino;

      ret = sys_objms_setxattr(tid, prev_de->i_ino, &(oi->i_d.d_next),
          offsetof(struct obfs_inode, i_d.d_next), sizeof(__le64));
		//}
	}
  /*if (!obfs_xmode()){
    sys_objms_xcntl(OBJMS_XMODE_SET, OBJMS_XWEAK);
  }*/
  //we do not need to write the deleted inode's dir info
/*
	oi->i_d.d_next = oi->i_d.d_prev = oi->i_d.d_parent = 0;
  ret = sys_objms_setxattr(dentry->i_ino, &(oi->i_d),
      //offsetof(struct obfs_inode, i_d), sizeof(oi->i_d));
      offsetof(struct obfs_inode, i_d), 24);
*/
  set_fs(fs);
	mutex_unlock(&dir->i_link_mutex);
	obfs_dput(tid, dir);

  dentry->d_inode.stat.st_objno = 0;
	return 0;
}

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)
//FIXME: unfinished
int obfs_readdir(struct file *file, struct dir_context *ctx){
  struct obfs_dentry_info *dentry = obfs_convert_to_obfs_dentry(file->f_path.dentry);
	struct obfs_inode *oi;
  struct obfs_dentry_info *tmpdentry;
	int namelen, ret = 0;
	char *name;
	ino_t ino;
  bool needfree = false;

  ctx->pos = file->f_pos;
  oi = obfs_get_inode(dentry);
  if (unlikely(IS_DEADDIR(oi))){
    return -ENOENT;
  }

	switch ((u32)file->f_pos) {
	case 0:
    //printk(KERN_ERR "@obfs_readdir: (.),ino=%lu\n", dentry->i_ino);
    ret = (ctx->actor(ctx, ".", 1, ctx->pos,
        dentry->i_ino, DT_DIR) == 0);
		ctx->pos = 1;
    goto out;
	case 1:
		ret = dir_emit(ctx, "..", 2, le64_to_cpu(oi->i_d.d_parent),
			      DT_DIR);
		//mutex_lock(&dentry->i_link_mutex);
		ino = le64_to_cpu(oi->i_type.dir.head);
		//mutex_unlock(&dentry->i_link_mutex);
		ctx->pos = ino ? ino : 2;
    //printk(KERN_ERR "@obfs_readdir: (..),ino=%lu\n", ino);
    goto out;
	case 2://first sub dentry
		//mutex_lock(&dentry->i_link_mutex);
		ino = le64_to_cpu(oi->i_type.dir.head);
    //printk(KERN_ERR "@obfs_readdir: case 2,ino=%lu\n", ino);
		if (ino) {
			ctx->pos = ino;
      tmpdentry = obfs_find_dentry_by_ino(ino);
      if (!tmpdentry){
        dentry = obfs_alloc_dcache();
        oi = obfs_get_inode(tmpdentry);
        obfs_get_xattrs(ino, obfs_get_inode(tmpdentry));
        needfree = true;
      }
      oi = obfs_get_inode(tmpdentry);
			break;
		} else {
			// the directory is empty 
			ctx->pos = 2;
			//mutex_unlock(&dentry->i_link_mutex);
      ret = 0;
      goto out;
		}
	case 3://end sub dentry
    //printk(KERN_ERR "@obfs_readdir: end\n");
		return 0;
	default://next sub dentry
		//mutex_lock(&dentry->i_link_mutex);
		ino = file->f_pos;
    //printk(KERN_ERR "@obfs_readdir: case default, ino=%lu\n", ino);
    tmpdentry = obfs_find_dentry_by_ino(ino);
    if (!tmpdentry){
      dentry = obfs_alloc_dcache();
      oi = obfs_get_inode(tmpdentry);
      obfs_get_xattrs(ino, obfs_get_inode(tmpdentry));
      needfree = true;
    }
    oi = obfs_get_inode(tmpdentry);

		break;
	}

  //TODO: this is not gonna happen
	while (oi && !le16_to_cpu(oi->i_links_count)) {//skip invalid oi(i_links_count=0)
		ino = ctx->pos = le64_to_cpu(oi->i_d.d_next);
    tmpdentry = obfs_find_dentry_by_ino(ino);//FIXME:
    if (!tmpdentry){
      oi = NULL;
      break;
    }
    oi = obfs_get_inode(tmpdentry);
	}

	if (oi) {
    //printk(KERN_ERR "@obfs_readdir: oi\n");
		name = oi->i_d.d_name;
		namelen = strlen(name);

		ret = dir_emit(ctx, name, namelen,
			      ino, IF2DT(le16_to_cpu(tmpdentry->d_inode.stat.st_mode)));
    //if this is not the last dentry
    if (ino != obfs_get_inode(dentry)->i_type.dir.tail){
      ctx->pos  = oi->i_d.d_next;
    } else {
      ctx->pos = 3;
    }
		//ctx->pos = oi->i_d.d_next ? le64_to_cpu(oi->i_d.d_next) : 3;
    if (needfree){
      obfs_free_dcache(tmpdentry);
    }
	} else {
		ctx->pos = 3;
  }

	//mutex_unlock(&PRAM_I(inode)->i_link_mutex);
  //printk(KERN_ERR "@pram_readdir: end\n");
out:
  file->f_pos = ctx->pos;
  //file_accessed(file);
	return ret;
}
EXPORT_SYMBOL(obfs_readdir);

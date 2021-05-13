#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
//#include <linux/smp_lock.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/fdtable.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/obj.h>
#include <linux/obfs_def.h>
#include "obfs.h"
//#include<linux/syscalls.h>
//#include<asm/unistd.h>
//#include<file.h>
//#include<linux/fs.h>

loff_t obfs_llseek(struct file *file, loff_t offset, int whence){
  /*
  if (whence != SEEK_DATA && whence != SEEK_HOLE){
    //return generic_file_llseek(file, offset, whence);
    return 0;
  }
  switch (whence){
    case SEEK_DATA:
      retval = obfs_find_region(inode, &offset, 0);
      if (retval){
        return retval;
      }
      break;
    case SEEK_HOLE:
      retval = obfs_find_region(inode, &offset, 1);
      if (retval){
        return retval;
      }
      break;
  }*/

  //offset = vfs_setpos(file, offset, obfs_sbi->s_maxbytes);
  offset = vfs_setpos(file, offset, MAX_LFS_FILESIZE);
  return offset;
}
EXPORT_SYMBOL(obfs_llseek);
//@ayu: obfs_def
/*
SYSCALL_DEFINE3(obfs_lseek, unsigned int, fd, off_t, offset, unsigned int, whence){
  off_t retval;
  struct fd f = fdget(fd);
  if (!f.file){
    return -EBADF;
  }

  retval = -EINVAL;
  if (whence <= SEEK_MAX
      && f.file->f_mode & FMODE_LSEEK){
    loff_t res = obfs_llseek(f.file, offset, whence);
    retval = res;
    if (res != (loff_t)retval){
      retval = -EOVERFLOW;
    }
  }
  fdput(f);
  return retval;
}

static inline struct file * obfs_fcheck_files(struct files_struct *files, unsigned int fd){
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);
	//fix
	//file = fdt->fd[fd];
	//return file;
	
	if (fd < fdt->max_fds)
		file = rcu_dereference_check_fdtable(files, fdt->fd[fd]);
	return file;
}


struct file *obfs_fget_light(unsigned int fd, int *fput_needed){
	struct file *file;
	struct files_struct *files = current->files;

	*fput_needed = 0;
	//printk("obfs_fget_light called \n");
	if (likely((atomic_read(&files->count) == 1))) {
		//printk("obfs_fget_light called files->count == 1\n");
		file = obfs_fcheck_files(files, fd);
    if (file && (file->f_mode & FMODE_PATH)){
      file = NULL;
    }
	} else {
		rcu_read_lock();
		//printk("obfs_fget_light called files->count != 1\n");
		file = obfs_fcheck_files(files, fd);
		if (file){
			if (!(file->f_mode & FMODE_PATH)
          && atomic_long_inc_not_zero(&file->f_count)){
				*fput_needed = 1;
      } else {
				file = NULL;
      }
		}
		
		rcu_read_unlock();
	}

	return file;
}

static inline struct fd obfs_fdget(unsigned int fd){
  int b;
  struct file *f = obfs_fget_light(fd, &b);
  return (struct fd){f, b};
}
*/
#define MAX_RW_COUNT (INT_MAX & PAGE_CACHE_MASK)
//permission check
int obfs_rw_verify_area(int read_write, struct file *file, loff_t *ppos, size_t count){
/*
	struct inode *inode;
	loff_t pos;
	int retval = -EINVAL;

	inode = file->f_path.dentry->d_inode;
	if (unlikely((ssize_t) count < 0))
		return retval;
	pos = *ppos;
	if (unlikely((pos < 0) || (loff_t) (pos + count) < 0))
		return retval;

	if (unlikely(inode->i_flock && mandatory_lock(inode))) {
		retval = locks_mandatory_area(
				read_write == READ ? FLOCK_VERIFY_READ : FLOCK_VERIFY_WRITE,
				inode, file, pos, count);
		if (retval < 0)
			return retval;
	}
	retval = security_file_permission(file,
			read_write == READ ? MAY_READ : MAY_WRITE);
	if (retval)
		return retval;
		*/
	return count > MAX_RW_COUNT ? MAX_RW_COUNT : count;

}

/*static void wait_on_retry_sync_kiocb(struct kiocb *iocb)
{
	set_current_state(TASK_UNINTERRUPTIBLE);
	if (!kiocbIsKicked(iocb))
		schedule();
	else
		kiocbClearKicked(iocb);
	__set_current_state(TASK_RUNNING);
}*/
//obfs_def
/*
static inline loff_t file_pos_read(struct file *file){
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos){
	file->f_pos = pos;
}
*/
//copy from vfs_read, communicate with objms
ssize_t obfs_read(struct file *file,
    char __user *buf, size_t count, loff_t *ppos){
  ssize_t ret;
  struct obfs_dentry_info *dentry;
  unsigned long tid = (unsigned long)file->private_data;

  if (!(file->f_mode &FMODE_READ)){
    return -EBADF;
  }

  //ret = obfs_rw_verify_area(READ, file, ppos, count);//FIXME: unfinished

  if (unlikely(!count)){
    return 0;
  }
  dentry = obfs_convert_to_obfs_dentry(file->f_path.dentry);
  //count = ret;
  ret = sys_objms_read(tid, dentry->i_ino, buf, count, *ppos);
  //printk(KERN_ERR "@obfs_file_read: i_ino=%lu,ret=%ld, count=%lu, pos=%lu\n",
   //   dentry->i_ino, ret, count, *ppos);
  if (likely(ret > 0)){
    *ppos += ret;
    //fsnotify_access(file);//FIXME: unfinished
    add_rchar(current, ret);
  }/* else {
    printk(KERN_ERR "@obfs_file_read: objms_read_obj failed, ret = %ld,count=%lu,pos=%lu\n", ret, count, *ppos);
  }*/
  inc_syscr(current);

  return ret;
}
EXPORT_SYMBOL(obfs_read);

//copy from vfs_write, communicate with objms
ssize_t obfs_write(struct file *file,
    const char __user *buf, size_t count, loff_t *ppos){
  ssize_t ret;
  struct obfs_dentry_info *dentry;
  unsigned long tid = (unsigned long)file->private_data;

  if (unlikely(!(file->f_mode & FMODE_WRITE))){
    return -EBADF;
  }
  //handle other check to objms

  if (unlikely(!count)){
    return 0;
  }
  dentry = obfs_convert_to_obfs_dentry(file->f_path.dentry);
  //printk(KERN_ERR "@obfs_write: objno=%lu, st_objno=%lu\n",
  //    dentry->i_ino, dentry->d_inode.stat.st_objno);
  //ret = obfs_rw_verify_area(WRITE, file, ppos, count);//FIXME: unfinished
  //count = ret;
  //tid = sys_objms_new_transaction(obfs_xmode() | OBJMS_XAUTO);
  //tid = sys_objms_new_txn(obfs_xmode());
  //mutex_lock(&dentry->i_mutex);//FIXME: lock the dentry's inode before writing, objms has locked the obj

  //printk(KERN_ERR "@obfs_file_write: ino=%lu, pos=%lu,count=%lu\n",
  //    dentry->i_ino, *ppos, count);
  ret = sys_objms_write(tid, dentry->i_ino, buf, count, *ppos);
  if (likely(ret == count)){
    *ppos += ret;
    //sys_objms_commit_txn(tid);
    //FIXME: now modify the in-memory inode's time and size
    if (*ppos > le32_to_cpu(dentry->d_inode.stat.st_size)){
      dentry->d_inode.stat.st_size = *ppos;
    }
    //printk(KERN_ERR "#obfs_file_write: objms_write_obj succeed, ret = %d\n", ret);
    //fsnotify_modify(file);//FIXME: unfinished
    add_wchar(current, ret);
  }/* else {
    sys_objms_abort_txn(tid);
  }*/
  inc_syscw(current);
  //mutex_unlock(&dentry->i_mutex);

  return ret;
}
EXPORT_SYMBOL(obfs_write);
//the read syscall
/*SYSCALL_DEFINE3(obfs_read, unsigned int, fd, char __user *, buf, size_t, count){
  struct fd f = fdget(fd);
	ssize_t ret = -EBADF;

    //printk(KERN_ERR "#obfs_read: start\n");
	if (f.file){
    struct obfs_dentry_info *dentry;
		loff_t pos = file_pos_read(f.file);
    //printk(KERN_ERR "#obfs_read: obfs_file_read start, pos = %lld\n", pos);
    dentry = obfs_convert_to_obfs_dentry((f.file)->f_path.dentry);
		ret = obfs_file_read(dentry, buf, count, &pos);
    if (ret > 0){
      //printk(KERN_ERR "#obfs_read: obfs_file_read succeed\n");
      file_pos_write(f.file, pos);
    }
    fdput(f);
	} else {
    printk(KERN_ERR "#obfs_read: f.file = NULL\n");
  }
	return ret;
}
//the write syscall
SYSCALL_DEFINE3(obfs_write, unsigned int, fd, const char __user *, buf, size_t, count){
  struct fd f = fdget(fd);
	ssize_t ret = -EBADF;

    //printk(KERN_ERR "#obfs_write: start\n");
	if (f.file){
    struct obfs_dentry_info *dentry;
		loff_t pos = file_pos_read(f.file);
    //printk(KERN_ERR "#obfs_write: obfs_file_write start, pos = %lld\n", pos);
    dentry = obfs_convert_to_obfs_dentry((f.file)->f_path.dentry);
		ret = obfs_file_write(dentry, buf, count, &pos);
    if (ret > 0){
    //printk(KERN_ERR "#obfs_write: obfs_file_write succeed\n");
      file_pos_write(f.file, pos);
    }
    fdput(f);
	} else {
    printk(KERN_ERR "#obfs_write: f.file = NULL\n");
  }
	return ret;
}

*/
//@ayu: TODO
int obfs_fsync(struct file *file, int datasync){
  return 0;
}
EXPORT_SYMBOL(obfs_fsync);

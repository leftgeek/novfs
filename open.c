#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fsnotify.h>
#include <linux/fdtable.h>
#include <linux/obfs_def.h>
#include "obfs.h"
#include "namei.h"
#include "dcache.h"

static int do_dentry_open(struct file *f, const struct cred *cred){
  static const struct file_operations empty_fops = {};
  struct obfs_dentry_info *dentry;

  f->f_mode = OPEN_FMODE(f->f_flags) | FMODE_LSEEK
    | FMODE_PREAD | FMODE_PWRITE;
  if (unlikely(f->f_flags & O_PATH)){
    f->f_mode = FMODE_PATH;
  }

  dentry = obfs_convert_to_obfs_dentry(f->f_path.dentry);
  obfs_dget(dentry);
  //f->f_inode = (struct inode *)&dentry->d_inode;//FIXME: to handle dnotify_flush()
  f->f_inode = (struct inode *)obfs_get_inode(dentry);//FIXME
  /*if (f->f_mode & FMODE_WRITE){
    if (!special_file(dentry->d_inode.stat.st_mode)){
      file_take_write(f);
    }
  }*/
  f->f_mapping = NULL;//FIXME

  if (unlikely(f->f_mode & FMODE_PATH)){
    f->f_op = &empty_fops;
    return 0;
  }
  f->f_op = &empty_fops;//FIXME

  f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

  return 0;
}
//finish open a file, connect file with it's dentry
int obfs_finish_open(struct file *file, struct obfs_dentry_info *dentry,
    int *opened){
  int error = 0;
  BUG_ON(*opened & FILE_OPENED);

  file->f_path.dentry = obfs_convert_to_vfs_dentry(dentry);
  error = do_dentry_open(file, current_cred());
  if (!error){
    *opened |= FILE_OPENED;
    if (file->private_data == NULL){
      //@ayu: FIXME, create auto-commit mode txn when file is opened
      file->private_data = (void *)sys_objms_new_txn(obfs_xmode() | OBJMS_XAUTO);
    }
  }
  return error;
}
//obfs_def
/*
static inline int build_open_flags(int flags, umode_t mode, struct open_flags *op){
	int lookup_flags = 0;
	int acc_mode;

	if (flags & (O_CREAT | __O_TMPFILE))
		op->mode = (mode & S_IALLUGO) | S_IFREG;
	else
		op->mode = 0;

	flags &= ~FMODE_NONOTIFY & ~O_CLOEXEC;

	
	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	if (flags & __O_TMPFILE) {
		if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
			return -EINVAL;
		acc_mode = MAY_OPEN | ACC_MODE(flags);
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	} else if (flags & O_PATH) {
		flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH;
		acc_mode = 0;
	} else {
		acc_mode = MAY_OPEN | ACC_MODE(flags);
	}

	op->open_flag = flags;

	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL)
			op->intent |= LOOKUP_EXCL;
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	op->lookup_flags = lookup_flags;
	return 0;
}

long obfs_do_sys_open(int dfd, const char __user *filename,
    int flags, umode_t mode){
  struct open_flags op;
  int fd = build_open_flags(flags, mode, &op);
  struct filename *tmp;

  if (fd){
    return fd;
  }

  tmp = getname(filename);
  if (IS_ERR(tmp)){
    return PTR_ERR(tmp);
  }

  fd = get_unused_fd_flags(flags);
  if (fd >= 0){
    struct file *f = obfs_do_filp_open(dfd, tmp, &op);
    if (IS_ERR(f)){
      //printk(KERN_ERR "#obfs_do_sys_open: obfs_do_filp_open failed\n");
      put_unused_fd(fd);
      fd = PTR_ERR(f);
    }else {
      //printk(KERN_ERR "#obfs_do_sys_open: obfs_do_filp_open succeed\n");
      //fsnotify_open(f);
      fd_install(fd, f);
    }
  }
  putname(tmp);
  return fd;
}

SYSCALL_DEFINE3(obfs_open, const char __user *, filename,
    int, flags, umode_t, mode){
  //if (force_o_largefile()){
   // flags |= O_LARGEFILE;
  //}

  return obfs_do_sys_open(AT_FDCWD, filename, flags, mode);
}
*/
static int obfs_fput(struct file *filp){
  struct obfs_dentry_info *dentry;

  put_pid(filp->f_owner.pid);//FIXME: @ayu
  dentry = obfs_convert_to_obfs_dentry(filp->f_path.dentry);
  filp->f_path.dentry = NULL;
  filp->f_path.mnt = NULL;
  filp->f_inode = NULL;
  obfs_dput((unsigned long)(filp->private_data), dentry);
  put_filp(filp);//FIXME: used this because it include file_free,
  //we can't call file_free directly because it's static

  return 0;
}

int obfs_filp_close(struct file *filp, fl_owner_t id){
  int retval = 0;
  
  if (!file_count(filp)){
    return 0;
  }
  //flush
  if (likely(!(filp->f_mode & FMODE_PATH))){
    //dnotify_flush(filp, id);
    //locks_remove_posix(filp, id);
  }
  //@ayu: FIXME, commit auto-commit mode txn when file is closed
  unsigned long tid = (unsigned long)filp->private_data;
  if (tid){
    sys_objms_commit_txn(tid);//not called in auto_commit mode
    filp->private_data = NULL;
  }
  //fput(filp);//FIXME: unfinished: cannot used vfs's
  obfs_fput(filp);
  return retval;
}
EXPORT_SYMBOL(obfs_filp_close);
//obfs_def
/*
static int __obfs_close_fd(struct files_struct *files,
    unsigned fd){
  struct file *file;
  struct fdtable *fdt;

  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);
  if (fd >= fdt->max_fds){
    goto out_unlock;
  }
  file = fdt->fd[fd];
  if (!file){
    goto out_unlock;
  }
  rcu_assign_pointer(fdt->fd[fd], NULL);
  //__clear_close_on_exec(fd, fdt);
  __clear_bit(fd, fdt->close_on_exec);
  //__put_unused_fd(files, fd);
  spin_unlock(&files->file_lock);
  put_unused_fd(fd);//FIXME: itself has a lock
  return obfs_filp_close(file, files);

out_unlock:
  //printk(KERN_ERR "#__obfs_close_fd: out_unlock\n");
  spin_unlock(&files->file_lock);
  return -EBADF;
}

SYSCALL_DEFINE1(obfs_close, unsigned int, fd){
  int retval = __obfs_close_fd(current->files, fd);

  if (unlikely(retval == -ERESTARTSYS
        || retval == -ERESTARTNOINTR
        || retval == -ERESTARTNOHAND
        || retval == -ERESTART_RESTARTBLOCK)){
    retval = -EINTR;
  }
  return retval;
}

SYSCALL_DEFINE2(obfs_creat, const char __user*, pathname, umode_t, mode){
  //return sys_obfs_open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
  return obfs_do_sys_open(AT_FDCWD, pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}*/

#ifndef _NAMEI_H
#define _NAMEI_H

#include <linux/fs.h>
#include <linux/namei.h>
#include "obfs_fs.h"

struct obfs_nameidata{
  struct obfs_dentry_info *path;
  struct qstr last;
  unsigned int flags;
  //unsigned seq;
  int last_type;
  unsigned depth;
  //char *saved_names[9];
  char *saved_names[MAX_NESTED_LINKS + 1];
};

//convert vfs dentry to obfs dentry info
/*static inline void convert_to_obfs_dentry(struct dentry *dentry,
    struct obfs_dentry_info *s_dentry){
}*/
extern struct file *obfs_nameidata_to_filp(struct obfs_nameidata *nd);

static inline void obfs_nd_set_link(struct obfs_nameidata *nd, char *path){
  nd->saved_names[nd->depth] = path;
}

static inline char *obfs_nd_get_link(struct obfs_nameidata *nd){
  return nd->saved_names[nd->depth];
}

static inline void obfs_nd_terminate_link(void *name, size_t len, size_t maxlen){
  ((char *)name)[min(len, maxlen)] = '\0';
}
#endif

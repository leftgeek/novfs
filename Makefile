#obj-$(CONFIG_OBFS) += obfs.o

#obfs-y := balloc.o dir.o inode.o namei.o super.o symlink.o ioctl.o
obj-y += obfs.o
obfs-y := super.o open.o namei.o dcache.o read_write.o inode.o dir.o

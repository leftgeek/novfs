NoVFS is a persistent memory file system bypassing Linux VFS layer
VFS maintains inode and dentry caches and hash tables for path resolution, while individual file systems also use similar techniques for directory lookup.
This can cause inefficiency in file metadata operations such as file/directory creation/deletion, especially for file systems on persistent memory.
NoVFS bypasses VFS layer and maintains a unified inode and dentry caches and hash tables, thereby improving file metadata performance.
NoVFS leverage user libraries to transparently intercept application file accesses.

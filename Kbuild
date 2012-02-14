EXTRA_CFLAGS := \
	-DCONFIG_NET_9P_DEBUG=1 \
	-I$(src)/include/net/9p \
	-I$(src)/include \
	-include $(src)/rhel6-compat.h \
	-include $(src)/include/net/9p/9p.h \
	-include $(src)/include/net/9p/client.h \
	-include $(src)/include/net/9p/transport.h

obj-m := 9pnet.o 9p.o 9pnet_rdma.o

# CONFIG_NET_9P
# CONFIG_NET_9P_VIRTIO
# CONFIG_NET_9P_RDMA
# CONFIG_NET_9P_DEBUG

9pnet-objs := \
        9p/mod.o \
        9p/client.o \
        9p/error.o \
        9p/util.o \
	9p/protocol.o\
        9p/trans_fd.o

9pnet_rdma-objs := \
	9p/trans_rdma.o

9pnet_virtio-objs := \
	9p/trans_virtio.o

# CONFIG_9P_FS
# CONFIG_9P_FSCACHE
# CONFIG_9P_FS_POSIX_ACL

9p-objs := \
	v9fs/vfs_super.o \
	v9fs/vfs_inode.o \
	v9fs/vfs_inode_dotl.o \
	v9fs/vfs_addr.o \
	v9fs/vfs_file.o \
	v9fs/vfs_dir.o \
	v9fs/vfs_dentry.o \
	v9fs/v9fs.o \
	v9fs/fid.o

#	v9fs/xattr.o
#	v9fs/xattr_user.o

EXTRA_CFLAGS := -I$(src)/include -include $(src)/external-module-compat.h
#obj-m := virtio.o virtio_pci.o virtio_ring.o 9pnet.o 9pnet_virtio.o 9p.o
obj-m := 9pnet.o 9p.o

#virtio-objs := virtio/virtio.o
#virtio_ring-objs := virtio/virtio_ring.o
#virtio_pci-objs := virtio/virtio_pci.o

9pnet-objs := \
        9p/mod.o \
        9p/client.o \
        9p/conv.o \
        9p/error.o \
        9p/fcprint.o \
        9p/util.o \
        9p/trans_fd.o \

9p-objs := v9fs/vfs_super.o v9fs/vfs_inode.o v9fs/vfs_addr.o v9fs/vfs_file.o \
	   v9fs/vfs_dir.o v9fs/vfs_dentry.o v9fs/v9fs.o v9fs/fid.o

EXTRA_CFLAGS := -I$(src)/include/net/9p -I$(src)/include -include $(src)/external-module-compat.h
obj-m := 9pnet.o 9p.o

ifeq ($(FSCACHE), 1)
        EXTRA_CFLAGS+="-DCONFIG_9P_FSCACHE"
        CONFIG_9P_FSCACHE=y
endif

ifeq ($(DEBUG9P), 1)
        EXTRA_CFLAGS+="-DCONFIG_NET_9P_DEBUG"
        CONFIG_NET_9P_DEBUG=y
endif

9pnet-objs := \
        9p/mod.o \
        9p/client.o \
        9p/error.o \
        9p/util.o \
	9p/protocol.o\
        9p/trans_fd.o \

9p-objs := v9fs/vfs_super.o v9fs/vfs_inode.o v9fs/vfs_addr.o v9fs/vfs_file.o \
	   v9fs/vfs_dir.o v9fs/vfs_dentry.o v9fs/v9fs.o v9fs/fid.o

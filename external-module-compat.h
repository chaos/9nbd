#ifndef _LINUX_EXTMOD_COMPAT_H
#define _LINUX_EXTMOD_COMPAT_H

#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

/* This is a really kludgy way to make it work. To see what
   deactivate_locked_super is all about, check the commit
   74dbbdd7fdc11763f4698d2f3e684cf4446951e6 by Al Viro */
static inline void deactivate_locked_super(struct super_block *s)
{
        up_write(&s->s_umount);
        deactivate_super(s);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

#define current_fsuid()  (current->fsuid)
#define current_fsgid()  (current->fsgid)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

struct virtio_device_id {
	__u32 device;
	__u32 vendor;
};

#define VIRTIO_DEV_ANY_ID	0xffffffff

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

#define COMPAT_kobject_uevent_env

#define sg_page(sg)	((sg)->page)

static inline void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
	memset(sgl, 0, sizeof(*sgl) * nents);
}

#define task_pid_nr(current) (0)

#define __mandatory_lock(ino) (0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#define COMPAT_request_irq
#define COMPAT_INIT_WORK
#define COMPAT_f_dentry

typedef unsigned int bool;

#define true (1)
#define false (0)

#define uninitialized_var(x) x = x

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

static inline void * __must_check krealloc(const void *data, size_t size,
					   gfp_t gfp)
{
	void *ret;

	ret = kmalloc(size, gfp);
	if (ret == NULL)
		return ret;
	memcpy(ret, data, min(size, ksize(data)));
	kfree((void *)data);

	return ret;
}

#endif
#endif
#endif

#endif
#endif
#endif

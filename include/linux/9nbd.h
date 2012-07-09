/*
 * 1999 Copyright (C) Pavel Machek, pavel@ucw.cz. This code is GPL.
 * 1999/11/04 Copyright (C) 1999 VMware, Inc. (Regis "HPReg" Duchesne)
 *            Made nbd_end_request() use the io_request_lock
 * 2001 Copyright (C) Steven Whitehouse
 *            New nbd_end_request() for compatibility with new linux block
 *            layer code.
 * 2003/06/24 Louis D. Langholtz <ldl@aros.net>
 *            Removed unneeded blksize_bits field from nbd_device struct.
 *            Cleanup PARANOIA usage & code.
 * 2004/02/19 Paul Clements
 *            Removed PARANOIA, plus various cleanup and comments
 * 2012/07/05 Jim Garlick
 *            Overhaul for 9P transport
 */

#ifndef LINUX_NBD_H
#define LINUX_NBD_H

#include <linux/types.h>

#define NBD_SET_BLKSIZE	_IO( 0xab, 1 )
#define NBD_SET_TIMEOUT _IO( 0xab, 9 )

#define NBD_SET_OPTS	_IOW( 0xab, 10, char* )
#define NBD_SET_SPEC	_IOW( 0xab, 11, char* )

#define NBD_START	_IO( 0xab, 12 )
#define NBD_STOP 	_IO( 0xab, 13 )

/* userspace doesn't need the nbd_device structure */
#ifdef __KERNEL__

#include <linux/wait.h>
#include <linux/mutex.h>

/* values for flags field */
#define NBD_READ_ONLY 0x0001
#define NBD_WRITE_NOCHK 0x0002

struct request;

struct p9_nbd_device {
	int flags;
	int magic;

	spinlock_t queue_lock;
	struct list_head waiting_queue;	/* Requests to be sent */
	wait_queue_head_t waiting_wq;

	struct task_struct *recov_kt;
	wait_queue_head_t recov_wq;

	struct gendisk *disk;
	int blksize;
	u64 bytesize;
	int p9_timeout;

	int ses_count;

	char *p9_spec;
	char *p9_opts;
};

#endif

#endif

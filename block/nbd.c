/*
 * Network block device - make block devices work over TCP
 *
 * Note that you can not swap over this thing, yet. Seems to work but
 * deadlocks sometimes - you can not swap over TCP in general.
 * 
 * Copyright 1997-2000, 2008 Pavel Machek <pavel@ucw.cz>
 * Parts copyright 2001 Steven Whitehouse <steve@chygwyn.com>
 *
 * This file is released under GPLv2 or later.
 *
 * (part of code stolen from loop.c)
 */

#include <linux/major.h>

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>
#include <asm/types.h>

#include <linux/nbd.h>
#include <net/9p/9p.h>
#include <net/9p/client.h>

#ifndef P9_DOTL_RDONLY
#define P9_DOTL_RDONLY 00000000
#endif

#define NBD_MAGIC 0x68797548

#ifdef NDEBUG
#define dprintk(flags, fmt...)
#else /* NDEBUG */
#define dprintk(flags, fmt...) do { \
	if (debugflags & (flags)) printk(KERN_DEBUG fmt); \
} while (0)
#define DBG_IOCTL       0x0004
#define DBG_INIT        0x0010
#define DBG_EXIT        0x0020
#define DBG_BLKDEV      0x0100
#define DBG_RX          0x0200
#define DBG_TX          0x0400
#define DBG_PLAN9       0x0800
#define DBG_RECOV       0x1000
static unsigned int debugflags;
#endif /* NDEBUG */

typedef enum {
	S_IDLE,		/* session (healthy) is blocked on waiting_wq */
	S_BUSY,		/* session is in the plan9 transport */
	S_FAIL,		/* session (failed) is blocked on waiting_wq */
} session_state_t;

struct session_struct {
	struct task_struct *kt;		
	struct nbd_device *nbd;
	session_state_t state;
	unsigned long start;	/* jiffies when session became busy */
	struct request *req;	/* request being processed by session */
	int num;
	struct list_head list;
};

static unsigned int nbds_max = 16;
static struct nbd_device *nbd_dev;
static int max_part;

/*
 * Use just one lock (or at most 1 per NIC). Two arguments for this:
 * 1. Each NIC is essentially a synchronization point for all servers
 *    accessed through that NIC so there's no need to have more locks
 *    than NICs anyway.
 * 2. More locks lead to more "Dirty cache line bouncing" which will slow
 *    down each lock to the point where they're actually slower than just
 *    a single lock.
 * Thanks go to Jens Axboe and Al Viro for their LKML emails explaining this!
 */
static DEFINE_SPINLOCK(nbd_lock);

#ifndef NDEBUG
static const char *ioctl_cmd_to_ascii(int cmd)
{
	switch (cmd) {
	case NBD_SET_SOCK: return "set-sock";
	case NBD_SET_BLKSIZE: return "set-blksize";
	case NBD_SET_SIZE: return "set-size";
	case NBD_DO_IT: return "do-it";
	case NBD_CLEAR_SOCK: return "clear-sock";
	case NBD_CLEAR_QUE: return "clear-que";
	case NBD_PRINT_DEBUG: return "print-debug";
	case NBD_SET_SIZE_BLOCKS: return "set-size-blocks";
	case NBD_DISCONNECT: return "disconnect";
	case NBD_SET_SPEC: return "set-spec";
	case NBD_SET_OPTS: return "set-opts";
	case NBD_START: return "start";
	case NBD_STOP: return "stop";
	case BLKROSET: return "set-read-only";
	case BLKFLSBUF: return "flush-buffer-cache";
	}
	return "unknown";
}

#endif /* NDEBUG */

static void nbd_end_request(struct request *req)
{
	int error = req->errors ? -EIO : 0;
	struct request_queue *q = req->q;
	unsigned long flags;

	dprintk(DBG_BLKDEV, "%s: request %p: %s\n", req->rq_disk->disk_name,
			req, error ? "failed" : "done");

	spin_lock_irqsave(q->queue_lock, flags);
	__blk_end_request_all(req, error);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static int plan9_parseopt (char *opts, char *key, char **valp)
{
	char *cpy, *options, *k, *v;
	int err = 0;

	if (!opts)
		return -ESRCH;
	cpy = kstrdup(opts, GFP_KERNEL);
	if (!cpy)
		return -ENOMEM;
	options = cpy;
	while ((k = strsep(&options, ",")) != NULL) {
		if (!(v = strchr(k, '=')))
			continue;
		*v++ = '\0';
		if (!strcmp(k, key))
			break;
	}
	if (!k) {
		err = -ESRCH;
		goto error;
	}
	*valp = kstrdup(v, GFP_KERNEL);
	if (!*valp) {
		err = -ENOMEM;
		goto error;
	}
	kfree (cpy);
	return 0;

error:
	if (cpy)
		kfree(cpy);
	return err;
}

#ifndef P9_DOTL_RDONLY
#define P9_DOTL_RDONLY 00000000
#endif
#if 0
static int plan9_getsize(struct nbd_device *nbd, struct p9_fid *fid)
{
	struct p9_stat_dotl *sb;

	dprintk(DBG_PLAN9, "%s: p9_client_getattr_dotl\n",
		nbd->disk->disk_name);
	sb = p9_client_getattr_dotl(fid, P9_STATS_SIZE);
	if (IS_ERR(sb))
		return PTR_ERR(sb);
	nbd->bytesize = sb->st_size;
	nbd->bytesize &= ~((u64)nbd->blksize-1);

	return 0;
}
#endif
static int plan9_attach(struct nbd_device *nbd, struct p9_fid **fp)
{
	struct p9_client *clnt = NULL;
	struct p9_fid *fid = NULL;
	int err;

	char *aname = NULL;
	
	err = plan9_parseopt(nbd->plan9_opts, "aname", &aname);
	if (err < 0)
		goto error;
	dprintk(DBG_PLAN9, "%s: p9_client_create %s %s\n",
		nbd->disk->disk_name, nbd->plan9_spec, nbd->plan9_opts);
	clnt = p9_client_create(nbd->plan9_spec, nbd->plan9_opts);
	if (IS_ERR(clnt)) {
		err = PTR_ERR(clnt);
		clnt = NULL;
		goto error;
	}
	if (clnt->msize - P9_IOHDRSZ < nbd->blksize) {
		err = -EINVAL;
		goto error;
	}
	if (clnt->proto_version != p9_proto_2000L) {
		err = -EINVAL;
		goto error;
	}
	dprintk(DBG_PLAN9, "%s: p9_client_attach %s\n", nbd->disk->disk_name,
		aname);
	fid = p9_client_attach(clnt, NULL, NULL, 0, aname);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		fid = NULL;
		goto error;
	}
	kfree(aname);
	*fp = fid;
	return 0;
error: 
	if (fid)
		(void)p9_client_clunk(fid);
	if (clnt)
		p9_client_destroy(clnt);
	if (aname)
		kfree(aname);
	return err;
}

static void plan9_detach(struct nbd_device *nbd, struct p9_fid *fid)
{
	struct p9_client *clnt = fid->clnt;

	dprintk(DBG_PLAN9, "%s: p9_client_clunk\n", nbd->disk->disk_name);
	p9_client_clunk(fid);

	dprintk(DBG_PLAN9, "%s: p9_client_destroy\n", nbd->disk->disk_name);
	p9_client_destroy(clnt);
}

static int plan9_request (struct nbd_device *nbd, struct p9_fid *fid,
			  int direction, u64 offset, int length, void *buf)
{
	int n;

	do {
		if (direction == WRITE)
			n = p9_client_write(fid, buf, NULL, offset, length);
		else
			n = p9_client_read(fid, buf, NULL, offset, length);
		if (n <= 0)
			return -1;
		buf += n;
		offset += n;
		length -= n;
	} while (length > 0);
	return 0;
}

static void memcpy_fromreq(void *buf, struct request *req)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	int offset = 0;
	void *kaddr;

	rq_for_each_segment(bvec, req, iter) {
		kaddr = kmap(bvec->bv_page);
		memcpy(buf + offset, kaddr + bvec->bv_offset, bvec->bv_len);
		kunmap(bvec->bv_page);
		offset += bvec->bv_len;
	}
}

static void memcpy_toreq(struct request *req, void *buf)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	int offset = 0;
	void *kaddr;

	rq_for_each_segment(bvec, req, iter) {
		kaddr = kmap(bvec->bv_page);
		memcpy(kaddr + bvec->bv_offset, buf + offset, bvec->bv_len);
		kunmap(bvec->bv_page);
		offset += bvec->bv_len;
	}
}

#define REQ_CONNECT	ERR_PTR(-42) /* sp->req only */

/* Put session in the busy state, recording start time and in-flight request.
 */
static void session_busy(struct session_struct *sp, struct request *req)
{
	struct nbd_device *nbd = sp->nbd;

	spin_lock_irq(&nbd->queue_lock);
	sp->req = req;
	sp->start = jiffies;
	sp->state = S_BUSY;
	spin_unlock_irq(&nbd->queue_lock);
	wake_up(&nbd->recov_wq);
}

/* Put session in idle state, setting rp to completed request.
 * Return 0 on success, -1 if recov thread timed out the request and
 * returned it to the waiting_queue.
 */
static int session_idle(struct session_struct *sp, struct request **rp)
{
	struct nbd_device *nbd = sp->nbd;
	int res = -1;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->req) {
		*rp = sp->req;
		sp->req = NULL;
		sp->state = S_IDLE;
		res = 0;
	}
	spin_unlock_irq(&nbd->queue_lock);
	if (res == 0)
		wake_up(&nbd->recov_wq);
	return res;
}

/* Put session in the fail state.
 * From here, the session just waits to be cleaned up by recov thread.
 */
static void session_fail(struct session_struct *sp)
{
	struct nbd_device *nbd = sp->nbd;

	spin_lock_irq(&nbd->queue_lock);
	sp->state = S_FAIL;
	spin_unlock_irq(&nbd->queue_lock);
	wake_up(&nbd->recov_wq);
}

static int session_thread(void *data)
{
	struct session_struct *sp = data;
	struct nbd_device *nbd = sp->nbd;
	struct p9_fid *fid = NULL;
	void *buf = NULL;
	u32 bufsize = (u32)BLK_SAFE_MAX_SECTORS << 9;
	struct request *req;

	set_user_nice(current, -20);

	dprintk(DBG_RECOV, "%s: ses%d start\n", nbd->disk->disk_name, sp->num);

	session_busy(sp, REQ_CONNECT);
	if (plan9_attach(nbd, &fid) < 0)
		goto fail;
	if (session_idle(sp, &req) < 0)
		goto fail;

	session_busy(sp, REQ_CONNECT);
	if (p9_client_open(fid, P9_DOTL_RDONLY) < 0)
		goto fail;
	if (session_idle(sp, &req) < 0)
		goto fail;

	buf = kmalloc(bufsize, GFP_KERNEL);
	if (!buf) {
		dev_err(disk_to_dev(nbd->disk), "out of memory\n");
		goto fail;
	}

	while (!kthread_should_stop()) {
		wait_event_interruptible(nbd->waiting_wq, kthread_should_stop()
				|| (sp->state == S_IDLE
				    && !list_empty(&nbd->waiting_queue)));
		if (kthread_should_stop())
			continue;

		/* Dequeue request at head of block request queue.
		 * Dispense with it immediately if it requires no I/O.
 		 */
		req = NULL;
		spin_lock_irq(&nbd->queue_lock);
		if (!list_empty(&nbd->waiting_queue)) {
			req = list_entry(nbd->waiting_queue.next,
					     struct request, queuelist);
			list_del_init(&req->queuelist);
		}
		spin_unlock_irq(&nbd->queue_lock);
		if (!req)
			continue;
		if (req->cmd_type != REQ_TYPE_FS) {
			req->errors = 1;
			nbd_end_request(req);
			continue;
		}
		if (rq_data_dir(req) == WRITE && nbd->flags == NBD_READ_ONLY) {
			dev_err(disk_to_dev(nbd->disk), "Write on read-only\n");
			req->errors = 1;
			nbd_end_request(req);
			continue;
		}

		/* Perform the 9p request.
 		 */
		BUG_ON(blk_rq_bytes(req) > bufsize);
		if (rq_data_dir(req) == WRITE)
			memcpy_fromreq(buf, sp->req);
		session_busy(sp, req);
		if (plan9_request (nbd, fid, rq_data_dir(req),
				   (u64)blk_rq_pos(req) << 9,
				   blk_rq_bytes(req), buf) < 0) {
			goto fail;
		}
		if (session_idle(sp, &req) < 0)
			goto fail;
		if (rq_data_dir(req) == READ)
			memcpy_toreq(req, buf);
		req->errors = 0;
		nbd_end_request(req);
		continue;
fail:
		session_fail(sp);
	}
	if (buf)
		kfree(buf);
	if (fid)
		plan9_detach(nbd, fid); /* FIXME: could block kthread_stop() */

	dprintk(DBG_RECOV, "%s: ses%d end\n", nbd->disk->disk_name, sp->num);
	return 0;
}

static int session_create(struct nbd_device *nbd, struct session_struct **spp)
{
	struct session_struct *sp;
	int err;

	dprintk(DBG_RECOV, "%s: create ses%d\n",
		nbd->disk->disk_name, nbd->ses_count);
	sp = kcalloc(1, sizeof(*sp), GFP_KERNEL);
	if (!sp)
		return -ENOMEM;
	sp->state = S_IDLE;
	sp->req = NULL;
	sp->start = 0;
	sp->nbd = nbd;
	sp->num = nbd->ses_count;
	sp->kt = kthread_run(session_thread, sp,
			     "%s/ses%d", nbd->disk->disk_name, sp->num);
	if (IS_ERR(sp->kt)) {
		err = PTR_ERR(sp->kt);
		kfree(sp);
		return err;
	}
	nbd->ses_count++;
	*spp = sp;
	return 0;
}

static void session_destroy(struct session_struct *sp)
{
	struct nbd_device *nbd = sp->nbd;

	dprintk(DBG_RECOV, "%s: destroy ses%d\n",
		nbd->disk->disk_name, sp->num);
	kthread_stop(sp->kt);
	BUG_ON(sp->req != NULL);
	kfree(sp);
}

/* If session has been busy longer than xmit_timeout, return the
 * in-flight request to waiting_queue.  If the session gets unstuck,
 * it will find sp->req NULL and call session_fail().
 */
static int session_istimedout(struct session_struct *sp)
{
	struct nbd_device *nbd = sp->nbd;
	int res = 0;

	if (nbd->xmit_timeout == 0)
		return 0;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->state == S_BUSY && jiffies - sp->start >= nbd->xmit_timeout) {
		if (sp->req != NULL && sp->req != REQ_CONNECT)
			list_add(&sp->req->queuelist, &nbd->waiting_queue);
		sp->req = NULL;
		res = 1;
	}
	spin_unlock_irq(&nbd->queue_lock);
	return res;
}

/* If session has failed, return the in-flight request to waiting_queue.
 * We can get here via a session timeout, but also directly hence the need
 * to return the in-flight request.
 */
static int session_isfailed(struct session_struct *sp)
{
	struct nbd_device *nbd = sp->nbd;
	int res = 0;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->state == S_FAIL) {
		if (sp->req != NULL && sp->req != REQ_CONNECT)
			list_add(&sp->req->queuelist, &nbd->waiting_queue);
		sp->req = NULL;
		res = 1;
	}
	spin_unlock_irq(&nbd->queue_lock);
	return res;
}

static int recov_thread(void *data)
{
	struct nbd_device *nbd = data;
	struct session_struct *sp, *n;
	LIST_HEAD(sessions);
	int count;

	dprintk(DBG_RECOV, "%s: recov start\n", nbd->disk->disk_name);
	if (session_create(nbd, &sp) == 0)
		list_add(&sp->list, &sessions);
	while (!kthread_should_stop()) {
		/* FIXME: wake up shouldn't be periodic */
		if (nbd->xmit_timeout > 0)
			wait_event_interruptible_timeout(nbd->recov_wq,
							 kthread_should_stop(),
							 nbd->xmit_timeout);
		else
			wait_event_interruptible(nbd->recov_wq,
						 kthread_should_stop());
		if (kthread_should_stop())
			continue;
		/* time out or fail active sessions */
		count = 0;
		list_for_each_entry_safe(sp, n, &sessions, list) {
			if (session_isfailed(sp)) {
				list_del_init(&sp->list);
				session_destroy(sp);
			} else if (!session_istimedout(sp))
				count++;
		}
		/* create new session if needed */
		if (count == 0 && session_create(nbd, &sp) == 0)
			list_add(&sp->list, &sessions);
	}
	dprintk(DBG_RECOV, "%s: recov end", nbd->disk->disk_name);
	list_for_each_entry_safe(sp, n, &sessions, list) {
		list_del_init(&sp->list);
		session_destroy(sp);
	}
	return 0;
}

/* copy requests to tail of 'waiting_queue' and wake 'waiting_wq'
 */
static void do_nbd_request(struct request_queue *q)
{
	struct request *req;
	
	while ((req = blk_fetch_request(q)) != NULL) {
		struct nbd_device *nbd;

		spin_unlock_irq(q->queue_lock);

		dprintk(DBG_BLKDEV, "%s: request %p: dequeued (flags=%x)\n",
				req->rq_disk->disk_name, req, req->cmd_type);

		nbd = req->rq_disk->private_data;

		BUG_ON(nbd->magic != NBD_MAGIC);

		spin_lock_irq(&nbd->queue_lock);
		list_add_tail(&req->queuelist, &nbd->waiting_queue);
		spin_unlock_irq(&nbd->queue_lock);

		wake_up_all(&nbd->waiting_wq);

		spin_lock_irq(q->queue_lock);
	}
}

static int __nbd_ioctl(struct block_device *bdev, struct nbd_device *nbd,
		       unsigned int cmd, unsigned long arg)
{
	switch (cmd) {

	case NBD_SET_SOCK:
	case NBD_DO_IT:
	case NBD_CLEAR_SOCK:
	case NBD_CLEAR_QUE:
	case NBD_DISCONNECT:
	case NBD_PRINT_DEBUG:
		return -EINVAL;
 
	case NBD_SET_BLKSIZE:
		nbd->blksize = arg;
		nbd->bytesize &= ~(nbd->blksize-1);
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;

	case NBD_SET_SIZE:
		nbd->bytesize = arg & ~(nbd->blksize-1);
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;

	case NBD_SET_TIMEOUT:
		nbd->xmit_timeout = arg * HZ;
		return 0;

	case NBD_SET_SIZE_BLOCKS:
		nbd->bytesize = ((u64) arg) * nbd->blksize;
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;


	case NBD_SET_SPEC: {
		const char __user *ustr = (const char __user *)arg;
		int err;

		if (nbd->plan9_spec)
			kfree(nbd->plan9_spec);          
		nbd->plan9_spec = strndup_user(ustr, PAGE_SIZE);
		if (IS_ERR(nbd->plan9_spec)) {
			err = PTR_ERR(nbd->plan9_spec);
			nbd->plan9_spec = NULL;
			return err;
		}
		return 0;
	}

	case NBD_SET_OPTS: {
		const char __user *ustr = (const char __user *)arg;
		int err;

		if (nbd->plan9_opts)
			kfree(nbd->plan9_opts);          
		nbd->plan9_opts = strndup_user(ustr, PAGE_SIZE);
		if (IS_ERR(nbd->plan9_opts)) {
			err = PTR_ERR(nbd->plan9_opts);
			nbd->plan9_opts = NULL;
			return err;
		}
		return 0;
	}

	case NBD_START: {
		int err;

		if (nbd->recov_kt)
			return -EBUSY;
		if (max_part > 0) {
#if RHEL6_COMPAT
			mutex_lock(&bdev->bd_mutex);
			bdev->bd_disk->flags |= GENHD_FL_INVALIDATED;
			mutex_unlock(&bdev->bd_mutex);
#else
			bdev->bd_invalidated = 1;
#endif
		}
		nbd->recov_kt = kthread_run(recov_thread, nbd,
					    "%s/recov", nbd->disk->disk_name);
		if (IS_ERR(nbd->recov_kt)) {
			err = PTR_ERR(nbd->recov_kt);
			nbd->recov_kt = NULL;
			return err;
		}
		return 0;
	}

	case NBD_STOP:
		if (!nbd->recov_kt)
			return -EINVAL;
		if (nbd->recov_kt)
			kthread_stop(nbd->recov_kt);
		nbd->recov_kt = NULL;
		nbd->bytesize = 0;
		bdev->bd_inode->i_size = 0;
		set_capacity(nbd->disk, 0);
		if (max_part > 0)
			ioctl_by_bdev(bdev, BLKRRPART, 0);
		return 0;

	}

	return -ENOTTY;
}

static int nbd_ioctl(struct block_device *bdev, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	struct nbd_device *nbd = bdev->bd_disk->private_data;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	BUG_ON(nbd->magic != NBD_MAGIC);

	/* Anyone capable of this syscall can do *real bad* things */
	dprintk(DBG_IOCTL, "%s: nbd_ioctl cmd=%s(0x%x) arg=%lu\n",
		nbd->disk->disk_name, ioctl_cmd_to_ascii(cmd), cmd, arg);

	error = __nbd_ioctl(bdev, nbd, cmd, arg);

	return error;
}

static const struct block_device_operations nbd_fops =
{
	.owner =	THIS_MODULE,
	.ioctl =	nbd_ioctl,
};

/*
 * And here should be modules and kernel interface 
 *  (Just smiley confuses emacs :-)
 */

static int __init nbd_init(void)
{
	int err = -ENOMEM;
	int i;
	int part_shift;

	if (max_part < 0) {
		printk(KERN_ERR "nbd: max_part must be >= 0\n");
		return -EINVAL;
	}

	nbd_dev = kcalloc(nbds_max, sizeof(*nbd_dev), GFP_KERNEL);
	if (!nbd_dev)
		return -ENOMEM;

	part_shift = 0;
	if (max_part > 0) {
		part_shift = fls(max_part);

		/*
		 * Adjust max_part according to part_shift as it is exported
		 * to user space so that user can know the max number of
		 * partition kernel should be able to manage.
		 *
		 * Note that -1 is required because partition 0 is reserved
		 * for the whole disk.
		 */
		max_part = (1UL << part_shift) - 1;
	}

	if ((1UL << part_shift) > DISK_MAX_PARTS)
		return -EINVAL;

	if (nbds_max > 1UL << (MINORBITS - part_shift))
		return -EINVAL;

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = alloc_disk(1 << part_shift);
		if (!disk)
			goto out;
		nbd_dev[i].disk = disk;
		/*
		 * The new linux 2.5 block layer implementation requires
		 * every gendisk to have its very own request_queue struct.
		 * These structs are big so we dynamically allocate them.
		 */
		disk->queue = blk_init_queue(do_nbd_request, &nbd_lock);
		if (!disk->queue) {
			put_disk(disk);
			goto out;
		}
		/*
		 * Tell the block layer that we are not a rotational device
		 */
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, disk->queue);
	}

	if (register_blkdev(NBD_MAJOR, "nbd")) {
		err = -EIO;
		goto out;
	}

	printk(KERN_INFO "nbd: registered device at major %d\n", NBD_MAJOR);
	dprintk(DBG_INIT, "nbd: debugflags=0x%x\n", debugflags);

	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].magic = NBD_MAGIC;
		nbd_dev[i].flags = 0;
		INIT_LIST_HEAD(&nbd_dev[i].waiting_queue);
		spin_lock_init(&nbd_dev[i].queue_lock);
		init_waitqueue_head(&nbd_dev[i].waiting_wq);
		nbd_dev[i].xmit_timeout = 10 * HZ;
		nbd_dev[i].blksize = 4096;
		nbd_dev[i].bytesize = 0;
		nbd_dev[i].plan9_spec = NULL;
		nbd_dev[i].plan9_opts = NULL;
		nbd_dev[i].recov_kt = NULL;
		init_waitqueue_head(&nbd_dev[i].recov_wq);
		disk->major = NBD_MAJOR;
		disk->first_minor = i << part_shift;
		disk->fops = &nbd_fops;
		disk->private_data = &nbd_dev[i];
		sprintf(disk->disk_name, "nbd%d", i);
		set_capacity(disk, 0);
		add_disk(disk);
	}

	return 0;
out:
	while (i--) {
		blk_cleanup_queue(nbd_dev[i].disk->queue);
		put_disk(nbd_dev[i].disk);
	}
	kfree(nbd_dev);
	return err;
}

static void __exit nbd_cleanup(void)
{
	int i;
	for (i = 0; i < nbds_max; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].magic = 0;
		if (disk) {
			del_gendisk(disk);
			blk_cleanup_queue(disk->queue);
			put_disk(disk);
		}
		if (nbd_dev[i].plan9_spec)
			kfree(nbd_dev[i].plan9_spec);
		if (nbd_dev[i].plan9_opts)
			kfree(nbd_dev[i].plan9_opts);
		if (nbd_dev[i].recov_kt)
			kthread_stop(nbd_dev[i].recov_kt);
	}
	unregister_blkdev(NBD_MAJOR, "nbd");
	kfree(nbd_dev);
	printk(KERN_INFO "nbd: unregistered device at major %d\n", NBD_MAJOR);
}

module_init(nbd_init);
module_exit(nbd_cleanup);

MODULE_DESCRIPTION("Network Block Device");
MODULE_LICENSE("GPL");

module_param(nbds_max, int, 0444);
MODULE_PARM_DESC(nbds_max, "number of network block devices to initialize (default: 16)");
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "number of partitions per device (default: 0)");
#ifndef NDEBUG
module_param(debugflags, int, 0644);
MODULE_PARM_DESC(debugflags, "flags for controlling debug output");
#endif

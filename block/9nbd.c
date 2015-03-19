/*
 * 9P Network block device - make block devices work over 9P
 *
 * Note that you can not swap over this thing, yet. Seems to work but
 * deadlocks sometimes - you can not swap over TCP in general.
 *
 * 9P support added by Jim Garlick <garlick@llnl.gov>
 * Copyright 1997-2000, 2008 Pavel Machek <pavel@ucw.cz>
 * Parts copyright 2001 Steven Whitehouse <steve@chygwyn.com>
 *
 * This file is released under GPLv2 or later.
 *
 * (part of code stolen from loop.c and nbd.c)
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
#include <linux/capability.h>
#include <linux/key.h>
#include <keys/user-type.h>

#include <asm/uaccess.h>
#include <asm/types.h>

#include <linux/9nbd.h>
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
#define DBG_AUTH	0x2000
static unsigned int debugflags;
#endif /* NDEBUG */

typedef enum {
	S_IDLE,		/* session (healthy) is blocked on waiting_wq */
	S_BUSY,		/* session is in the plan9 transport */
	S_FAIL,		/* session (failed) is blocked on waiting_wq */
} session_state_t;

struct session_struct {
	struct task_struct *kt;
	struct p9_nbd_device *nbd;
	session_state_t state;
	unsigned long start;	/* jiffies when session became busy */
	struct request *req;	/* request being processed by session */
	int num;
	struct list_head list;
	const char *reason;
};

#define REQ_SPECIAL		ERR_PTR(-42)

static void session_busy_setreq(struct session_struct *sp, struct request *req);
static void session_busy(struct session_struct *sp);
static int session_cont(struct session_struct *sp);
static int session_idle(struct session_struct *sp);
static int session_idle_getreq(struct session_struct *sp, struct request **rp);
static int session_idle_setsize(struct session_struct *sp, u64 filesize);
static void session_fail(struct session_struct *sp);

static unsigned int max_devs = 4;
static struct p9_nbd_device *nbd_dev;
static int max_part;
static int nbd_major = 0;

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
	case NBD_SET_BLKSIZE: return "set-blksize";
	case NBD_SET_TIMEOUT: return "set-timeout";
	case NBD_SET_ADDR: return "set-addr";
	case NBD_SET_OPTS: return "set-opts";
	case NBD_SET_PATH: return "set-path";
	case NBD_START: return "start";
	case NBD_STOP: return "stop";
	case BLKROSET: return "set-read-only";
	case BLKFLSBUF: return "flush-buffer-cache";
	}
	return "unknown";
}

#endif /* NDEBUG */

static void nbd_end_request(struct request *req, int errnum)
{
	struct request_queue *q = req->q;
	unsigned long flags;

	dprintk(DBG_BLKDEV, "%s: request %p: %d\n", req->rq_disk->disk_name,
			req, errnum);

	req->errors =  (errnum == 0) ? 0 : 1;
	spin_lock_irqsave(q->queue_lock, flags);
	__blk_end_request_all(req, errnum);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

/* Get value of key from comma-delimited option list.
 * Caller must kfree value.
 */
static int plan9_parseopt_str (char *opts, char *key, char **valp)
{
	char *cpy, *options, *k, *v;
	int err = 0;

	if (!opts)
		return -ESRCH;
	if (!(cpy = kstrdup(opts, GFP_KERNEL)))
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
	if (!(*valp = kstrdup(v, GFP_KERNEL))) {
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

static int plan9_parseopt_int(char *opts, char *key, int *vp)
{
	int err;
	char *s;

	err = plan9_parseopt_str(opts, key, &s);
	if (err < 0)
		return err;
	*vp = (int)simple_strtol(s, NULL, 10);
	kfree(s);
	return 0;
}

static int plan9_create(struct session_struct *sp, struct p9_client **cp)
{
	struct p9_nbd_device *nbd = sp->nbd;
	struct p9_client *clnt = NULL;
	int err;

	dprintk(DBG_PLAN9, "%s: p9_client_create %s %s\n",
		nbd->disk->disk_name, nbd->p9_addr, nbd->p9_opts);
	session_busy(sp);
	clnt = p9_client_create(nbd->p9_addr, nbd->p9_opts);
	if (IS_ERR(clnt))
		return PTR_ERR(clnt);
	if (clnt->msize - P9_IOHDRSZ < nbd->blksize) {
		err = -EINVAL;
		goto error;
	}
	if (clnt->proto_version != p9_proto_2000L) {
		err = -EINVAL;
		goto error;
	}
	if (session_idle(sp) < 0) {
		err = -ETIMEDOUT;
		goto error;
	}
	*cp = clnt;
	return 0;
error:
	if (clnt)
		p9_client_destroy(clnt);
	return err;
}

static int plan9_attach(struct session_struct *sp, struct p9_client *clnt,
			struct p9_fid *afid, kuid_t uid, char *aname,
			struct p9_fid **fp)
{
	struct p9_nbd_device *nbd = sp->nbd;
	struct p9_fid *fid = NULL;
	int err;

	dprintk(DBG_PLAN9, "%s: p9_client_attach %s\n", nbd->disk->disk_name,
		aname);
	session_busy(sp);
	fid = p9_client_attach(clnt, afid, NULL, uid, aname);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		fid = NULL;
		goto error;
	}
	if (session_idle(sp) < 0) {
		err = -ETIMEDOUT;
		goto error;
	}
	*fp = fid;
	return 0;
error:
	if (fid)
		p9_client_clunk(fid);
	return err;
}

static int plan9_getsize(struct session_struct *sp, struct p9_fid *fid)
{
	struct p9_nbd_device *nbd = sp->nbd;
	struct p9_stat_dotl *sb = NULL;
	int err;

	dprintk(DBG_PLAN9, "%s: p9_client_getattr_dotl\n",
		nbd->disk->disk_name);
	session_busy(sp);
	sb = p9_client_getattr_dotl(fid, P9_STATS_SIZE);
	if (IS_ERR(sb)) {
		err = PTR_ERR(sb);
		sb = NULL;
		goto error;
	}
	if (session_idle_setsize(sp, sb->st_size) < 0) {
		err = -ETIMEDOUT;
		goto error;
	}
	kfree(sb);
	return 0;
error:
	if (sb)
		kfree(sb);
	return 0;
}

static int plan9_open(struct session_struct *sp, struct p9_fid *fid)
{
	struct p9_nbd_device *nbd = sp->nbd;
	int err;

	dprintk(DBG_PLAN9, "%s: p9_client_open\n", nbd->disk->disk_name);
	session_busy(sp);
	err = p9_client_open(fid, P9_DOTL_RDONLY);
	if (err < 0)
		return err;
	if (session_idle(sp) < 0)
		return -ETIMEDOUT;
	return 0;
}

static void memcpy_fromreq(void *buf, struct request *req)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	int off = 0;
	void *kaddr;

	rq_for_each_segment(bvec, req, iter) {
		kaddr = kmap(bvec->bv_page);
		memcpy(buf + off, kaddr + bvec->bv_offset, bvec->bv_len);
		kunmap(bvec->bv_page);
		off += bvec->bv_len;
	}
}

static void memcpy_toreq(struct request *req, void *buf)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	int off = 0;
	void *kaddr;

	rq_for_each_segment(bvec, req, iter) {
		kaddr = kmap(bvec->bv_page);
		memcpy(kaddr + bvec->bv_offset, buf + off, bvec->bv_len);
		kunmap(bvec->bv_page);
		off += bvec->bv_len;
	}
}

static int _p9_ioreq(struct p9_fid *fid, int dir, void *buf, u64 off, int len)
{
	int n;

	if (dir == WRITE) {
		n = p9_client_write(fid, buf, NULL, off, len);
	} else {
		n = p9_client_read(fid, buf, NULL, off, len);
		if (n == 0)
			return -EIO;
	}
	return n;
}

static int plan9_request (struct session_struct *sp, struct p9_fid *fid,
			  void *buf, struct request *req, int *ep)
{
	u64 off = (u64)blk_rq_pos(req) << 9;
	int dir = rq_data_dir(req);
	int len = blk_rq_bytes(req);
	int n, tot = 0, err = 0;

	if (dir == WRITE)
		memcpy_fromreq(buf, req);
	session_busy_setreq(sp, req);
	req = NULL;/* reminder not to access until after session_idle_getreq */
	do {
		n = _p9_ioreq(fid, dir, buf + tot, off + tot, len - tot);
		if (n < 0) {
			err = n;
			goto error;
		}
		tot += n;
		if (tot < len && session_cont(sp) < 0) {
			err = -ETIMEDOUT;
			goto error;
		}
	} while (tot < len);
	if (session_idle_getreq(sp, &req) < 0) {
		err = -ETIMEDOUT;
		goto error;
	}
	if (dir == READ)
		memcpy_toreq(req, buf);
	*ep = 0;
	return 0;
error:
	switch (err) {
		case -EROFS:
		case -ENOSPC:
			if (session_idle_getreq(sp, &req) < 0)
				return -ETIMEDOUT;
			*ep = err;
			return 0; /* only fail the block request */
		default:
			return err; /* fail the session */
	}
}

static void _freewnames(int nwname, char **wnames)
{
	while (nwname > 0)
		kfree(wnames[--nwname]);
	kfree(wnames);
}

static int _path2wnames(char *path, int *np, char ***wp)
{
	char *cpy = NULL, *p, *el;
	char **wnames = NULL;
	int nwname = 0;
	int err;

	if (!(cpy = kstrdup(path, GFP_KERNEL))) {
		err = -ENOMEM;
		goto error;
	}
	if (!(wnames = kmalloc(P9_MAXWELEM * sizeof(char *), GFP_KERNEL))) {
		err = -ENOMEM;
		goto error;
	}
	p = cpy;
	while ((el = strsep(&p, "/")) != NULL) {
		if (strlen(el) == 0)
			continue;
		if (nwname == P9_MAXWELEM) {
			err = -ERANGE;
			goto error;
		}
		if (!(wnames[nwname] = kstrdup(el, GFP_KERNEL))) {
			err = -ENOMEM;
			goto error;
		}
		nwname++;
	}
	kfree(cpy);
	*np = nwname;
	*wp = wnames;
	return 0;
error:
	if (wnames)
		_freewnames(nwname, wnames);
	if (cpy)
		kfree(cpy);
	return err;
}

static int plan9_walk(struct session_struct *sp, struct p9_fid *fid)
{
	struct p9_nbd_device *nbd = sp->nbd;
	struct p9_fid *res;
	int err;
	int nwname;
	char **wnames = NULL;

	if (!nbd->p9_path)
		return 0;
	err = _path2wnames(nbd->p9_path, &nwname, &wnames);
	if (err < 0)
		goto error;
	session_busy(sp);
	res = p9_client_walk(fid, nwname, wnames, 0);
	if (session_idle(sp) < 0) {
		err = -ETIMEDOUT;
		goto error;
	}
	if (IS_ERR(res)) {
		err = PTR_ERR(res);
		goto error;
	}
	_freewnames(nwname, wnames);
	return 0;
error:
	if (wnames)
		_freewnames(nwname, wnames);
	return err;
}

static int session_thread(void *data)
{
	struct session_struct *sp = data;
	struct p9_nbd_device *nbd = sp->nbd;
	struct p9_client *clnt = NULL;
	struct p9_fid *fid = NULL;
	struct p9_fid *afid = NULL;
	void *buf = NULL;
	u32 bufsize = (u32)BLK_SAFE_MAX_SECTORS << 9;
	struct request *req;
	int err;
	int uid = 0;
	char *aname = NULL;

	set_user_nice(current, -20);

	if (sp->reason)
		printk(KERN_ERR "%s/ses%d: 9P session restart due to %s\n",
			nbd->disk->disk_name, sp->num, sp->reason);

	err = plan9_parseopt_str(nbd->p9_opts, "aname", &aname);
	if (err < 0)
		goto fail;
	(void)plan9_parseopt_int(nbd->p9_opts, "uid", &uid);

	dprintk(DBG_RECOV, "%s/ses%d: start\n", nbd->disk->disk_name, sp->num);

	if (plan9_create(sp, &clnt) < 0)
		goto fail;
	if (plan9_attach(sp, clnt, afid, make_kuid (current_user_ns (), uid),
							aname, &fid) < 0)
		goto fail;
	if (plan9_walk(sp, fid) < 0)
		goto fail;
	if (plan9_getsize(sp, fid) < 0)
		goto fail;
	if (plan9_open(sp, fid) < 0)
		goto fail;

	buf = kmalloc(bufsize, GFP_KERNEL);
	if (!buf) {
		dev_err(disk_to_dev(nbd->disk), "out of memory\n");
		goto fail;
	}

	if (sp->reason)
		printk(KERN_ERR "%s/ses%d: 9P server ok\n",
			nbd->disk->disk_name, sp->num);

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
			nbd_end_request(req, -EIO);
			continue;
		}
		if (rq_data_dir(req) == WRITE && nbd->flags == NBD_READ_ONLY) {
			dev_err(disk_to_dev(nbd->disk), "Write on read-only\n");
			nbd_end_request(req, -EIO);
			continue;
		}

		/* Perform the 9p request.
		 */
		BUG_ON(blk_rq_bytes(req) > bufsize);
		if (plan9_request (sp, fid, buf, req, &err) < 0)
			goto fail;
		nbd_end_request(req, err);
		continue;
fail:
		session_fail(sp);
	}
	if (afid) {
		dprintk(DBG_PLAN9, "%s: p9_client_clunk afid\n",
			nbd->disk->disk_name);
		p9_client_clunk(afid);
	}
	if (fid) {
		dprintk(DBG_PLAN9, "%s: p9_client_clunk fid\n",
			nbd->disk->disk_name);
		p9_client_clunk(fid);
	}
	if (clnt) {
		dprintk(DBG_PLAN9, "%s: p9_client_destroy\n",
			nbd->disk->disk_name);
		p9_client_destroy(clnt);
	}
	if (buf)
		kfree(buf);
	if (aname)
		kfree(aname);
	dprintk(DBG_RECOV, "%s/ses%d: end\n", nbd->disk->disk_name, sp->num);
	return 0;
}

static int session_create(struct p9_nbd_device *nbd,
			  struct session_struct **spp, const char *reason)
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
	sp->reason = reason;
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
	struct p9_nbd_device *nbd = sp->nbd;

	dprintk(DBG_RECOV, "%s: destroy ses%d\n",
		nbd->disk->disk_name, sp->num);
	kthread_stop(sp->kt);
	spin_lock_irq(&nbd->queue_lock);
	if (sp->req != NULL && sp->req != REQ_SPECIAL)
		list_add(&sp->req->queuelist, &nbd->waiting_queue);
	spin_unlock_irq(&nbd->queue_lock);
	kfree(sp);
}

/* Put session in the busy state, recording start time and in-flight request.
 */
static void session_busy_setreq(struct session_struct *sp, struct request *req)
{
	struct p9_nbd_device *nbd = sp->nbd;

	spin_lock_irq(&nbd->queue_lock);
	sp->req = req;
	sp->start = jiffies;
	sp->state = S_BUSY;
	spin_unlock_irq(&nbd->queue_lock);
	wake_up(&nbd->recov_wq);
}
/* Put session in the busy state, recording start time.
 * Request is set to REQ_SPECIAL indicating a block request is not flight.
 */
static void session_busy(struct session_struct *sp)
{
	struct p9_nbd_device *nbd = sp->nbd;

	spin_lock_irq(&nbd->queue_lock);
	sp->req = REQ_SPECIAL;
	sp->start = jiffies;
	sp->state = S_BUSY;
	spin_unlock_irq(&nbd->queue_lock);
	wake_up(&nbd->recov_wq);
}

/* Put session in idle state.
 * Return 0 on success, -1 if recov thread timed us out.
 */
static int session_idle(struct session_struct *sp)
{
	struct p9_nbd_device *nbd = sp->nbd;
	int res = -1;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->req) {
		BUG_ON(sp->req != REQ_SPECIAL);
		sp->req = NULL;
		sp->state = S_IDLE;
		res = 0;
	}
	spin_unlock_irq(&nbd->queue_lock);
	if (res == 0)
		wake_up(&nbd->recov_wq);
	return res;
}
/* Put session in idle state.
 * Return request (if not "stolen" by recov thread) in 'rp'.
 * Return 0 on success, -1 if recov thread timed us out.
 */
static int session_idle_getreq(struct session_struct *sp, struct request **rp)
{
	struct p9_nbd_device *nbd = sp->nbd;
	int res = -1;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->req) {
		BUG_ON(sp->req == REQ_SPECIAL);
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
/* Test for timeout without altering state, except to reset start time.
 * This is for back-to-back handling of request chunks.
 * Return 0 on success, -1 if recov thread timed us out.
 */
static int session_cont(struct session_struct *sp)
{
	struct p9_nbd_device *nbd = sp->nbd;
	int res = -1;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->req) {
		sp->start = jiffies;
		res = 0;
	}
	spin_unlock_irq(&nbd->queue_lock);
	if (res == 0)
		wake_up(&nbd->recov_wq);
	return res;
}

/* Put session in idle state.
 * Set nbd->filesize under the lock.
 * Return 0 on success, -1 if recov thread timed us out.
 */
static int session_idle_setsize(struct session_struct *sp, u64 filesize)
{
	struct p9_nbd_device *nbd = sp->nbd;
	int res = -1;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->req) {
		BUG_ON(sp->req != REQ_SPECIAL);
		sp->req = NULL;
		sp->state = S_IDLE;
		if (nbd->bytesize == 0) {
			nbd->bytesize = filesize;
			nbd->bytesize &= ~((u64)nbd->blksize - 1);
		}
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
	struct p9_nbd_device *nbd = sp->nbd;

	spin_lock_irq(&nbd->queue_lock);
	sp->state = S_FAIL;
	spin_unlock_irq(&nbd->queue_lock);
	wake_up(&nbd->recov_wq);
}

/* If session has been busy longer than p9_timeout, return the
 * in-flight request to waiting_queue.  If the session gets unstuck,
 * it will find sp->req NULL and call session_fail().
 */
static int session_istimedout(struct session_struct *sp)
{
	struct p9_nbd_device *nbd = sp->nbd;
	int res = 0;

	if (nbd->p9_timeout == 0)
		return 0;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->state == S_BUSY && jiffies - sp->start >= nbd->p9_timeout) {
		if (sp->req != NULL && sp->req != REQ_SPECIAL)
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
	struct p9_nbd_device *nbd = sp->nbd;
	int res = 0;

	spin_lock_irq(&nbd->queue_lock);
	if (sp->state == S_FAIL) {
		if (sp->req != NULL && sp->req != REQ_SPECIAL)
			list_add(&sp->req->queuelist, &nbd->waiting_queue);
		sp->req = NULL;
		res = 1;
	}
	spin_unlock_irq(&nbd->queue_lock);
	return res;
}

static int recov_thread(void *data)
{
	struct p9_nbd_device *nbd = data;
	struct session_struct *sp, *n;
	LIST_HEAD(sessions);
	int count;
	char *reason = NULL;

	dprintk(DBG_RECOV, "%s: recov start\n", nbd->disk->disk_name);
	if (session_create(nbd, &sp, reason) == 0)
		list_add(&sp->list, &sessions);
	while (!kthread_should_stop()) {
		/* FIXME: wake up shouldn't be periodic */
		if (nbd->p9_timeout > 0)
			wait_event_interruptible_timeout(nbd->recov_wq,
							 kthread_should_stop(),
							 nbd->p9_timeout);
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
				reason = "protocol failure";
			} else if (session_istimedout(sp)) {
				reason = "server not responding";
			} else {
				count++;
			}
		}
		/* create new session if needed */
		if (count == 0 && session_create(nbd, &sp, reason) == 0)
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
		struct p9_nbd_device *nbd;

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

static void clear_waiting_queue(struct p9_nbd_device *nbd)
{
	struct request *req, *n;

	spin_lock_irq(&nbd->queue_lock);
	list_for_each_entry_safe(req, n, &nbd->waiting_queue, queuelist) {
		list_del_init(&req->queuelist);
		nbd_end_request(req, -EIO);
	}
	spin_unlock_irq(&nbd->queue_lock);
}

static int _ioctl_strdup(unsigned long arg, char **sp)
{
	const char __user *ustr = (const char __user *)arg;
	char *s = NULL;

	if (ustr) {
		s = strndup_user(ustr, PAGE_SIZE);
		if (IS_ERR(s))
			return PTR_ERR(s);
	}
	if (*sp)
		kfree(*sp);
	*sp = s;
	return 0;
}

static int __nbd_ioctl(struct block_device *bdev, struct p9_nbd_device *nbd,
		       unsigned int cmd, unsigned long arg)
{
	switch (cmd) {

	case NBD_SET_BLKSIZE:
		nbd->blksize = arg;

		dprintk(DBG_IOCTL, "%s: setting blocksize to %d bytes\n",
			nbd->disk->disk_name, nbd->blksize);
		nbd->bytesize &= ~(nbd->blksize-1);
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		return 0;

	case NBD_SET_TIMEOUT:
		nbd->p9_timeout = arg * HZ;
		return 0;

	case NBD_SET_ADDR:
		return _ioctl_strdup(arg, &nbd->p9_addr);

	case NBD_SET_OPTS:
		return _ioctl_strdup(arg, &nbd->p9_opts);

	case NBD_SET_PATH:
		return _ioctl_strdup(arg, &nbd->p9_path);

	case NBD_START: {
		int err = 0;
		u64 filesize = (u64)(-1LL);

		if (nbd->recov_kt)
			return -EBUSY;
		if (max_part > 0)
			bdev->bd_invalidated = 1;
		nbd->recov_kt = kthread_run(recov_thread, nbd,
					    "%s/recov", nbd->disk->disk_name);
		if (IS_ERR(nbd->recov_kt)) {
			err = PTR_ERR(nbd->recov_kt);
			nbd->recov_kt = NULL;
			return err;
		}
		/* Wait for session to connect and obtain device size
		 * with a 9P getattr call.
		 */
		do {
			err = wait_event_interruptible(nbd->recov_wq,
						       nbd->bytesize != 0);
			if (err < 0) {
				kthread_stop(nbd->recov_kt);
				nbd->recov_kt = NULL;
				return err;
			}
			spin_lock_irq(&nbd->queue_lock);
			filesize = nbd->bytesize;
			spin_unlock_irq(&nbd->queue_lock);
		} while (filesize == (u64)(-1LL));

		dprintk(DBG_IOCTL, "%s: setting device size to %llu bytes\n",
			nbd->disk->disk_name, filesize);
		bdev->bd_inode->i_size = nbd->bytesize;
		set_blocksize(bdev, nbd->blksize);
		set_capacity(nbd->disk, nbd->bytesize >> 9);
		set_device_ro(bdev, 1);
		return 0;
	}

	case NBD_STOP:
		if (!nbd->recov_kt)
			return -EINVAL;
		kthread_stop(nbd->recov_kt);
		nbd->recov_kt = NULL;
		nbd->bytesize = 0;
		bdev->bd_inode->i_size = 0;
		set_capacity(nbd->disk, 0);
		clear_waiting_queue(nbd);
		if (max_part > 0)
			ioctl_by_bdev(bdev, BLKRRPART, 0);
		return 0;
	}

	return -ENOTTY;
}

static int nbd_ioctl(struct block_device *bdev, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	struct p9_nbd_device *nbd = bdev->bd_disk->private_data;
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
		printk(KERN_ERR "9nbd: max_part must be >= 0\n");
		return -EINVAL;
	}

	nbd_dev = kcalloc(max_devs, sizeof(*nbd_dev), GFP_KERNEL);
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

	if (max_devs > 1UL << (MINORBITS - part_shift))
		return -EINVAL;

	for (i = 0; i < max_devs; i++) {
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

	if ((nbd_major = register_blkdev(0, "9nbd")) < 0) {
		err = nbd_major;
		goto out;
	}

	printk(KERN_INFO "9nbd: registered device at major %d\n", nbd_major);
	dprintk(DBG_INIT, "9nbd: debugflags=0x%x\n", debugflags);

	for (i = 0; i < max_devs; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].magic = NBD_MAGIC;
		nbd_dev[i].flags = 0;
		INIT_LIST_HEAD(&nbd_dev[i].waiting_queue);
		spin_lock_init(&nbd_dev[i].queue_lock);
		init_waitqueue_head(&nbd_dev[i].waiting_wq);
		nbd_dev[i].p9_timeout = 10 * HZ;
		nbd_dev[i].blksize = 4096;
		nbd_dev[i].bytesize = 0;
		nbd_dev[i].p9_addr = NULL;
		nbd_dev[i].p9_opts = NULL;
		nbd_dev[i].p9_path = NULL;
		nbd_dev[i].recov_kt = NULL;
		init_waitqueue_head(&nbd_dev[i].recov_wq);
		disk->major = nbd_major;
		disk->first_minor = i << part_shift;
		disk->fops = &nbd_fops;
		disk->private_data = &nbd_dev[i];
		sprintf(disk->disk_name, "9nbd%d", i);
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
	for (i = 0; i < max_devs; i++) {
		struct gendisk *disk = nbd_dev[i].disk;
		nbd_dev[i].magic = 0;
		if (disk) {
			del_gendisk(disk);
			blk_cleanup_queue(disk->queue);
			put_disk(disk);
		}
		if (nbd_dev[i].recov_kt)
			kthread_stop(nbd_dev[i].recov_kt);
		if (nbd_dev[i].p9_addr)
			kfree(nbd_dev[i].p9_addr);
		if (nbd_dev[i].p9_opts)
			kfree(nbd_dev[i].p9_opts);
		if (nbd_dev[i].p9_path)
			kfree(nbd_dev[i].p9_path);
	}
	unregister_blkdev(nbd_major, "9nbd");
	kfree(nbd_dev);
	printk(KERN_INFO "9nbd: unregistered device at major %d\n", nbd_major);
}

module_init(nbd_init);
module_exit(nbd_cleanup);

MODULE_DESCRIPTION("Network Block Device");
MODULE_LICENSE("GPL");

module_param(max_devs, int, 0444);
MODULE_PARM_DESC(max_devs, "number of block devices to initialize (default: 16)");
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "number of partitions per device (default: 0)");
#ifndef NDEBUG
module_param(debugflags, int, 0644);
MODULE_PARM_DESC(debugflags, "flags for controlling debug output");
#endif

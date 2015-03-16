### 9nbd

`9nbd` is a network block device driver for the linux kernel.

The network block device (nbd) driver that has been in the Linux kernel for
some time associates a block special file (`/dev/nbdX`) with a remote file
or block device. A local file system image (like ext4) in the file or block
device can be mounted just like it were on a local disk on the client.
The nbd server runs in user space. The client and server communicate using
a purpose-built TCP protocol.

In `9nbd`, the protocol is replaced with 9P. The server can be
[diod](https://github.com/chaos/diod) or another 9P server.
Resiliency and strong authentication are added on top of 9P.
The 9P protocol engine and transports already in the kernel are
leveraged, simplifying the network block device implementation.

### Why is 9nbd needed?

Diod began as an I/O forwarding project for clusters. One planned use is
to improve application load times by mounting NFS servers on I/O nodes,
then remounting them on compute nodes with a 1:64 or so fanout.
During a parallel exec or other type of read, data is read from the
NFS server into the I/O node page cache on first access and is
subsequently served out of cache.

Two issues subvert this plan. One is the v9fs `cache=none` behavior, i.e.
total reliance on the I/O node page and dentry cache, which adds latency
to every operation. The other, compounded by the first, is the fact that
path search on compute nodes is synchronous (one directory at a time),
and for new names, always involves a round trip to the NFS server for
each directory searched.  The NFS cache revalidation behavior further
confounds performacne.

Intuitively one might expect the I/O node dcache to help here, and it
does with negative and positive dentries, but of course unless a name
has been looked up before, it cannot have a dentry, and applications
with many moving parts can look up a large number of new names from
essentially a cold cache. What is really needed is the buffer cache,
which would allow the full content of the directories being searched to
enter cache.

If one can manage to place the content formerly stored in NFS in a local
file system image and share it read-only, the buffer cache can be used.
For example, store a squashfs image as a single file in NFS; mount NFS
on I/O nodes; re-export via diod to compute nodes; set up 9nbd block device
on compute node; mount squashfs on compute node.

Now the buffer cache comes into play on compute nodes, dramatically
speeding up path search, and for that matter all metadata operations.
Content of the file also enters the page cache on I/O forwarding nodes.

The end result performs extremely well, eliminating a significant amount
of network traffic when compared with both direct and forwarded NFS.
The main catch is the need to place the content in a read-only container.

### Resiliency

`nbd` offers reconnection on server disconnect but does not shield clients
from I/O errors that might result during reconnection. Recovery behavior
from block level I/O errors is file system dependent, and for any given
file system, varies depending on what type of file system object is
involved. It can be fatal or it might hand an I/O error to an application.
Either is unacceptable in a parallel environment where cascading errors
can be difficult to debug and restarting is expensive.

The in-kernel 9P transport does not offer resiliency, and the 9P protocol
design offers no help. General purpose resiliency in 9P is complicated
by the fact that the server carries per-connection state that would
have to be re-established on a reconnect. That is why v9fs just gives
up when the transport gets an error and the only recourse is to
unmount/remount. It is also possible for the transport to hang forever
if a request is not answered but the connection is not completely torn down.

For `9nbd` with read-only block devices, it is fairly simple to add a
layer of resiliency on top of the 9P transport since all we are doing is
accessing a single file. We spawn a kernel thread for each 9P connection,
and if a 9P request ever fails or times out, we abort the original thread,
start a new one, and reissue the request. We can even connect to a
different server as long as it is serving the same file content.

For read-write block devices, recovery is more complicated due to write
ordering constraints, write barriers, etc., but since sharing a local
file system image requires that the contents remain static, `9nbd` only
supports recovery for read-only block devices.

### MUNGE Security

diod accepts MUNGE authentication, and for the `v9fs` file system client,
the diod mount helper achieves this by connecting to the server in user
space, performing an AUTH on the connect, then handing the connected
(and authenticated) file descriptor in to the kernel 9P transport at
mount time. This doe not work with `9nbd` since the kernel must be able
to reconnect on its own during recovery.

It turns out that obtaining munge credentials in the kernel is easy with
the kernel keyring service. The kernel calls out to user space to
generate a credential at connect time, sends it, then immediately
destroys it since munge creds are one-time use only. This required
support for the 9P AUTH message to be re-added to the kernel 9P
transport code (it had been removed in a fit of overzealous cleanup
since nothing was using it). The munge-specific code for I/O on
the resulting afid is part of 9nbd, though it probably should be moved
into the transport.

Some setup in `/etc/request-key.conf` is required to facilitate the
kernel upcall.

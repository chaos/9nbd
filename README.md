### 9nbd

`9nbd` is a network block device driver for the linux kernel.

The [nbd driver](http://en.wikipedia.org/wiki/Network_block_device)
that has been in the Linux kernel since 2.1.101 associates a block
special file, `/dev/nbdX`, with a remote file or block device.
A remote file system image is mounted from a block device backed
by `nbd` just as from a block device backed by a local disk.
`nbd-server` runs in user space and communicates with `nbd`
using a purpose-built TCP protocol.

`9nbd` is a replacement for `nbd` that uses the 9P transport instead
of the purpose-built TCP protocol.  9P has the advantage of
abstracting the protocol away from the network block device
implementation; leveraging a proven design and implementation;
supporting TCP, Infiniband RDMA, virtio, and file descriptor passing;
and allowing any 9P server,
[diod](https://github.com/chaos/diod) for example, to serve
file system images.

In addition, for read-only block device images, `9nbd` has the ability
to survive a server reboot and, if configured, to fail over to an alternate
server that has the identical block device image, without returning
errors in the block layer.   `9nbd` behavior in this regard is similar
to the familiar NFS client, except for the client-orchestrated failover
which goes beyond NFS client capabilities.

### Scalability

On clusters, serving read-only root file systems with a network block
device really shines.  Specifically, the inability of network file systems
like NFS and Lustre to cache full directories creates an environment
that is pathalogical for common idioms such as path search.  With
a network block device, the buffer cache is active, and buffer cache
entries never need to be invalidated.  This means the network can be
_dead silent_ while an application is running or when loading shared
libraries or searching for executables after a working set has been
pulled in.

### Security

The 9P transport can use a privileged port if desired, and servers
such as `diod` can restrict access based on that and an access list.
The 9P AUTH mechanism is available for extending this at the transport
level.  At LLNL we have experimented with MUNGE authentication over 9P,
though this is not currently implemented in `9nbd`.

### Diskless

`9nbd` works great for root file systems.  More details will appear here
as we integrate `9nbd` with dracut in our RHEL 7 based clusters.

### Quick How-to

Create a 4GB disk image image, bound to a loopback device:
```
# dd if=/dev/zero of=/tmp/image bs=4k count=$((1024*1024))
1048576+0 records in
1048576+0 records out
4294967296 bytes (4.3 GB) copied, 32.3354 s, 133 MB/s
# losetup /dev/loop0 /tmp/image
```

Create an ext4 file system on it:
```
# yes | mkfs.ext4 -m 0 -N 1000000 /dev/loop0
mke2fs 1.41.12 (17-May-2010)
Filesystem label=
...
180 days, whichever comes first.  Use tune2fs -c or -i to override.

# tune2fs -i 0 /dev/loop0
tune2fs 1.41.12 (17-May-2010)
Setting interval between checks to 0 seconds

# tune2fs -O ^has_journal,sparse_super /dev/loop0
tune2fs 1.41.12 (17-May-2010)

# fsck.ext4 -y /dev/loop0
e2fsck 1.41.12 (17-May-2010)
/dev/loop0: clean, 11/1000448 files, 64654/1048576 blocks
```
Mount `/dev/loop0` and copy in content, then unmount.
The file system image should not be exposed to writes while it is
being served as a network block device.

Export the image via `diod` by adding it to `/etc/diod.conf`.
```
exports = {
    { path="/tmp/image",  opts="ro,noauth" }
}
```
then `service diod reload`.

Load the `9nbd` module on the client, instantiate the block device entry,
and mount the remote file system.
```
insmod ./9nbd.ko
/sbin/mount.diod --9nbd-attach host:path /dev/9nbd0
mount -oro /dev/9nbd0 /mnt
...
umount /mnt
/sbin/mount.diod --9nbd-detach /dev/9nbd0
```

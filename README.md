# v9fs 

Out of kernel tree versions of Linux 9P modules for RHEL 6 based distros.
These versions were initially based on 2.6.38.5, but many patches were
subsequently backported from newer kernels.  Testing has been primarily
with the [_diod_](http://code.google.com/p/diod) 9P server.

A spec file is included which allows these modules to be built as
an RPM named `kmod-v9fs`.

## 9nbd

`block/9nbd` contains a network block device driver that leverages
in-kernel 9P transport support, and thus can use all of the transport
features offered by 9P, and can be served by battle-hardened 9p server
such as _diod_.

A more detailed write-up on 9nbd is available on the
[diod NBD wiki page](http://code.google.com/p/diod/wiki/9NBD).

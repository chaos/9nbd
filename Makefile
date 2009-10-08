KERNELDIR ?= /lib/modules/$(shell uname -r)/build
MODULEDIR ?= /lib/modules/$(shell uname -r)/kernel

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

fscache:
	$(MAKE) -C $(KERNELDIR) M=`pwd` FSCACHE=1 "$$@"

debug:
	$(MAKE) -C $(KERNELDIR) M=`pwd` DEBUG9P=1 "$$@"

install:
	install -v 9p.ko $(MODULEDIR)/fs/9p/
	install -v 9pnet.ko $(MODULEDIR)/net/9p/

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
	rm -f Module.symvers


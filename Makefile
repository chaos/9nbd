KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

fscache:
	$(MAKE) -C $(KERNELDIR) M=`pwd` FSCACHE=1 "$$@"

debug:
	$(MAKE) -C $(KERNELDIR) M=`pwd` DEBUG9P=1 "$$@"

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
	rm -f Module.symvers


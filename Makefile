KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` "$$@"

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
	rm -f Module.symvers


ifneq ($(KERNELRELEASE),)
agpgart-y := backend.o frontend.o generic.o isoch.o 

obj-$(CONFIG_AGP)		+= agpgart.o
obj-$(CONFIG_AGP_INTEL)		+= intel-agp.o
obj-$(CONFIG_AGP_INTEL_MCH)	+= intel-agp.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(CC) -I. -o testgart testgart.c
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif

clean:
	rm -rf *.o *.ko *.mod.c testgart .*.cmd .tmp_versions

install-agp: FORCE
	cp agpgart.ko intel-agp.ko /lib/modules/`uname -r`/kernel/drivers/char/agp
	depmod -ae
FORCE:

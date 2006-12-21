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
clean:
	rm -rf *.o *.ko *.mod.c testgart .*.cmd .tmp_versions

install: FORCE
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules_install	
endif

FORCE:

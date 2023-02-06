KMOD=bwfm
SRCS=bwfm.c if_bwfm_pci.h if_bwfm_pci.c if_bwfm_usb.c bwfmvar.h bwfmreg.h bus_if.h device_if.h

.include <bsd.kmod.mk>

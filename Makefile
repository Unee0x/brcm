KMOD=brcm
SRCS=brcm.c if_brcm_pci.h if_brcm_pci.c if_brcm_usb.c brcmvar.h brcmreg.h bus_if.h device_if.h

.include <bsd.kmod.mk>

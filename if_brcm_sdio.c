/* $OpenBSD: if_brcm_sdio.c,v 1.44 2022/04/06 18:59:30 naddy Exp $ */
/*
 * Copyright (c) 2010-2016 Broadcom Corporation
 * Copyright (c) 2016,2017 Patrick Wildt <patrick@blueri.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "bpfilter.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/pool.h>

#if defined(__HAVE_FDT)
#include <machine/fdt.h>
#include <dev/ofw/openfirm.h>
#endif

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net80211/ieee80211_var.h>

#include <dev/sdmmc/sdmmcdevs.h>
#include <dev/sdmmc/sdmmcvar.h>

#include <dev/ic/brcmvar.h>
#include <dev/ic/brcmreg.h>
#include <dev/sdmmc/if_brcm_sdio.h>

#define BRCM_SDIO_CCCR_BRCM_CARDCAP			0xf0
#define  BRCM_SDIO_CCCR_BRCM_CARDCAP_CMD14_SUPPORT	0x02
#define  BRCM_SDIO_CCCR_BRCM_CARDCAP_CMD14_EXT		0x04
#define  BRCM_SDIO_CCCR_BRCM_CARDCAP_CMD_NODEC		0x08
#define BRCM_SDIO_CCCR_BRCM_CARDCTRL			0xf1
#define  BRCM_SDIO_CCCR_BRCM_CARDCTRL_WLANRESET		0x02
#define BRCM_SDIO_CCCR_BRCM_SEPINT			0xf2

/* #define BRCM_DEBUG */
#ifdef BRCM_DEBUG
#define DPRINTF(x)	do { if (brcm_debug > 0) printf x; } while (0)
#define DPRINTFN(n, x)	do { if (brcm_debug >= (n)) printf x; } while (0)
static int brcm_debug = 1;
#else
#define DPRINTF(x)	do { ; } while (0)
#define DPRINTFN(n, x)	do { ; } while (0)
#endif

#undef DEVNAME
#define DEVNAME(sc)	((sc)->sc_sc.sc_dev.dv_xname)

enum brcm_sdio_clkstate {
	CLK_NONE,
	CLK_SDONLY,
	CLK_PENDING,
	CLK_AVAIL,
};

struct brcm_sdio_softc {
	struct brcm_softc	  sc_sc;
	struct sdmmc_function	**sc_sf;
	struct rwlock		 *sc_lock;
	void			 *sc_ih;
	int			  sc_oob;

	int			  sc_initialized;

	uint32_t		  sc_bar0;
	int			  sc_clkstate;
	int			  sc_alp_only;
	int			  sc_sr_enabled;
	uint32_t		  sc_console_addr;

	char			 *sc_bounce_buf;
	size_t			  sc_bounce_size;

	char			 *sc_console_buf;
	size_t			  sc_console_buf_size;
	uint32_t		  sc_console_readidx;

	struct brcm_core	 *sc_cc;

	uint8_t			  sc_tx_seq;
	uint8_t			  sc_tx_max_seq;
	struct mbuf_list	  sc_tx_queue;
	int			  sc_tx_count;

	struct task		  sc_task;
};

int		 brcm_sdio_match(struct device *, void *, void *);
void		 brcm_sdio_attach(struct device *, struct device *, void *);
int		 brcm_sdio_preinit(struct brcm_softc *);
int		 brcm_sdio_detach(struct device *, int);

int		 brcm_sdio_intr(void *);
int		 brcm_sdio_oob_intr(void *);
void		 brcm_sdio_task(void *);
int		 brcm_sdio_load_microcode(struct brcm_sdio_softc *,
		    u_char *, size_t, u_char *, size_t);

void		 brcm_sdio_clkctl(struct brcm_sdio_softc *,
		    enum brcm_sdio_clkstate, int);
void		 brcm_sdio_htclk(struct brcm_sdio_softc *, int, int);
void		 brcm_sdio_readshared(struct brcm_sdio_softc *);

void		 brcm_sdio_backplane(struct brcm_sdio_softc *, uint32_t);
uint8_t		 brcm_sdio_read_1(struct brcm_sdio_softc *, uint32_t);
uint32_t	 brcm_sdio_read_4(struct brcm_sdio_softc *, uint32_t);
void		 brcm_sdio_write_1(struct brcm_sdio_softc *, uint32_t,
		    uint8_t);
void		 brcm_sdio_write_4(struct brcm_sdio_softc *, uint32_t,
		    uint32_t);
int		 brcm_sdio_buf_read(struct brcm_sdio_softc *,
		    struct sdmmc_function *, uint32_t, char *, size_t);
int		 brcm_sdio_buf_write(struct brcm_sdio_softc *,
		    struct sdmmc_function *, uint32_t, char *, size_t);
uint32_t	 brcm_sdio_ram_read_write(struct brcm_sdio_softc *,
		    uint32_t, char *, size_t, int);
uint32_t	 brcm_sdio_frame_read_write(struct brcm_sdio_softc *,
		    char *, size_t, int);

uint32_t	 brcm_sdio_dev_read(struct brcm_sdio_softc *, uint32_t);
void		 brcm_sdio_dev_write(struct brcm_sdio_softc *, uint32_t,
		    uint32_t);

uint32_t	 brcm_sdio_buscore_read(struct brcm_softc *, uint32_t);
void		 brcm_sdio_buscore_write(struct brcm_softc *, uint32_t,
		    uint32_t);
int		 brcm_sdio_buscore_prepare(struct brcm_softc *);
void		 brcm_sdio_buscore_activate(struct brcm_softc *, uint32_t);

struct mbuf *	 brcm_sdio_newbuf(void);
int		 brcm_sdio_tx_ok(struct brcm_sdio_softc *);
void		 brcm_sdio_tx_frames(struct brcm_sdio_softc *);
void		 brcm_sdio_tx_ctrlframe(struct brcm_sdio_softc *, struct mbuf *);
void		 brcm_sdio_tx_dataframe(struct brcm_sdio_softc *, struct mbuf *);
void		 brcm_sdio_rx_frames(struct brcm_sdio_softc *);
void		 brcm_sdio_rx_glom(struct brcm_sdio_softc *, uint16_t *, int,
		    uint16_t *, struct mbuf_list *);

int		 brcm_sdio_txcheck(struct brcm_softc *);
int		 brcm_sdio_txdata(struct brcm_softc *, struct mbuf *);
int		 brcm_sdio_txctl(struct brcm_softc *, void *);

#ifdef BRCM_DEBUG
void		 brcm_sdio_debug_console(struct brcm_sdio_softc *);
#endif

struct brcm_bus_ops brcm_sdio_bus_ops = {
	.bs_preinit = brcm_sdio_preinit,
	.bs_stop = NULL,
	.bs_txcheck = brcm_sdio_txcheck,
	.bs_txdata = brcm_sdio_txdata,
	.bs_txctl = brcm_sdio_txctl,
};

struct brcm_buscore_ops brcm_sdio_buscore_ops = {
	.bc_read = brcm_sdio_buscore_read,
	.bc_write = brcm_sdio_buscore_write,
	.bc_prepare = brcm_sdio_buscore_prepare,
	.bc_reset = NULL,
	.bc_setup = NULL,
	.bc_activate = brcm_sdio_buscore_activate,
};

const struct cfattach brcm_sdio_ca = {
	sizeof(struct brcm_sdio_softc),
	brcm_sdio_match,
	brcm_sdio_attach,
	brcm_sdio_detach,
};

int
brcm_sdio_match(struct device *parent, void *match, void *aux)
{
	struct sdmmc_attach_args *saa = aux;
	struct sdmmc_function *sf = saa->sf;
	struct sdmmc_cis *cis;

	/* Not SDIO. */
	if (sf == NULL)
		return 0;

	/* Look for Broadcom. */
	cis = &sf->sc->sc_fn0->cis;
	if (cis->manufacturer != SDMMC_VENDOR_BROADCOM)
		return 0;

	/* Look for supported chips. */
	switch (cis->product) {
	case SDMMC_PRODUCT_BROADCOM_BCM4324:
	case SDMMC_PRODUCT_BROADCOM_BCM4329:
	case SDMMC_PRODUCT_BROADCOM_BCM4330:
	case SDMMC_PRODUCT_BROADCOM_BCM4334:
	case SDMMC_PRODUCT_BROADCOM_BCM4335:
	case SDMMC_PRODUCT_BROADCOM_BCM4339:
	case SDMMC_PRODUCT_BROADCOM_BCM4345:
	case SDMMC_PRODUCT_BROADCOM_BCM4354:
	case SDMMC_PRODUCT_BROADCOM_BCM4356:
	case SDMMC_PRODUCT_BROADCOM_BCM4359:
	case SDMMC_PRODUCT_BROADCOM_BCM43143:
	case SDMMC_PRODUCT_BROADCOM_BCM43340:
	case SDMMC_PRODUCT_BROADCOM_BCM43341:
	case SDMMC_PRODUCT_BROADCOM_BCM43362:
	case SDMMC_PRODUCT_BROADCOM_BCM43430:
	case SDMMC_PRODUCT_BROADCOM_BCM43364:
		break;
	default:
		return 0;
	}

	/* We need both functions, but ... */
	if (sf->sc->sc_function_count <= 1)
		return 0;

	/* ... only attach for one. */
	if (sf->number != 1)
		return 0;

	return 1;
}

void
brcm_sdio_attach(struct device *parent, struct device *self, void *aux)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)self;
	struct sdmmc_attach_args *saa = aux;
	struct sdmmc_function *sf = saa->sf;
	struct brcm_core *core;
	uint32_t reg;

	printf("\n");

#if defined(__HAVE_FDT)
	if (sf->cookie)
		sc->sc_sc.sc_node = *(int *)sf->cookie;
#endif

	task_set(&sc->sc_task, brcm_sdio_task, sc);
	ml_init(&sc->sc_tx_queue);
	sc->sc_bounce_size = 64 * 1024;
	sc->sc_bounce_buf = dma_alloc(sc->sc_bounce_size, PR_WAITOK);
	sc->sc_tx_seq = 0xff;

	rw_assert_wrlock(&sf->sc->sc_lock);
	sc->sc_lock = &sf->sc->sc_lock;

	sc->sc_sf = mallocarray(sf->sc->sc_function_count + 1,
	    sizeof(struct sdmmc_function *), M_DEVBUF, M_WAITOK);

	/* Copy all function pointers. */
	SIMPLEQ_FOREACH(sf, &saa->sf->sc->sf_head, sf_list) {
		sc->sc_sf[sf->number] = sf;
	}
	sf = saa->sf;

	sdmmc_io_set_blocklen(sc->sc_sf[1], 64);
	sdmmc_io_set_blocklen(sc->sc_sf[2], 512);

	/* Enable Function 1. */
	if (sdmmc_io_function_enable(sc->sc_sf[1]) != 0) {
		printf("%s: cannot enable function 1\n", DEVNAME(sc));
		goto err;
	}

	DPRINTF(("%s: F1 signature read @0x18000000=%x\n", DEVNAME(sc),
	    brcm_sdio_read_4(sc, 0x18000000)));

	/* Force PLL off */
	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR,
	    BRCM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HW_CLKREQ_OFF |
	    BRCM_SDIO_FUNC1_CHIPCLKCSR_ALP_AVAIL_REQ);

	sc->sc_sc.sc_buscore_ops = &brcm_sdio_buscore_ops;
	if (brcm_chip_attach(&sc->sc_sc) != 0) {
		printf("%s: cannot attach chip\n", DEVNAME(sc));
		goto err;
	}

	sc->sc_cc = brcm_chip_get_core(&sc->sc_sc, BRCM_AGENT_CORE_CHIPCOMMON);
	if (sc->sc_cc == NULL) {
		printf("%s: cannot find chipcommon core\n", DEVNAME(sc));
		goto err;
	}

	core = brcm_chip_get_core(&sc->sc_sc, BRCM_AGENT_CORE_SDIO_DEV);
	if (core->co_rev >= 12) {
		reg = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_SLEEPCSR);
		if (!(reg & BRCM_SDIO_FUNC1_SLEEPCSR_KSO)) {
			reg |= BRCM_SDIO_FUNC1_SLEEPCSR_KSO;
			brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_SLEEPCSR, reg);
		}
	}

	/* TODO: drive strength */

	brcm_sdio_write_1(sc, BRCM_SDIO_CCCR_BRCM_CARDCTRL,
	    brcm_sdio_read_1(sc, BRCM_SDIO_CCCR_BRCM_CARDCTRL) |
	    BRCM_SDIO_CCCR_BRCM_CARDCTRL_WLANRESET);

	core = brcm_chip_get_pmu(&sc->sc_sc);
	brcm_sdio_write_4(sc, core->co_base + BRCM_CHIP_REG_PMUCONTROL,
	    brcm_sdio_read_4(sc, core->co_base + BRCM_CHIP_REG_PMUCONTROL) |
	    (BRCM_CHIP_REG_PMUCONTROL_RES_RELOAD <<
	     BRCM_CHIP_REG_PMUCONTROL_RES_SHIFT));

	sdmmc_io_function_disable(sc->sc_sf[2]);

	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR, 0);
	sc->sc_clkstate = CLK_SDONLY;

	sc->sc_sc.sc_bus_ops = &brcm_sdio_bus_ops;
	sc->sc_sc.sc_proto_ops = &brcm_proto_bcdc_ops;
	brcm_attach(&sc->sc_sc);
	config_mountroot(self, brcm_attachhook);
	return;

err:
	free(sc->sc_sf, M_DEVBUF, 0);
}

int
brcm_sdio_preinit(struct brcm_softc *brcm)
{
	struct brcm_sdio_softc *sc = (void *)brcm;
	const char *chip = NULL;
	uint32_t clk, reg;
	u_char *ucode, *nvram;
	size_t size = 0, nvsize, nvlen = 0;

	if (sc->sc_initialized)
		return 0;

	rw_enter_write(sc->sc_lock);

	switch (brcm->sc_chip.ch_chip)
	{
	case BRCM_CC_43241_CHIP_ID:
		if (brcm->sc_chip.ch_chiprev <= 4)
			chip = "43241b0";
		else if (brcm->sc_chip.ch_chiprev == 5)
			chip = "43241b4";
		else
			chip = "43241b5";
		break;
	case BRCM_CC_4330_CHIP_ID:
		chip = "4330";
		break;
	case BRCM_CC_4334_CHIP_ID:
		chip = "4334";
		break;
	case BRCM_CC_4345_CHIP_ID:
		if (brcm->sc_chip.ch_chiprev == 9)
			chip = "43456";
		else
			chip = "43455";
		break;
	case BRCM_CC_43340_CHIP_ID:
	case BRCM_CC_43341_CHIP_ID:
		chip = "43340";
		break;
	case BRCM_CC_4335_CHIP_ID:
		if (brcm->sc_chip.ch_chiprev < 2)
			chip = "4335";
		else
			chip = "4339";
		break;
	case BRCM_CC_4339_CHIP_ID:
		chip = "4339";
		break;
	case BRCM_CC_43430_CHIP_ID:
		if (brcm->sc_chip.ch_chiprev == 0)
			chip = "43430a0";
		else if (brcm->sc_chip.ch_chiprev == 2)
			chip = "43436";
		else
			chip = "43430";
		break;
	case BRCM_CC_4356_CHIP_ID:
		chip = "4356";
		break;
	case BRCM_CC_4359_CHIP_ID:
		chip = "4359";
		break;
	default:
		printf("%s: unknown firmware for chip %s\n",
		    DEVNAME(sc), brcm->sc_chip.ch_name);
		goto err;
	}

	if (brcm_loadfirmware(brcm, chip, "-sdio", &ucode, &size,
	    &nvram, &nvsize, &nvlen) != 0)
		goto err;

	sc->sc_alp_only = 1;
	if (brcm_sdio_load_microcode(sc, ucode, size,
	    nvram, nvlen) != 0) {
		printf("%s: could not load microcode\n",
		    DEVNAME(sc));
		free(ucode, M_DEVBUF, size);
		free(nvram, M_DEVBUF, nvsize);
		goto err;
	}
	sc->sc_alp_only = 0;
	free(ucode, M_DEVBUF, size);
	free(nvram, M_DEVBUF, nvsize);

	brcm_sdio_clkctl(sc, CLK_AVAIL, 0);
	if (sc->sc_clkstate != CLK_AVAIL)
		goto err;

	clk = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR);
	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR,
	    clk | BRCM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HT);

	brcm_sdio_dev_write(sc, SDPCMD_TOSBMAILBOXDATA,
	    SDPCM_PROT_VERSION << SDPCM_PROT_VERSION_SHIFT);
	if (sdmmc_io_function_enable(sc->sc_sf[2]) != 0) {
		printf("%s: cannot enable function 2\n", DEVNAME(sc));
		goto err;
	}

	brcm_sdio_dev_write(sc, SDPCMD_HOSTINTMASK,
	    SDPCMD_INTSTATUS_HMB_SW_MASK|SDPCMD_INTSTATUS_CHIPACTIVE);
	brcm_sdio_write_1(sc, BRCM_SDIO_WATERMARK, 8);

	if (brcm_chip_sr_capable(brcm)) {
		reg = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_WAKEUPCTRL);
		reg |= BRCM_SDIO_FUNC1_WAKEUPCTRL_HTWAIT;
		brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_WAKEUPCTRL, reg);
		brcm_sdio_write_1(sc, BRCM_SDIO_CCCR_CARDCAP,
		    BRCM_SDIO_CCCR_CARDCAP_CMD14_SUPPORT |
		    BRCM_SDIO_CCCR_CARDCAP_CMD14_EXT);
		brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR,
		    BRCM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HT);
		sc->sc_sr_enabled = 1;
	} else {
		brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR, clk);
	}

#if defined(__HAVE_FDT)
	if (sc->sc_sc.sc_node) {
		sc->sc_ih = fdt_intr_establish(sc->sc_sc.sc_node,
		    IPL_NET, brcm_sdio_oob_intr, sc, DEVNAME(sc));
		if (sc->sc_ih != NULL) {
			brcm_sdio_write_1(sc, BRCM_SDIO_CCCR_SEPINT,
			    BRCM_SDIO_CCCR_SEPINT_MASK |
			    BRCM_SDIO_CCCR_SEPINT_OE |
			    BRCM_SDIO_CCCR_SEPINT_ACT_HI);
			sc->sc_oob = 1;
		}
	}
	if (sc->sc_ih == NULL)
#endif
	sc->sc_ih = sdmmc_intr_establish(brcm->sc_dev.dv_parent,
	    brcm_sdio_intr, sc, DEVNAME(sc));
	if (sc->sc_ih == NULL) {
		printf("%s: can't establish interrupt\n", DEVNAME(sc));
		brcm_sdio_clkctl(sc, CLK_NONE, 0);
		goto err;
	}
	sdmmc_intr_enable(sc->sc_sf[1]);
	rw_exit(sc->sc_lock);

	sc->sc_initialized = 1;
	return 0;

err:
	rw_exit(sc->sc_lock);
	return 1;
}

int
brcm_sdio_load_microcode(struct brcm_sdio_softc *sc, u_char *ucode, size_t size,
    u_char *nvram, size_t nvlen)
{
	struct brcm_softc *brcm = (void *)sc;
	char *verify = NULL;
	int err = 0;

	brcm_sdio_clkctl(sc, CLK_AVAIL, 0);

	/* Upload firmware */
	err = brcm_sdio_ram_read_write(sc, brcm->sc_chip.ch_rambase,
	    ucode, size, 1);
	if (err)
		goto out;

	/* Verify firmware */
	verify = malloc(size, M_TEMP, M_WAITOK | M_ZERO);
	err = brcm_sdio_ram_read_write(sc, brcm->sc_chip.ch_rambase,
	    verify, size, 0);
	if (err || memcmp(verify, ucode, size)) {
		printf("%s: firmware verification failed\n",
		    DEVNAME(sc));
		free(verify, M_TEMP, size);
		goto out;
	}
	free(verify, M_TEMP, size);

	/* Upload nvram */
	err = brcm_sdio_ram_read_write(sc, brcm->sc_chip.ch_rambase +
	    brcm->sc_chip.ch_ramsize - nvlen, nvram, nvlen, 1);
	if (err)
		goto out;

	/* Verify nvram */
	verify = malloc(nvlen, M_TEMP, M_WAITOK | M_ZERO);
	err = brcm_sdio_ram_read_write(sc, brcm->sc_chip.ch_rambase +
	    brcm->sc_chip.ch_ramsize - nvlen, verify, nvlen, 0);
	if (err || memcmp(verify, nvram, nvlen)) {
		printf("%s: nvram verification failed\n",
		    DEVNAME(sc));
		free(verify, M_TEMP, nvlen);
		goto out;
	}
	free(verify, M_TEMP, nvlen);

	/* Load reset vector from firmware and kickstart core. */
	brcm_chip_set_active(brcm, *(uint32_t *)ucode);

out:
	brcm_sdio_clkctl(sc, CLK_SDONLY, 0);
	return err;
}

void
brcm_sdio_clkctl(struct brcm_sdio_softc *sc, enum brcm_sdio_clkstate newstate,
    int pendok)
{
	enum brcm_sdio_clkstate oldstate;

	oldstate = sc->sc_clkstate;
	if (sc->sc_clkstate == newstate)
		return;

	switch (newstate) {
	case CLK_AVAIL:
		if (sc->sc_clkstate == CLK_NONE)
			sc->sc_clkstate = CLK_SDONLY;
		brcm_sdio_htclk(sc, 1, pendok);
		break;
	case CLK_SDONLY:
		if (sc->sc_clkstate == CLK_NONE)
			sc->sc_clkstate = CLK_SDONLY;
		else if (sc->sc_clkstate == CLK_AVAIL)
			brcm_sdio_htclk(sc, 0, 0);
		else
			printf("%s: request for %d -> %d\n",
			    DEVNAME(sc), sc->sc_clkstate, newstate);
		break;
	case CLK_NONE:
		if (sc->sc_clkstate == CLK_AVAIL)
			brcm_sdio_htclk(sc, 0, 0);
		sc->sc_clkstate = CLK_NONE;
		break;
	default:
		break;
	}

	DPRINTF(("%s: %d -> %d = %d\n", DEVNAME(sc), oldstate, newstate,
	    sc->sc_clkstate));
}

void
brcm_sdio_htclk(struct brcm_sdio_softc *sc, int on, int pendok)
{
	uint32_t clkctl, devctl, req;
	int i;

	if (sc->sc_sr_enabled) {
		if (on)
			sc->sc_clkstate = CLK_AVAIL;
		else
			sc->sc_clkstate = CLK_SDONLY;
		return;
	}

	if (on) {
		if (sc->sc_alp_only)
			req = BRCM_SDIO_FUNC1_CHIPCLKCSR_ALP_AVAIL_REQ;
		else
			req = BRCM_SDIO_FUNC1_CHIPCLKCSR_HT_AVAIL_REQ;
		brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR, req);

		clkctl = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR);
		if (!BRCM_SDIO_FUNC1_CHIPCLKCSR_CLKAV(clkctl, sc->sc_alp_only)
		    && pendok) {
			devctl = brcm_sdio_read_1(sc, BRCM_SDIO_DEVICE_CTL);
			devctl |= BRCM_SDIO_DEVICE_CTL_CA_INT_ONLY;
			brcm_sdio_write_1(sc, BRCM_SDIO_DEVICE_CTL, devctl);
			sc->sc_clkstate = CLK_PENDING;
			return;
		} else if (sc->sc_clkstate == CLK_PENDING) {
			devctl = brcm_sdio_read_1(sc, BRCM_SDIO_DEVICE_CTL);
			devctl &= ~BRCM_SDIO_DEVICE_CTL_CA_INT_ONLY;
			brcm_sdio_write_1(sc, BRCM_SDIO_DEVICE_CTL, devctl);
		}

		for (i = 0; i < 5000; i++) {
			if (BRCM_SDIO_FUNC1_CHIPCLKCSR_CLKAV(clkctl,
			    sc->sc_alp_only))
				break;
			clkctl = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR);
			delay(1000);
		}
		if (!BRCM_SDIO_FUNC1_CHIPCLKCSR_CLKAV(clkctl, sc->sc_alp_only)) {
			printf("%s: HT avail timeout\n", DEVNAME(sc));
			return;
		}

		sc->sc_clkstate = CLK_AVAIL;
	} else {
		if (sc->sc_clkstate == CLK_PENDING) {
			devctl = brcm_sdio_read_1(sc, BRCM_SDIO_DEVICE_CTL);
			devctl &= ~BRCM_SDIO_DEVICE_CTL_CA_INT_ONLY;
			brcm_sdio_write_1(sc, BRCM_SDIO_DEVICE_CTL, devctl);
		}
		sc->sc_clkstate = CLK_SDONLY;
		brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR, 0);
	}
}

void
brcm_sdio_readshared(struct brcm_sdio_softc *sc)
{
	struct brcm_softc *brcm = (void *)sc;
	struct brcm_sdio_sdpcm sdpcm;
	uint32_t addr, shaddr;
	int err;

	shaddr = brcm->sc_chip.ch_rambase + brcm->sc_chip.ch_ramsize - 4;
	if (!brcm->sc_chip.ch_rambase && brcm_chip_sr_capable(brcm))
		shaddr -= brcm->sc_chip.ch_srsize;

	err = brcm_sdio_ram_read_write(sc, shaddr, (char *)&addr,
	    sizeof(addr), 0);
	if (err)
		return;

	addr = letoh32(addr);
	if (addr == 0 || ((~addr >> 16) & 0xffff) == (addr & 0xffff))
		return;

	err = brcm_sdio_ram_read_write(sc, addr, (char *)&sdpcm,
	    sizeof(sdpcm), 0);
	if (err)
		return;

	sc->sc_console_addr = letoh32(sdpcm.console_addr);
}

int
brcm_sdio_intr(void *v)
{
	brcm_sdio_task(v);
	return 1;
}

#if defined(__HAVE_FDT)
int
brcm_sdio_oob_intr(void *v)
{
	struct brcm_sdio_softc *sc = (void *)v;
	if (!sc->sc_oob)
		return 0;
	fdt_intr_disable(sc->sc_ih);
	task_add(systq, &sc->sc_task);
	return 1;
}
#endif

void
brcm_sdio_task(void *v)
{
	struct brcm_sdio_softc *sc = (void *)v;
	uint32_t clkctl, devctl, intstat, hostint;

	rw_enter_write(sc->sc_lock);

	if (!sc->sc_sr_enabled && sc->sc_clkstate == CLK_PENDING) {
		clkctl = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR);
		if (BRCM_SDIO_FUNC1_CHIPCLKCSR_HTAV(clkctl)) {
			devctl = brcm_sdio_read_1(sc, BRCM_SDIO_DEVICE_CTL);
			devctl &= ~BRCM_SDIO_DEVICE_CTL_CA_INT_ONLY;
			brcm_sdio_write_1(sc, BRCM_SDIO_DEVICE_CTL, devctl);
			sc->sc_clkstate = CLK_AVAIL;
		}
	}

	intstat = brcm_sdio_dev_read(sc, BRCM_SDPCMD_INTSTATUS);
	intstat &= (SDPCMD_INTSTATUS_HMB_SW_MASK|SDPCMD_INTSTATUS_CHIPACTIVE);
	/* XXX fc state */
	if (intstat)
		brcm_sdio_dev_write(sc, BRCM_SDPCMD_INTSTATUS, intstat);

	if (intstat & SDPCMD_INTSTATUS_HMB_HOST_INT) {
		hostint = brcm_sdio_dev_read(sc, SDPCMD_TOHOSTMAILBOXDATA);
		brcm_sdio_dev_write(sc, SDPCMD_TOSBMAILBOX,
		    SDPCMD_TOSBMAILBOX_INT_ACK);
		if (hostint & SDPCMD_TOHOSTMAILBOXDATA_NAKHANDLED)
			intstat |= SDPCMD_INTSTATUS_HMB_FRAME_IND;
		if (hostint & SDPCMD_TOHOSTMAILBOXDATA_DEVREADY ||
		    hostint & SDPCMD_TOHOSTMAILBOXDATA_FWREADY)
			brcm_sdio_readshared(sc);
	}

	/* FIXME: Might stall if we don't when not set. */
	if (1 || intstat & SDPCMD_INTSTATUS_HMB_FRAME_IND) {
		brcm_sdio_rx_frames(sc);
	}

	if (!ml_empty(&sc->sc_tx_queue)) {
		brcm_sdio_tx_frames(sc);
	}

#ifdef BRCM_DEBUG
	brcm_sdio_debug_console(sc);
#endif

	rw_exit(sc->sc_lock);

#if defined(__HAVE_FDT)
	if (sc->sc_oob)
		fdt_intr_enable(sc->sc_ih);
#endif
}

int
brcm_sdio_detach(struct device *self, int flags)
{
	struct brcm_sdio_softc *sc = (struct brcm_sdio_softc *)self;

	brcm_detach(&sc->sc_sc, flags);

	dma_free(sc->sc_bounce_buf, sc->sc_bounce_size);
	free(sc->sc_sf, M_DEVBUF, 0);

	return 0;
}

void
brcm_sdio_backplane(struct brcm_sdio_softc *sc, uint32_t bar0)
{
	if (sc->sc_bar0 == bar0)
		return;

	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_SBADDRLOW,
	    (bar0 >>  8) & 0x80);
	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_SBADDRMID,
	    (bar0 >> 16) & 0xff);
	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_SBADDRHIGH,
	    (bar0 >> 24) & 0xff);
	sc->sc_bar0 = bar0;
}

uint8_t
brcm_sdio_read_1(struct brcm_sdio_softc *sc, uint32_t addr)
{
	struct sdmmc_function *sf;
	uint8_t rv;

	/*
	 * figure out how to read the register based on address range
	 * 0x00 ~ 0x7FF: function 0 CCCR and FBR
	 * 0x10000 ~ 0x1FFFF: function 1 miscellaneous registers
	 * The rest: function 1 silicon backplane core registers
	 */
	if ((addr & ~0x7ff) == 0)
		sf = sc->sc_sf[0];
	else
		sf = sc->sc_sf[1];

	rv = sdmmc_io_read_1(sf, addr);
	return rv;
}

uint32_t
brcm_sdio_read_4(struct brcm_sdio_softc *sc, uint32_t addr)
{
	struct sdmmc_function *sf;
	uint32_t bar0 = addr & ~BRCM_SDIO_SB_OFT_ADDR_MASK;
	uint32_t rv;

	brcm_sdio_backplane(sc, bar0);

	addr &= BRCM_SDIO_SB_OFT_ADDR_MASK;
	addr |= BRCM_SDIO_SB_ACCESS_2_4B_FLAG;

	/*
	 * figure out how to read the register based on address range
	 * 0x00 ~ 0x7FF: function 0 CCCR and FBR
	 * 0x10000 ~ 0x1FFFF: function 1 miscellaneous registers
	 * The rest: function 1 silicon backplane core registers
	 */
	if ((addr & ~0x7ff) == 0)
		sf = sc->sc_sf[0];
	else
		sf = sc->sc_sf[1];

	rv = sdmmc_io_read_4(sf, addr);
	return rv;
}

void
brcm_sdio_write_1(struct brcm_sdio_softc *sc, uint32_t addr, uint8_t data)
{
	struct sdmmc_function *sf;

	/*
	 * figure out how to read the register based on address range
	 * 0x00 ~ 0x7FF: function 0 CCCR and FBR
	 * 0x10000 ~ 0x1FFFF: function 1 miscellaneous registers
	 * The rest: function 1 silicon backplane core registers
	 */
	if ((addr & ~0x7ff) == 0)
		sf = sc->sc_sf[0];
	else
		sf = sc->sc_sf[1];

	sdmmc_io_write_1(sf, addr, data);
}

void
brcm_sdio_write_4(struct brcm_sdio_softc *sc, uint32_t addr, uint32_t data)
{
	struct sdmmc_function *sf;
	uint32_t bar0 = addr & ~BRCM_SDIO_SB_OFT_ADDR_MASK;

	brcm_sdio_backplane(sc, bar0);

	addr &= BRCM_SDIO_SB_OFT_ADDR_MASK;
	addr |= BRCM_SDIO_SB_ACCESS_2_4B_FLAG;

	/*
	 * figure out how to read the register based on address range
	 * 0x00 ~ 0x7FF: function 0 CCCR and FBR
	 * 0x10000 ~ 0x1FFFF: function 1 miscellaneous registers
	 * The rest: function 1 silicon backplane core registers
	 */
	if ((addr & ~0x7ff) == 0)
		sf = sc->sc_sf[0];
	else
		sf = sc->sc_sf[1];

	sdmmc_io_write_4(sf, addr, data);
}

int
brcm_sdio_buf_read(struct brcm_sdio_softc *sc, struct sdmmc_function *sf,
    uint32_t reg, char *data, size_t size)
{
	int err;

	KASSERT(((vaddr_t)data & 0x3) == 0);
	KASSERT((size & 0x3) == 0);

	if (sf == sc->sc_sf[1])
		err = sdmmc_io_read_region_1(sf, reg, data, size);
	else
		err = sdmmc_io_read_multi_1(sf, reg, data, size);

	if (err)
		printf("%s: error %d\n", __func__, err);

	return err;
}

int
brcm_sdio_buf_write(struct brcm_sdio_softc *sc, struct sdmmc_function *sf,
    uint32_t reg, char *data, size_t size)
{
	int err;

	KASSERT(((vaddr_t)data & 0x3) == 0);
	KASSERT((size & 0x3) == 0);

	err = sdmmc_io_write_region_1(sf, reg, data, size);

	if (err)
		printf("%s: error %d\n", __func__, err);

	return err;
}

uint32_t
brcm_sdio_ram_read_write(struct brcm_sdio_softc *sc, uint32_t reg,
    char *data, size_t left, int write)
{
	uint32_t sbaddr, sdaddr, off;
	size_t size;
	int err;

	err = off = 0;
	while (left > 0) {
		sbaddr = reg + off;
		brcm_sdio_backplane(sc, sbaddr);

		sdaddr = sbaddr & BRCM_SDIO_SB_OFT_ADDR_MASK;
		size = min(left, (BRCM_SDIO_SB_OFT_ADDR_PAGE - sdaddr));
		sdaddr |= BRCM_SDIO_SB_ACCESS_2_4B_FLAG;

		if (write) {
			memcpy(sc->sc_bounce_buf, data + off, size);
			if (roundup(size, 4) != size)
				memset(sc->sc_bounce_buf + size, 0,
				    roundup(size, 4) - size);
			err = brcm_sdio_buf_write(sc, sc->sc_sf[1], sdaddr,
			    sc->sc_bounce_buf, roundup(size, 4));
		} else {
			err = brcm_sdio_buf_read(sc, sc->sc_sf[1], sdaddr,
			    sc->sc_bounce_buf, roundup(size, 4));
			memcpy(data + off, sc->sc_bounce_buf, size);
		}
		if (err)
			break;

		off += size;
		left -= size;
	}

	return err;
}

uint32_t
brcm_sdio_frame_read_write(struct brcm_sdio_softc *sc,
    char *data, size_t size, int write)
{
	uint32_t addr;
	int err;

	addr = sc->sc_cc->co_base;
	brcm_sdio_backplane(sc, addr);

	addr &= BRCM_SDIO_SB_OFT_ADDR_MASK;
	addr |= BRCM_SDIO_SB_ACCESS_2_4B_FLAG;

	if (write)
		err = brcm_sdio_buf_write(sc, sc->sc_sf[2], addr, data, size);
	else
		err = brcm_sdio_buf_read(sc, sc->sc_sf[2], addr, data, size);

	return err;
}

uint32_t
brcm_sdio_dev_read(struct brcm_sdio_softc *sc, uint32_t reg)
{
	struct brcm_core *core;
	core = brcm_chip_get_core(&sc->sc_sc, BRCM_AGENT_CORE_SDIO_DEV);
	return brcm_sdio_read_4(sc, core->co_base + reg);
}

void
brcm_sdio_dev_write(struct brcm_sdio_softc *sc, uint32_t reg, uint32_t val)
{
	struct brcm_core *core;
	core = brcm_chip_get_core(&sc->sc_sc, BRCM_AGENT_CORE_SDIO_DEV);
	brcm_sdio_write_4(sc, core->co_base + reg, val);
}

uint32_t
brcm_sdio_buscore_read(struct brcm_softc *brcm, uint32_t reg)
{
	struct brcm_sdio_softc *sc = (void *)brcm;
	return brcm_sdio_read_4(sc, reg);
}

void
brcm_sdio_buscore_write(struct brcm_softc *brcm, uint32_t reg, uint32_t val)
{
	struct brcm_sdio_softc *sc = (void *)brcm;
	brcm_sdio_write_4(sc, reg, val);
}

int
brcm_sdio_buscore_prepare(struct brcm_softc *brcm)
{
	struct brcm_sdio_softc *sc = (void *)brcm;
	uint8_t clkval, clkset, clkmask;
	int i;

	clkset = BRCM_SDIO_FUNC1_CHIPCLKCSR_ALP_AVAIL_REQ |
	    BRCM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HW_CLKREQ_OFF;
	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR, clkset);

	clkmask = BRCM_SDIO_FUNC1_CHIPCLKCSR_ALP_AVAIL |
	    BRCM_SDIO_FUNC1_CHIPCLKCSR_HT_AVAIL;
	clkval = brcm_sdio_read_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR);

	if ((clkval & ~clkmask) != clkset) {
		printf("%s: wrote 0x%02x read 0x%02x\n", DEVNAME(sc),
		    clkset, clkval);
		return 1;
	}

	for (i = 1000; i > 0; i--) {
		clkval = brcm_sdio_read_1(sc,
		    BRCM_SDIO_FUNC1_CHIPCLKCSR);
		if (clkval & clkmask)
			break;
	}
	if (i == 0) {
		printf("%s: timeout on ALPAV wait, clkval 0x%02x\n",
		    DEVNAME(sc), clkval);
		return 1;
	}

	clkset = BRCM_SDIO_FUNC1_CHIPCLKCSR_FORCE_HW_CLKREQ_OFF |
	    BRCM_SDIO_FUNC1_CHIPCLKCSR_FORCE_ALP;
	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_CHIPCLKCSR, clkset);
	delay(65);

	brcm_sdio_write_1(sc, BRCM_SDIO_FUNC1_SDIOPULLUP, 0);

	return 0;
}

void
brcm_sdio_buscore_activate(struct brcm_softc *brcm, uint32_t rstvec)
{
	struct brcm_sdio_softc *sc = (void *)brcm;

	brcm_sdio_dev_write(sc, BRCM_SDPCMD_INTSTATUS, 0xFFFFFFFF);

	if (rstvec)
		brcm_sdio_ram_read_write(sc, 0, (char *)&rstvec,
		    sizeof(rstvec), 1);
}

struct mbuf *
brcm_sdio_newbuf(void)
{
	struct mbuf *m;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return (NULL);

	MCLGET(m, M_DONTWAIT);
	if (!(m->m_flags & M_EXT)) {
		m_freem(m);
		return (NULL);
	}

	m->m_len = m->m_pkthdr.len = MCLBYTES;

	return (m);
}

int
brcm_sdio_tx_ok(struct brcm_sdio_softc *sc)
{
	return (uint8_t)(sc->sc_tx_max_seq - sc->sc_tx_seq) != 0 &&
	    ((uint8_t)(sc->sc_tx_max_seq - sc->sc_tx_seq) & 0x80) == 0;
}

void
brcm_sdio_tx_frames(struct brcm_sdio_softc *sc)
{
	struct ifnet *ifp = &sc->sc_sc.sc_ic.ic_if;
	struct mbuf *m;
	int i;

	if (!brcm_sdio_tx_ok(sc))
		return;

	i = min((uint8_t)(sc->sc_tx_max_seq - sc->sc_tx_seq), 32);
	while (i--) {
		m = ml_dequeue(&sc->sc_tx_queue);
		if (m == NULL)
			break;

		if (m->m_type == MT_CONTROL)
			brcm_sdio_tx_ctrlframe(sc, m);
		else
			brcm_sdio_tx_dataframe(sc, m);

		m_freem(m);
	}

	if (sc->sc_tx_count < 64)
		ifq_restart(&ifp->if_snd);
}

void
brcm_sdio_tx_ctrlframe(struct brcm_sdio_softc *sc, struct mbuf *m)
{
	struct brcm_sdio_hwhdr *hwhdr;
	struct brcm_sdio_swhdr *swhdr;
	size_t len, roundto;

	len = sizeof(*hwhdr) + sizeof(*swhdr) + m->m_len;

	/* Zero-pad to either block-size or 4-byte alignment. */
	if (len > 512 && (len % 512) != 0)
		roundto = 512;
	else
		roundto = 4;

	KASSERT(roundup(len, roundto) <= sc->sc_bounce_size);

	hwhdr = (void *)sc->sc_bounce_buf;
	hwhdr->frmlen = htole16(len);
	hwhdr->cksum = htole16(~len);

	swhdr = (void *)&hwhdr[1];
	swhdr->seqnr = sc->sc_tx_seq++;
	swhdr->chanflag = BRCM_SDIO_SWHDR_CHANNEL_CONTROL;
	swhdr->nextlen = 0;
	swhdr->dataoff = sizeof(*hwhdr) + sizeof(*swhdr);
	swhdr->maxseqnr = 0;

	m_copydata(m, 0, m->m_len, (caddr_t)&swhdr[1]);

	if (roundup(len, roundto) != len)
		memset(sc->sc_bounce_buf + len, 0,
		    roundup(len, roundto) - len);

	brcm_sdio_frame_read_write(sc, sc->sc_bounce_buf,
	    roundup(len, roundto), 1);
}

void
brcm_sdio_tx_dataframe(struct brcm_sdio_softc *sc, struct mbuf *m)
{
	struct brcm_sdio_hwhdr *hwhdr;
	struct brcm_sdio_swhdr *swhdr;
	struct brcm_proto_bcdc_hdr *bcdc;
	size_t len, roundto;

	len = sizeof(*hwhdr) + sizeof(*swhdr) + sizeof(*bcdc)
	    + m->m_pkthdr.len;

	/* Zero-pad to either block-size or 4-byte alignment. */
	if (len > 512 && (len % 512) != 0)
		roundto = 512;
	else
		roundto = 4;

	KASSERT(roundup(len, roundto) <= sc->sc_bounce_size);

	hwhdr = (void *)sc->sc_bounce_buf;
	hwhdr->frmlen = htole16(len);
	hwhdr->cksum = htole16(~len);

	swhdr = (void *)&hwhdr[1];
	swhdr->seqnr = sc->sc_tx_seq++;
	swhdr->chanflag = BRCM_SDIO_SWHDR_CHANNEL_DATA;
	swhdr->nextlen = 0;
	swhdr->dataoff = sizeof(*hwhdr) + sizeof(*swhdr);
	swhdr->maxseqnr = 0;

	bcdc = (void *)&swhdr[1];
	bcdc->data_offset = 0;
	bcdc->priority = ieee80211_classify(&sc->sc_sc.sc_ic, m);
	bcdc->flags = BRCM_BCDC_FLAG_VER(BRCM_BCDC_FLAG_PROTO_VER);
	bcdc->flags2 = 0;

	m_copydata(m, 0, m->m_pkthdr.len, (caddr_t)&bcdc[1]);

	if (roundup(len, roundto) != len)
		memset(sc->sc_bounce_buf + len, 0,
		    roundup(len, roundto) - len);

	brcm_sdio_frame_read_write(sc, sc->sc_bounce_buf,
	    roundup(len, roundto), 1);

	sc->sc_tx_count--;
}

void
brcm_sdio_rx_frames(struct brcm_sdio_softc *sc)
{
	struct ifnet *ifp = &sc->sc_sc.sc_ic.ic_if;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	struct brcm_sdio_hwhdr *hwhdr;
	struct brcm_sdio_swhdr *swhdr;
	uint16_t *sublen, nextlen = 0;
	struct mbuf *m;
	size_t flen;
	char *data;
	off_t off;
	int nsub;

	hwhdr = (struct brcm_sdio_hwhdr *)sc->sc_bounce_buf;
	swhdr = (struct brcm_sdio_swhdr *)&hwhdr[1];
	data = (char *)&swhdr[1];

	for (;;) {
		/* If we know the next size, just read ahead. */
		if (nextlen) {
			if (brcm_sdio_frame_read_write(sc, sc->sc_bounce_buf,
			    nextlen, 0))
				break;
		} else {
			if (brcm_sdio_frame_read_write(sc, sc->sc_bounce_buf,
			    sizeof(*hwhdr) + sizeof(*swhdr), 0))
				break;
		}

		hwhdr->frmlen = letoh16(hwhdr->frmlen);
		hwhdr->cksum = letoh16(hwhdr->cksum);

		if (hwhdr->frmlen == 0 && hwhdr->cksum == 0)
			break;

		if ((hwhdr->frmlen ^ hwhdr->cksum) != 0xffff) {
			printf("%s: checksum error\n", DEVNAME(sc));
			break;
		}

		if (hwhdr->frmlen < sizeof(*hwhdr) + sizeof(*swhdr)) {
			printf("%s: length error\n", DEVNAME(sc));
			break;
		}

		if (nextlen && hwhdr->frmlen > nextlen) {
			printf("%s: read ahead length error (%u > %u)\n",
			    DEVNAME(sc), hwhdr->frmlen, nextlen);
			break;
		}

		sc->sc_tx_max_seq = swhdr->maxseqnr;

		flen = hwhdr->frmlen - (sizeof(*hwhdr) + sizeof(*swhdr));
		if (flen == 0) {
			nextlen = swhdr->nextlen << 4;
			continue;
		}

		if (!nextlen) {
			KASSERT(roundup(flen, 4) <= sc->sc_bounce_size -
			    (sizeof(*hwhdr) + sizeof(*swhdr)));
			if (brcm_sdio_frame_read_write(sc, data,
			    roundup(flen, 4), 0))
				break;
		}

		if (swhdr->dataoff < (sizeof(*hwhdr) + sizeof(*swhdr)))
			break;

		off = swhdr->dataoff - (sizeof(*hwhdr) + sizeof(*swhdr));
		if (off > flen)
			break;

		switch (swhdr->chanflag & BRCM_SDIO_SWHDR_CHANNEL_MASK) {
		case BRCM_SDIO_SWHDR_CHANNEL_CONTROL:
			sc->sc_sc.sc_proto_ops->proto_rxctl(&sc->sc_sc,
			    data + off, flen - off);
			nextlen = swhdr->nextlen << 4;
			break;
		case BRCM_SDIO_SWHDR_CHANNEL_EVENT:
		case BRCM_SDIO_SWHDR_CHANNEL_DATA:
			m = brcm_sdio_newbuf();
			if (m == NULL)
				break;
			if (flen - off > m->m_len) {
				printf("%s: frame bigger than anticipated\n",
				    DEVNAME(sc));
				m_freem(m);
				break;
			}
			m->m_len = m->m_pkthdr.len = flen - off;
			memcpy(mtod(m, char *), data + off, flen - off);
			sc->sc_sc.sc_proto_ops->proto_rx(&sc->sc_sc, m, &ml);
			nextlen = swhdr->nextlen << 4;
			break;
		case BRCM_SDIO_SWHDR_CHANNEL_GLOM:
			if ((flen % sizeof(uint16_t)) != 0)
				break;
			nsub = flen / sizeof(uint16_t);
			sublen = mallocarray(nsub, sizeof(uint16_t),
			    M_DEVBUF, M_WAITOK | M_ZERO);
			memcpy(sublen, data, nsub * sizeof(uint16_t));
			brcm_sdio_rx_glom(sc, sublen, nsub, &nextlen, &ml);
			free(sublen, M_DEVBUF, nsub * sizeof(uint16_t));
			break;
		default:
			printf("%s: unknown channel\n", DEVNAME(sc));
			break;
		}
	}

	if_input(ifp, &ml);
}

void
brcm_sdio_rx_glom(struct brcm_sdio_softc *sc, uint16_t *sublen, int nsub,
    uint16_t *nextlen, struct mbuf_list *ml)
{
	struct brcm_sdio_hwhdr hwhdr;
	struct brcm_sdio_swhdr swhdr;
	struct mbuf_list glom, drop;
	struct mbuf *m;
	size_t flen;
	off_t off;
	int i;

	ml_init(&glom);
	ml_init(&drop);

	if (nsub == 0)
		return;

	for (i = 0; i < nsub; i++) {
		m = brcm_sdio_newbuf();
		if (m == NULL) {
			ml_purge(&glom);
			return;
		}
		ml_enqueue(&glom, m);
		if (letoh16(sublen[i]) > m->m_len) {
			ml_purge(&glom);
			return;
		}
		if (brcm_sdio_frame_read_write(sc, mtod(m, char *),
		    letoh16(sublen[i]), 0)) {
			ml_purge(&glom);
			return;
		}
		m->m_len = m->m_pkthdr.len = letoh16(sublen[i]);
	}

	/* TODO: Verify actual superframe header */
	m = MBUF_LIST_FIRST(&glom);
	if (m->m_len >= sizeof(hwhdr) + sizeof(swhdr)) {
		m_copydata(m, 0, sizeof(hwhdr), (caddr_t)&hwhdr);
		m_copydata(m, sizeof(hwhdr), sizeof(swhdr), (caddr_t)&swhdr);
		*nextlen = swhdr.nextlen << 4;
		m_adj(m, sizeof(struct brcm_sdio_hwhdr) +
		    sizeof(struct brcm_sdio_swhdr));
	}

	while ((m = ml_dequeue(&glom)) != NULL) {
		if (m->m_len < sizeof(hwhdr) + sizeof(swhdr))
			goto drop;

		m_copydata(m, 0, sizeof(hwhdr), (caddr_t)&hwhdr);
		m_copydata(m, sizeof(hwhdr), sizeof(swhdr), (caddr_t)&swhdr);

		hwhdr.frmlen = letoh16(hwhdr.frmlen);
		hwhdr.cksum = letoh16(hwhdr.cksum);

		if (hwhdr.frmlen == 0 && hwhdr.cksum == 0)
			goto drop;

		if ((hwhdr.frmlen ^ hwhdr.cksum) != 0xffff) {
			printf("%s: checksum error\n", DEVNAME(sc));
			goto drop;
		}

		if (hwhdr.frmlen < sizeof(hwhdr) + sizeof(swhdr)) {
			printf("%s: length error\n", DEVNAME(sc));
			goto drop;
		}

		flen = hwhdr.frmlen - (sizeof(hwhdr) + sizeof(swhdr));
		if (flen == 0)
			goto drop;
		if (m->m_len < flen)
			goto drop;

		if (swhdr.dataoff < (sizeof(hwhdr) + sizeof(swhdr)))
			goto drop;

		off = swhdr.dataoff - (sizeof(hwhdr) + sizeof(swhdr));
		if (off > flen)
			goto drop;

		switch (swhdr.chanflag & BRCM_SDIO_SWHDR_CHANNEL_MASK) {
		case BRCM_SDIO_SWHDR_CHANNEL_CONTROL:
			printf("%s: control channel not allowed in glom\n",
			    DEVNAME(sc));
			goto drop;
		case BRCM_SDIO_SWHDR_CHANNEL_EVENT:
		case BRCM_SDIO_SWHDR_CHANNEL_DATA:
			m_adj(m, swhdr.dataoff);
			sc->sc_sc.sc_proto_ops->proto_rx(&sc->sc_sc, m, ml);
			break;
		case BRCM_SDIO_SWHDR_CHANNEL_GLOM:
			printf("%s: glom not allowed in glom\n",
			    DEVNAME(sc));
			goto drop;
		default:
			printf("%s: unknown channel\n", DEVNAME(sc));
			goto drop;
		}

		continue;
drop:
		ml_enqueue(&drop, m);
	}

	ml_purge(&drop);
}

int
brcm_sdio_txcheck(struct brcm_softc *brcm)
{
	struct brcm_sdio_softc *sc = (void *)brcm;

	if (sc->sc_tx_count >= 64)
		return ENOBUFS;

	return 0;
}

int
brcm_sdio_txdata(struct brcm_softc *brcm, struct mbuf *m)
{
	struct brcm_sdio_softc *sc = (void *)brcm;

	if (sc->sc_tx_count >= 64)
		return ENOBUFS;

	sc->sc_tx_count++;
	ml_enqueue(&sc->sc_tx_queue, m);
	task_add(systq, &sc->sc_task);
	return 0;
}

int
brcm_sdio_txctl(struct brcm_softc *brcm, void *arg)
{
	struct brcm_sdio_softc *sc = (void *)brcm;
	struct brcm_proto_bcdc_ctl *ctl = arg;
	struct mbuf *m;

	KASSERT(ctl->len <= MCLBYTES);

	MGET(m, M_DONTWAIT, MT_CONTROL);
	if (m == NULL)
		goto fail;
	if (ctl->len > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if (!(m->m_flags & M_EXT)) {
			m_freem(m);
			goto fail;
		}
	}
	memcpy(mtod(m, char *), ctl->buf, ctl->len);
	m->m_len = ctl->len;

	TAILQ_INSERT_TAIL(&sc->sc_sc.sc_bcdc_rxctlq, ctl, next);
	ml_enqueue(&sc->sc_tx_queue, m);
	task_add(systq, &sc->sc_task);
	return 0;

fail:
	free(ctl->buf, M_TEMP, ctl->len);
	free(ctl, M_TEMP, sizeof(*ctl));
	return 1;
}

#ifdef BRCM_DEBUG
void
brcm_sdio_debug_console(struct brcm_sdio_softc *sc)
{
	struct brcm_sdio_console c;
	uint32_t newidx;
	int err;

	if (!sc->sc_console_addr)
		return;

	err = brcm_sdio_ram_read_write(sc, sc->sc_console_addr,
	    (char *)&c, sizeof(c), 0);
	if (err)
		return;

	c.log_buf = letoh32(c.log_buf);
	c.log_bufsz = letoh32(c.log_bufsz);
	c.log_idx = letoh32(c.log_idx);

	if (sc->sc_console_buf == NULL) {
		sc->sc_console_buf = malloc(c.log_bufsz, M_DEVBUF,
		    M_WAITOK|M_ZERO);
		sc->sc_console_buf_size = c.log_bufsz;
	}

	newidx = c.log_idx;
	if (newidx >= sc->sc_console_buf_size)
		return;

	err = brcm_sdio_ram_read_write(sc, c.log_buf, sc->sc_console_buf,
	    sc->sc_console_buf_size, 0);
	if (err)
		return;

	if (newidx != sc->sc_console_readidx)
		DPRINTFN(3, ("BRCM CONSOLE: "));
	while (newidx != sc->sc_console_readidx) {
		uint8_t ch = sc->sc_console_buf[sc->sc_console_readidx];
		sc->sc_console_readidx++;
		if (sc->sc_console_readidx == sc->sc_console_buf_size)
			sc->sc_console_readidx = 0;
		if (ch == '\r')
			continue;
		DPRINTFN(3, ("%c", ch));
	}
}
#endif

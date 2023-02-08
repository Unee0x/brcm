/* $OpenBSD: brcm.c,v 1.106 2022/12/30 16:49:34 kettenis Exp $ */
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
//#include <sys/device.h>
#include <sys/abi_compat.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>

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

#include "brcmvar.h"
#include "brcmreg.h"

/* #define BRCM_DEBUG */
#ifdef BRCM_DEBUG
#define DPRINTF(x)	do { if (brcm_debug > 0) printf x; } while (0)
#define DPRINTFN(n, x)	do { if (brcm_debug >= (n)) printf x; } while (0)
static int brcm_debug = 1;
#else
#define DPRINTF(x)	do { ; } while (0)
#define DPRINTFN(n, x)	do { ; } while (0)
#endif

#define DEVNAME(sc)	((sc)->sc_dev.dv_xname)

void	 brcm_start(struct ifnet *);
void	 brcm_init(struct ifnet *);
void	 brcm_stop(struct ifnet *);
void	 brcm_iff(struct brcm_softc *);
void	 brcm_watchdog(struct ifnet *);
void	 brcm_update_node(void *, struct ieee80211_node *);
void	 brcm_update_nodes(struct brcm_softc *);
int	 brcm_ioctl(struct ifnet *, u_long, caddr_t);
int	 brcm_media_change(struct ifnet *);

void	 brcm_init_board_type(struct brcm_softc *);
void	 brcm_process_blob(struct brcm_softc *, char *, u_char **, size_t *);

int	 brcm_chip_attach(struct brcm_softc *);
void	 brcm_chip_detach(struct brcm_softc *);
struct brcm_core *brcm_chip_get_core_idx(struct brcm_softc *, int, int);
struct brcm_core *brcm_chip_get_core(struct brcm_softc *, int);
struct brcm_core *brcm_chip_get_pmu(struct brcm_softc *);
int	 brcm_chip_ai_isup(struct brcm_softc *, struct brcm_core *);
void	 brcm_chip_ai_disable(struct brcm_softc *, struct brcm_core *,
	     uint32_t, uint32_t);
void	 brcm_chip_ai_reset(struct brcm_softc *, struct brcm_core *,
	     uint32_t, uint32_t, uint32_t);
void	 brcm_chip_dmp_erom_scan(struct brcm_softc *);
int	 brcm_chip_dmp_get_regaddr(struct brcm_softc *, uint32_t *,
	     uint32_t *, uint32_t *);
int	 brcm_chip_cr4_set_active(struct brcm_softc *, uint32_t);
void	 brcm_chip_cr4_set_passive(struct brcm_softc *);
int	 brcm_chip_ca7_set_active(struct brcm_softc *, uint32_t);
void	 brcm_chip_ca7_set_passive(struct brcm_softc *);
int	 brcm_chip_cm3_set_active(struct brcm_softc *);
void	 brcm_chip_cm3_set_passive(struct brcm_softc *);
void	 brcm_chip_socram_ramsize(struct brcm_softc *, struct brcm_core *);
void	 brcm_chip_sysmem_ramsize(struct brcm_softc *, struct brcm_core *);
void	 brcm_chip_tcm_ramsize(struct brcm_softc *, struct brcm_core *);
void	 brcm_chip_tcm_rambase(struct brcm_softc *);

int	 brcm_proto_bcdc_query_dcmd(struct brcm_softc *, int,
	     int, char *, size_t *);
int	 brcm_proto_bcdc_set_dcmd(struct brcm_softc *, int,
	     int, char *, size_t);
void	 brcm_proto_bcdc_rx(struct brcm_softc *, struct mbuf *,
	     struct mbuf_list *);
int	 brcm_proto_bcdc_txctl(struct brcm_softc *, int, char *, size_t *);
void	 brcm_proto_bcdc_rxctl(struct brcm_softc *, char *, size_t);

int	 brcm_fwvar_cmd_get_data(struct brcm_softc *, int, void *, size_t);
int	 brcm_fwvar_cmd_set_data(struct brcm_softc *, int, void *, size_t);
int	 brcm_fwvar_cmd_get_int(struct brcm_softc *, int, uint32_t *);
int	 brcm_fwvar_cmd_set_int(struct brcm_softc *, int, uint32_t);
int	 brcm_fwvar_var_get_data(struct brcm_softc *, char *, void *, size_t);
int	 brcm_fwvar_var_set_data(struct brcm_softc *, char *, void *, size_t);
int	 brcm_fwvar_var_get_int(struct brcm_softc *, char *, uint32_t *);
int	 brcm_fwvar_var_set_int(struct brcm_softc *, char *, uint32_t);

uint32_t brcm_chan2spec(struct brcm_softc *, struct ieee80211_channel *);
uint32_t brcm_chan2spec_d11n(struct brcm_softc *, struct ieee80211_channel *);
uint32_t brcm_chan2spec_d11ac(struct brcm_softc *, struct ieee80211_channel *);
uint32_t brcm_spec2chan(struct brcm_softc *, uint32_t);
uint32_t brcm_spec2chan_d11n(struct brcm_softc *, uint32_t);
uint32_t brcm_spec2chan_d11ac(struct brcm_softc *, uint32_t);

void	 brcm_connect(struct brcm_softc *);
#ifndef IEEE80211_STA_ONLY
void	 brcm_hostap(struct brcm_softc *);
#endif
void	 brcm_scan(struct brcm_softc *);
void	 brcm_scan_abort(struct brcm_softc *);

void	 brcm_task(void *);
void	 brcm_do_async(struct brcm_softc *,
	     void (*)(struct brcm_softc *, void *), void *, int);

int	 brcm_set_key(struct ieee80211com *, struct ieee80211_node *,
	     struct ieee80211_key *);
void	 brcm_delete_key(struct ieee80211com *, struct ieee80211_node *,
	     struct ieee80211_key *);
int	 brcm_send_mgmt(struct ieee80211com *, struct ieee80211_node *,
	     int, int, int);
int	 brcm_newstate(struct ieee80211com *, enum ieee80211_state, int);

void	 brcm_set_key_cb(struct brcm_softc *, void *);
void	 brcm_delete_key_cb(struct brcm_softc *, void *);
void	 brcm_rx_event_cb(struct brcm_softc *, struct mbuf *);

struct mbuf *brcm_newbuf(void);
#ifndef IEEE80211_STA_ONLY
void	 brcm_rx_auth_ind(struct brcm_softc *, struct brcm_event *, size_t);
void	 brcm_rx_assoc_ind(struct brcm_softc *, struct brcm_event *, size_t, int);
void	 brcm_rx_deauth_ind(struct brcm_softc *, struct brcm_event *, size_t);
void	 brcm_rx_disassoc_ind(struct brcm_softc *, struct brcm_event *, size_t);
void	 brcm_rx_leave_ind(struct brcm_softc *, struct brcm_event *, size_t, int);
#endif
void	 brcm_rx_event(struct brcm_softc *, struct mbuf *);
void	 brcm_scan_node(struct brcm_softc *, struct brcm_bss_info *, size_t);

extern void ieee80211_node2req(struct ieee80211com *,
	     const struct ieee80211_node *, struct ieee80211_nodereq *);
extern void ieee80211_req2node(struct ieee80211com *,
	     const struct ieee80211_nodereq *, struct ieee80211_node *);

uint8_t brcm_2ghz_channels[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
};
uint8_t brcm_5ghz_channels[] = {
	34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64, 100, 104, 108, 112,
	116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165,
};

struct brcm_proto_ops brcm_proto_bcdc_ops = {
	.proto_query_dcmd = brcm_proto_bcdc_query_dcmd,
	.proto_set_dcmd = brcm_proto_bcdc_set_dcmd,
	.proto_rx = brcm_proto_bcdc_rx,
	.proto_rxctl = brcm_proto_bcdc_rxctl,
};

struct cfdriver brcm_cd = {
	NULL, "brcm", DV_IFNET
};

void
brcm_attach(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;

	TAILQ_INIT(&sc->sc_bcdc_rxctlq);

	/* Init host async commands ring. */
	sc->sc_cmdq.cur = sc->sc_cmdq.next = sc->sc_cmdq.queued = 0;
	sc->sc_taskq = taskq_create(DEVNAME(sc), 1, IPL_SOFTNET, 0);
	task_set(&sc->sc_task, brcm_task, sc);
	ml_init(&sc->sc_evml);

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	ic->ic_caps =
#ifndef IEEE80211_STA_ONLY
	    IEEE80211_C_HOSTAP |	/* Access Point */
#endif
	    IEEE80211_C_RSN | 		/* WPA/RSN */
	    IEEE80211_C_SCANALL |	/* device scans all channels at once */
	    IEEE80211_C_SCANALLBAND;	/* device scans all bands at once */

	/* IBSS channel undefined for now. */
	ic->ic_ibss_chan = &ic->ic_channels[0];

	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = brcm_ioctl;
	ifp->if_start = brcm_start;
	ifp->if_watchdog = brcm_watchdog;
	memcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);

	if_attach(ifp);
	ieee80211_ifattach(ifp);

	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = brcm_newstate;
	ic->ic_send_mgmt = brcm_send_mgmt;
	ic->ic_set_key = brcm_set_key;
	ic->ic_delete_key = brcm_delete_key;

	ieee80211_media_init(ifp, brcm_media_change, ieee80211_media_status);
}

void
brcm_attachhook(struct device *self)
{
	struct brcm_softc *sc = (struct brcm_softc *)self;

	if (sc->sc_bus_ops->bs_preinit != NULL &&
	    sc->sc_bus_ops->bs_preinit(sc))
		return;
	if (brcm_preinit(sc))
		return;
	sc->sc_initialized = 1;
}

int
brcm_preinit(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	int i, j, nbands, nmode, vhtmode;
	uint32_t bandlist[3], tmp;

	if (sc->sc_initialized)
		return 0;

	if (brcm_fwvar_cmd_get_int(sc, BRCM_C_GET_VERSION, &tmp)) {
		printf("%s: could not read io type\n", DEVNAME(sc));
		return 1;
	} else
		sc->sc_io_type = tmp;
	if (brcm_fwvar_var_get_data(sc, "cur_etheraddr", ic->ic_myaddr,
	    sizeof(ic->ic_myaddr))) {
		printf("%s: could not read mac address\n", DEVNAME(sc));
		return 1;
	}

	printf("%s: address %s\n", DEVNAME(sc), ether_sprintf(ic->ic_myaddr));

	brcm_process_blob(sc, "clmload", &sc->sc_clm, &sc->sc_clmsize);
	brcm_process_blob(sc, "txcapload", &sc->sc_txcap, &sc->sc_txcapsize);
	brcm_process_blob(sc, "calload", &sc->sc_cal, &sc->sc_calsize);

	if (brcm_fwvar_var_get_int(sc, "nmode", &nmode))
		nmode = 0;
	if (brcm_fwvar_var_get_int(sc, "vhtmode", &vhtmode))
		vhtmode = 0;
	if (brcm_fwvar_var_get_int(sc, "scan_ver", &sc->sc_scan_ver))
		sc->sc_scan_ver = 0;
	if (brcm_fwvar_cmd_get_data(sc, BRCM_C_GET_BANDLIST, bandlist,
	    sizeof(bandlist))) {
		printf("%s: couldn't get supported band list\n", DEVNAME(sc));
		return 1;
	}
	nbands = letoh32(bandlist[0]);
	for (i = 1; i <= nbands && i < nitems(bandlist); i++) {
		switch (letoh32(bandlist[i])) {
		case BRCM_BAND_2G:
			DPRINTF(("%s: 2G HT %d VHT %d\n",
			    DEVNAME(sc), nmode, vhtmode));
			ic->ic_sup_rates[IEEE80211_MODE_11B] =
			    ieee80211_std_rateset_11b;
			ic->ic_sup_rates[IEEE80211_MODE_11G] =
			    ieee80211_std_rateset_11g;

			for (j = 0; j < nitems(brcm_2ghz_channels); j++) {
				uint8_t chan = brcm_2ghz_channels[j];
				ic->ic_channels[chan].ic_freq =
				    ieee80211_ieee2mhz(chan, IEEE80211_CHAN_2GHZ);
				ic->ic_channels[chan].ic_flags =
				    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
				    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
				if (nmode)
					ic->ic_channels[chan].ic_flags |=
					    IEEE80211_CHAN_HT;
				/* VHT is 5GHz only */
			}
			break;
		case BRCM_BAND_5G:
			DPRINTF(("%s: 5G HT %d VHT %d\n",
			    DEVNAME(sc), nmode, vhtmode));
			ic->ic_sup_rates[IEEE80211_MODE_11A] =
			    ieee80211_std_rateset_11a;

			for (j = 0; j < nitems(brcm_5ghz_channels); j++) {
				uint8_t chan = brcm_5ghz_channels[j];
				ic->ic_channels[chan].ic_freq =
				    ieee80211_ieee2mhz(chan, IEEE80211_CHAN_5GHZ);
				ic->ic_channels[chan].ic_flags =
				    IEEE80211_CHAN_A;
				if (nmode)
					ic->ic_channels[chan].ic_flags |=
					    IEEE80211_CHAN_HT;
				if (vhtmode)
					ic->ic_channels[chan].ic_flags |=
					    IEEE80211_CHAN_VHT;
			}
			break;
		default:
			printf("%s: unsupported band 0x%x\n", DEVNAME(sc),
			    letoh32(bandlist[i]));
			break;
		}
	}

	/* Configure channel information obtained from firmware. */
	ieee80211_channel_init(ifp);

	/* Configure MAC address. */
	if (if_setlladdr(ifp, ic->ic_myaddr))
		printf("%s: could not set MAC address\n", DEVNAME(sc));

	ieee80211_media_init(ifp, brcm_media_change, ieee80211_media_status);
	return 0;
}

void
brcm_cleanup(struct brcm_softc *sc)
{
	brcm_chip_detach(sc);
	sc->sc_initialized = 0;
}

int
brcm_detach(struct brcm_softc *sc, int flags)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;

	task_del(sc->sc_taskq, &sc->sc_task);
	ieee80211_ifdetach(ifp);
	taskq_barrier(sc->sc_taskq);
	if_detach(ifp);
	taskq_destroy(sc->sc_taskq);

	brcm_cleanup(sc);
	return 0;
}

int
brcm_activate(struct brcm_softc *sc, int act)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;

	switch (act) {
	case DVACT_QUIESCE:
		if (ifp->if_flags & IFF_UP)
			brcm_stop(ifp);
		break;
	case DVACT_WAKEUP:
		if (ifp->if_flags & IFF_UP)
			brcm_init(ifp);
		break;
	default:
		break;
	}

	return 0;
}

void
brcm_start(struct ifnet *ifp)
{
	struct brcm_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct mbuf *m;

	if (!(ifp->if_flags & IFF_RUNNING))
		return;
	if (ifq_is_oactive(&ifp->if_snd))
		return;
	if (ifq_empty(&ifp->if_snd))
		return;

	/* TODO: return if no link? */

	for (;;) {
		if (sc->sc_bus_ops->bs_txcheck(sc)) {
			ifq_set_oactive(&ifp->if_snd);
			break;
		}

		if (ic->ic_state != IEEE80211_S_RUN ||
		    (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY))
			break;

		m = ifq_dequeue(&ifp->if_snd);
		if (m == NULL)
			break;

		if (sc->sc_bus_ops->bs_txdata(sc, m) != 0) {
			ifp->if_oerrors++;
			m_freem(m);
			continue;
		}

#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
	}
}

void
brcm_init(struct ifnet *ifp)
{
	struct brcm_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t evmask[BRCM_EVENT_MASK_LEN];
	struct brcm_join_pref_params join_pref[2];
	int pm;

	if (!sc->sc_initialized) {
		if (sc->sc_bus_ops->bs_preinit != NULL &&
		    sc->sc_bus_ops->bs_preinit(sc)) {
			printf("%s: could not init bus\n", DEVNAME(sc));
			return;
		}
		if (brcm_preinit(sc)) {
			printf("%s: could not init\n", DEVNAME(sc));
			return;
		}
		sc->sc_initialized = 1;
	}

	/* Select default channel */
	ic->ic_bss->ni_chan = ic->ic_ibss_chan;

	if (brcm_fwvar_var_set_int(sc, "mpc", 1)) {
		printf("%s: could not set mpc\n", DEVNAME(sc));
		return;
	}

	/* Select target by RSSI (boost on 5GHz) */
	join_pref[0].type = BRCM_JOIN_PREF_RSSI_DELTA;
	join_pref[0].len = 2;
	join_pref[0].rssi_gain = BRCM_JOIN_PREF_RSSI_BOOST;
	join_pref[0].band = BRCM_JOIN_PREF_BAND_5G;
	join_pref[1].type = BRCM_JOIN_PREF_RSSI;
	join_pref[1].len = 2;
	join_pref[1].rssi_gain = 0;
	join_pref[1].band = 0;
	if (brcm_fwvar_var_set_data(sc, "join_pref", join_pref,
	    sizeof(join_pref))) {
		printf("%s: could not set join pref\n", DEVNAME(sc));
		return;
	}

#define BRCM_EVENT(event) evmask[(event) / 8] |= 1 << ((event) % 8)
	memset(evmask, 0, sizeof(evmask));
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		BRCM_EVENT(BRCM_E_IF);
		BRCM_EVENT(BRCM_E_LINK);
		BRCM_EVENT(BRCM_E_AUTH);
		BRCM_EVENT(BRCM_E_ASSOC);
		BRCM_EVENT(BRCM_E_DEAUTH);
		BRCM_EVENT(BRCM_E_DISASSOC);
		BRCM_EVENT(BRCM_E_ESCAN_RESULT);
		break;
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_HOSTAP:
		BRCM_EVENT(BRCM_E_AUTH_IND);
		BRCM_EVENT(BRCM_E_ASSOC_IND);
		BRCM_EVENT(BRCM_E_REASSOC_IND);
		BRCM_EVENT(BRCM_E_DEAUTH_IND);
		BRCM_EVENT(BRCM_E_DISASSOC_IND);
		BRCM_EVENT(BRCM_E_ESCAN_RESULT);
		break;
#endif
	default:
		break;
	}
#undef BRCM_EVENT

	if (brcm_fwvar_var_set_data(sc, "event_msgs", evmask, sizeof(evmask))) {
		printf("%s: could not set event mask\n", DEVNAME(sc));
		return;
	}

	if (brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_SCAN_CHANNEL_TIME,
	    BRCM_DEFAULT_SCAN_CHANNEL_TIME)) {
		printf("%s: could not set scan channel time\n", DEVNAME(sc));
		return;
	}
	if (brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_SCAN_UNASSOC_TIME,
	    BRCM_DEFAULT_SCAN_UNASSOC_TIME)) {
		printf("%s: could not set scan unassoc time\n", DEVNAME(sc));
		return;
	}
	if (brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_SCAN_PASSIVE_TIME,
	    BRCM_DEFAULT_SCAN_PASSIVE_TIME)) {
		printf("%s: could not set scan passive time\n", DEVNAME(sc));
		return;
	}

	/*
	 * Use CAM (constantly awake) when we are running as AP,
	 * otherwise use fast power saving.
	 */
	pm = BRCM_PM_FAST_PS;
#ifndef IEEE80211_STA_ONLY
	if (ic->ic_opmode == IEEE80211_M_HOSTAP)
		pm = BRCM_PM_CAM;
#endif
	if (brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_PM, pm)) {
		printf("%s: could not set power\n", DEVNAME(sc));
		return;
	}

	brcm_fwvar_var_set_int(sc, "txbf", 1);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_UP, 0);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_INFRA, 1);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_AP, 0);

	/* Disable all offloading (ARP, NDP, TCP/UDP cksum). */
	brcm_fwvar_var_set_int(sc, "arp_ol", 0);
	brcm_fwvar_var_set_int(sc, "arpoe", 0);
	brcm_fwvar_var_set_int(sc, "ndoe", 0);
	brcm_fwvar_var_set_int(sc, "toe", 0);

	/*
	 * The firmware supplicant can handle the WPA handshake for
	 * us, but we honestly want to do this ourselves, so disable
	 * the firmware supplicant and let our stack handle it.
	 */
	brcm_fwvar_var_set_int(sc, "sup_wpa", 0);

	brcm_iff(sc);

	ifp->if_flags |= IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);

	ieee80211_begin_scan(ifp);
}

void
brcm_stop(struct ifnet *ifp)
{
	struct brcm_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct brcm_join_params join;

	sc->sc_tx_timer = 0;
	ifp->if_timer = 0;
	ifp->if_flags &= ~IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	memset(&join, 0, sizeof(join));
	brcm_fwvar_cmd_set_data(sc, BRCM_C_SET_SSID, &join, sizeof(join));
	brcm_fwvar_cmd_set_int(sc, BRCM_C_DOWN, 1);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_AP, 0);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_INFRA, 0);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_UP, 1);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_PM, BRCM_PM_FAST_PS);
	brcm_fwvar_var_set_int(sc, "mpc", 1);

	if (sc->sc_bus_ops->bs_stop)
		sc->sc_bus_ops->bs_stop(sc);
}

void
brcm_iff(struct brcm_softc *sc)
{
	struct arpcom *ac = &sc->sc_ic.ic_ac;
	struct ifnet *ifp = &ac->ac_if;
	struct ether_multi *enm;
	struct ether_multistep step;
	size_t mcastlen;
	char *mcast;
	int i = 0;

	mcastlen = sizeof(uint32_t) + ac->ac_multicnt * ETHER_ADDR_LEN;
	mcast = malloc(mcastlen, M_TEMP, M_WAITOK);
	htolem32((uint32_t *)mcast, ac->ac_multicnt);

	ifp->if_flags &= ~IFF_ALLMULTI;
	if (ifp->if_flags & IFF_PROMISC || ac->ac_multirangecnt > 0) {
		ifp->if_flags |= IFF_ALLMULTI;
	} else {
		ETHER_FIRST_MULTI(step, ac, enm);
		while (enm != NULL) {
			memcpy(mcast + sizeof(uint32_t) + i * ETHER_ADDR_LEN,
			    enm->enm_addrlo, ETHER_ADDR_LEN);
			ETHER_NEXT_MULTI(step, enm);
			i++;
		}
	}

	brcm_fwvar_var_set_data(sc, "mcast_list", mcast, mcastlen);
	brcm_fwvar_var_set_int(sc, "allmulti",
	    !!(ifp->if_flags & IFF_ALLMULTI));
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_PROMISC,
	    !!(ifp->if_flags & IFF_PROMISC));

	free(mcast, M_TEMP, mcastlen);
}

void
brcm_watchdog(struct ifnet *ifp)
{
	struct brcm_softc *sc = ifp->if_softc;

	ifp->if_timer = 0;

	if (sc->sc_tx_timer > 0) {
		if (--sc->sc_tx_timer == 0) {
			printf("%s: device timeout\n", DEVNAME(sc));
			ifp->if_oerrors++;
			return;
		}
		ifp->if_timer = 1;
	}
	ieee80211_watchdog(ifp);
}

/*
 * Tx-rate to MCS conversion might lie since some rates map to multiple MCS.
 * But this is the best we can do given that firmware only reports kbit/s.
 */

void
brcm_rate2vhtmcs(int *mcs, int *ss, uint32_t txrate)
{
	const struct ieee80211_vht_rateset *rs;
	int i, j;
	
	*mcs = -1;
	*ss = -1;
	/* TODO: Select specific ratesets based on BSS channel width. */
	for (i = 0; i < IEEE80211_VHT_NUM_RATESETS; i++) {
		rs = &ieee80211_std_ratesets_11ac[i];
		for (j = 0; j < rs->nrates; j++) {
			if (rs->rates[j] == txrate / 500) {
				*mcs = j;
				*ss = rs->num_ss;
				return;
			}
		}
	}
}

int
brcm_rate2htmcs(uint32_t txrate)
{
	const struct ieee80211_ht_rateset *rs;
	int i, j;
	
	/* TODO: Select specific ratesets based on BSS channel width. */
	for (i = 0; i < IEEE80211_HT_NUM_RATESETS; i++) {
		rs = &ieee80211_std_ratesets_11n[i];
		for (j = 0; j < rs->nrates; j++) {
			if (rs->rates[j] == txrate / 500)
				return rs->min_mcs + j;
		}
	}

	return -1;
}

void
brcm_update_node(void *arg, struct ieee80211_node *ni)
{
	struct brcm_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct brcm_sta_info sta;
	uint32_t flags;
	int8_t rssi;
	uint32_t txrate;
	int i;

	memset(&sta, 0, sizeof(sta));
	memcpy((uint8_t *)&sta, ni->ni_macaddr, sizeof(ni->ni_macaddr));

	if (brcm_fwvar_var_get_data(sc, "sta_info", &sta, sizeof(sta)))
		return;

	if (!IEEE80211_ADDR_EQ(ni->ni_macaddr, sta.ea))
		return;

	if (le16toh(sta.ver) < 3)
		return;

	flags = le32toh(sta.flags);
	if ((flags & BRCM_STA_SCBSTATS) == 0)
		return;

	if (le16toh(sta.ver) >= 4) {
		rssi = 0;
		for (i = 0; i < BRCM_ANT_MAX; i++) {
			if (sta.rssi[i] >= 0)
				continue;
			if (rssi == 0 || sta.rssi[i] > rssi)
				rssi = sta.rssi[i];
		}
		if (rssi)
			ni->ni_rssi = rssi;
	}

	txrate = le32toh(sta.tx_rate); /* in kbit/s */
	if (txrate == 0xffffffff) /* Seen this happening during association. */
		return;

	if ((le32toh(sta.flags) & BRCM_STA_VHT_CAP)) {
		int mcs, ss;
		/* Tell net80211 that firmware has negotiated 11ac. */
		ni->ni_flags |= IEEE80211_NODE_VHT;
		ni->ni_flags |= IEEE80211_NODE_HT; /* VHT implies HT support */
		if (ic->ic_curmode < IEEE80211_MODE_11AC)
			ieee80211_setmode(ic, IEEE80211_MODE_11AC);
	    	brcm_rate2vhtmcs(&mcs, &ss, txrate);
		if (mcs >= 0) {
			ni->ni_txmcs = mcs;
			ni->ni_vht_ss = ss;
		} else {
			ni->ni_txmcs = 0;
			ni->ni_vht_ss = 1;
		}
	} else if ((le32toh(sta.flags) & BRCM_STA_N_CAP)) {
		int mcs;
		/* Tell net80211 that firmware has negotiated 11n. */
		ni->ni_flags |= IEEE80211_NODE_HT;
		if (ic->ic_curmode < IEEE80211_MODE_11N)
			ieee80211_setmode(ic, IEEE80211_MODE_11N);
	    	mcs = brcm_rate2htmcs(txrate);
		ni->ni_txmcs = (mcs >= 0 ? mcs : 0);
	} else {
		/* We're in 11a/g mode. Map to a legacy rate. */
		for (i = 0; i < ni->ni_rates.rs_nrates; i++) {
			uint8_t rate = ni->ni_rates.rs_rates[i];
			rate &= IEEE80211_RATE_VAL;
			if (rate == txrate / 500) {
				ni->ni_txrate = i;
				break;
			}
		}
	}
}

void
brcm_update_nodes(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;

	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		brcm_update_node(sc, ic->ic_bss);
		/* Update cached copy in the nodes tree as well. */
		ni = ieee80211_find_node(ic, ic->ic_bss->ni_macaddr);
		if (ni) {
			ni->ni_rssi = ic->ic_bss->ni_rssi;
		}
		break;
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_HOSTAP:
		ieee80211_iterate_nodes(ic, brcm_update_node, sc);
		break;
#endif
	default:
		break;
	}
}

int
brcm_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct brcm_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifreq *ifr;
	int s, error = 0;

	s = splnet();
	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		/* FALLTHROUGH */
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (!(ifp->if_flags & IFF_RUNNING))
				brcm_init(ifp);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				brcm_stop(ifp);
		}
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		ifr = (struct ifreq *)data;
		error = (cmd == SIOCADDMULTI) ?
		    ether_addmulti(ifr, &ic->ic_ac) :
		    ether_delmulti(ifr, &ic->ic_ac);
		if (error == ENETRESET) {
			brcm_iff(sc);
			error = 0;
		}
		break;
	case SIOCGIFMEDIA:
	case SIOCG80211NODE:
	case SIOCG80211ALLNODES:
		if (ic->ic_state == IEEE80211_S_RUN)
			brcm_update_nodes(sc);
		/* fall through */
	default:
		error = ieee80211_ioctl(ifp, cmd, data);
	}
	if (error == ENETRESET) {
		if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
		    (IFF_UP | IFF_RUNNING)) {
			brcm_stop(ifp);
			brcm_init(ifp);
		}
		error = 0;
	}
	splx(s);
	return error;
}

int
brcm_media_change(struct ifnet *ifp)
{
	int error;

	error = ieee80211_media_change(ifp);
	if (error != ENETRESET)
		return error;

	if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
	    (IFF_UP | IFF_RUNNING)) {
		brcm_stop(ifp);
		brcm_init(ifp);
	}
	return error;
}

/* Chip initialization (SDIO, PCIe) */
int
brcm_chip_attach(struct brcm_softc *sc)
{
	struct brcm_core *core;
	int need_socram = 0;
	int has_socram = 0;
	int cpu_found = 0;
	uint32_t val;

	LIST_INIT(&sc->sc_chip.ch_list);

	if (sc->sc_buscore_ops->bc_prepare(sc) != 0) {
		printf("%s: failed buscore prepare\n", DEVNAME(sc));
		return 1;
	}

	val = sc->sc_buscore_ops->bc_read(sc,
	    BRCM_CHIP_BASE + BRCM_CHIP_REG_CHIPID);
	sc->sc_chip.ch_chip = BRCM_CHIP_CHIPID_ID(val);
	sc->sc_chip.ch_chiprev = BRCM_CHIP_CHIPID_REV(val);

	if ((sc->sc_chip.ch_chip > 0xa000) || (sc->sc_chip.ch_chip < 0x4000))
		snprintf(sc->sc_chip.ch_name, sizeof(sc->sc_chip.ch_name),
		    "%d", sc->sc_chip.ch_chip);
	else
		snprintf(sc->sc_chip.ch_name, sizeof(sc->sc_chip.ch_name),
		    "%x", sc->sc_chip.ch_chip);

	switch (BRCM_CHIP_CHIPID_TYPE(val))
	{
	case BRCM_CHIP_CHIPID_TYPE_SOCI_SB:
		printf("%s: SoC interconnect SB not implemented\n",
		    DEVNAME(sc));
		return 1;
	case BRCM_CHIP_CHIPID_TYPE_SOCI_AI:
		sc->sc_chip.ch_core_isup = brcm_chip_ai_isup;
		sc->sc_chip.ch_core_disable = brcm_chip_ai_disable;
		sc->sc_chip.ch_core_reset = brcm_chip_ai_reset;
		brcm_chip_dmp_erom_scan(sc);
		break;
	default:
		printf("%s: SoC interconnect %d unknown\n",
		    DEVNAME(sc), BRCM_CHIP_CHIPID_TYPE(val));
		return 1;
	}

	LIST_FOREACH(core, &sc->sc_chip.ch_list, co_link) {
		DPRINTF(("%s: 0x%x:%-2d base 0x%08x wrap 0x%08x\n",
		    DEVNAME(sc), core->co_id, core->co_rev,
		    core->co_base, core->co_wrapbase));

		switch (core->co_id) {
		case BRCM_AGENT_CORE_ARM_CM3:
			need_socram = 1;
			/* FALLTHROUGH */
		case BRCM_AGENT_CORE_ARM_CR4:
		case BRCM_AGENT_CORE_ARM_CA7:
			cpu_found = 1;
			break;
		case BRCM_AGENT_INTERNAL_MEM:
			has_socram = 1;
			break;
		default:
			break;
		}
	}

	if (!cpu_found) {
		printf("%s: CPU core not detected\n", DEVNAME(sc));
		return 1;
	}
	if (need_socram && !has_socram) {
		printf("%s: RAM core not provided\n", DEVNAME(sc));
		return 1;
	}

	brcm_chip_set_passive(sc);

	if (sc->sc_buscore_ops->bc_reset) {
		sc->sc_buscore_ops->bc_reset(sc);
		brcm_chip_set_passive(sc);
	}

	if ((core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CR4)) != NULL) {
		brcm_chip_tcm_ramsize(sc, core);
		brcm_chip_tcm_rambase(sc);
	} else if ((core = brcm_chip_get_core(sc, BRCM_AGENT_SYS_MEM)) != NULL) {
		brcm_chip_sysmem_ramsize(sc, core);
		brcm_chip_tcm_rambase(sc);
	} else if ((core = brcm_chip_get_core(sc, BRCM_AGENT_INTERNAL_MEM)) != NULL) {
		brcm_chip_socram_ramsize(sc, core);
	}

	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_CHIPCOMMON);
	sc->sc_chip.ch_cc_caps = sc->sc_buscore_ops->bc_read(sc,
	    core->co_base + BRCM_CHIP_REG_CAPABILITIES);
	sc->sc_chip.ch_cc_caps_ext = sc->sc_buscore_ops->bc_read(sc,
	    core->co_base + BRCM_CHIP_REG_CAPABILITIES_EXT);

	core = brcm_chip_get_pmu(sc);
	if (sc->sc_chip.ch_cc_caps & BRCM_CHIP_REG_CAPABILITIES_PMU) {
		sc->sc_chip.ch_pmucaps = sc->sc_buscore_ops->bc_read(sc,
		    core->co_base + BRCM_CHIP_REG_PMUCAPABILITIES);
		sc->sc_chip.ch_pmurev = sc->sc_chip.ch_pmucaps &
		    BRCM_CHIP_REG_PMUCAPABILITIES_REV_MASK;
	}

	if (sc->sc_buscore_ops->bc_setup)
		sc->sc_buscore_ops->bc_setup(sc);

	brcm_init_board_type(sc);

	return 0;
}

void
brcm_chip_detach(struct brcm_softc *sc)
{
	struct brcm_core *core, *tmp;

	LIST_FOREACH_SAFE(core, &sc->sc_chip.ch_list, co_link, tmp) {
		LIST_REMOVE(core, co_link);
		free(core, M_DEVBUF, sizeof(*core));
	}
}

struct brcm_core *
brcm_chip_get_core_idx(struct brcm_softc *sc, int id, int idx)
{
	struct brcm_core *core;

	LIST_FOREACH(core, &sc->sc_chip.ch_list, co_link) {
		if (core->co_id == id && idx-- == 0)
			return core;
	}

	return NULL;
}

struct brcm_core *
brcm_chip_get_core(struct brcm_softc *sc, int id)
{
	return brcm_chip_get_core_idx(sc, id, 0);
}

struct brcm_core *
brcm_chip_get_pmu(struct brcm_softc *sc)
{
	struct brcm_core *cc, *pmu;

	cc = brcm_chip_get_core(sc, BRCM_AGENT_CORE_CHIPCOMMON);
	if (cc->co_rev >= 35 && sc->sc_chip.ch_cc_caps_ext &
	    BRCM_CHIP_REG_CAPABILITIES_EXT_AOB_PRESENT) {
		pmu = brcm_chip_get_core(sc, BRCM_AGENT_CORE_PMU);
		if (pmu)
			return pmu;
	}

	return cc;
}

/* Functions for the AI interconnect */
int
brcm_chip_ai_isup(struct brcm_softc *sc, struct brcm_core *core)
{
	uint32_t ioctl, reset;

	ioctl = sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL);
	reset = sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_RESET_CTL);

	if (((ioctl & (BRCM_AGENT_IOCTL_FGC | BRCM_AGENT_IOCTL_CLK)) ==
	    BRCM_AGENT_IOCTL_CLK) &&
	    ((reset & BRCM_AGENT_RESET_CTL_RESET) == 0))
		return 1;

	return 0;
}

void
brcm_chip_ai_disable(struct brcm_softc *sc, struct brcm_core *core,
    uint32_t prereset, uint32_t reset)
{
	uint32_t val;
	int i;

	val = sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_RESET_CTL);
	if ((val & BRCM_AGENT_RESET_CTL_RESET) == 0) {

		sc->sc_buscore_ops->bc_write(sc,
		    core->co_wrapbase + BRCM_AGENT_IOCTL,
		    prereset | BRCM_AGENT_IOCTL_FGC | BRCM_AGENT_IOCTL_CLK);
		sc->sc_buscore_ops->bc_read(sc,
		    core->co_wrapbase + BRCM_AGENT_IOCTL);

		sc->sc_buscore_ops->bc_write(sc,
		    core->co_wrapbase + BRCM_AGENT_RESET_CTL,
		    BRCM_AGENT_RESET_CTL_RESET);
		delay(20);

		for (i = 300; i > 0; i--) {
			if (sc->sc_buscore_ops->bc_read(sc,
			    core->co_wrapbase + BRCM_AGENT_RESET_CTL) ==
			    BRCM_AGENT_RESET_CTL_RESET)
				break;
		}
		if (i == 0)
			printf("%s: timeout on core reset\n", DEVNAME(sc));
	}

	sc->sc_buscore_ops->bc_write(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL,
	    reset | BRCM_AGENT_IOCTL_FGC | BRCM_AGENT_IOCTL_CLK);
	sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL);
}

void
brcm_chip_ai_reset(struct brcm_softc *sc, struct brcm_core *core,
    uint32_t prereset, uint32_t reset, uint32_t postreset)
{
	struct brcm_core *core2 = NULL;
	int i;

	if (core->co_id == BRCM_AGENT_CORE_80211)
		core2 = brcm_chip_get_core_idx(sc, BRCM_AGENT_CORE_80211, 1);

	brcm_chip_ai_disable(sc, core, prereset, reset);
	if (core2)
		brcm_chip_ai_disable(sc, core2, prereset, reset);

	for (i = 50; i > 0; i--) {
		if ((sc->sc_buscore_ops->bc_read(sc,
		    core->co_wrapbase + BRCM_AGENT_RESET_CTL) &
		    BRCM_AGENT_RESET_CTL_RESET) == 0)
			break;
		sc->sc_buscore_ops->bc_write(sc,
		    core->co_wrapbase + BRCM_AGENT_RESET_CTL, 0);
		delay(60);
	}
	if (i == 0)
		printf("%s: timeout on core reset\n", DEVNAME(sc));
	if (core2) {
		for (i = 50; i > 0; i--) {
			if ((sc->sc_buscore_ops->bc_read(sc,
			    core2->co_wrapbase + BRCM_AGENT_RESET_CTL) &
			    BRCM_AGENT_RESET_CTL_RESET) == 0)
				break;
			sc->sc_buscore_ops->bc_write(sc,
			    core2->co_wrapbase + BRCM_AGENT_RESET_CTL, 0);
			delay(60);
		}
		if (i == 0)
			printf("%s: timeout on core reset\n", DEVNAME(sc));
	}

	sc->sc_buscore_ops->bc_write(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL,
	    postreset | BRCM_AGENT_IOCTL_CLK);
	sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL);
	if (core2) {
		sc->sc_buscore_ops->bc_write(sc,
		    core2->co_wrapbase + BRCM_AGENT_IOCTL,
		    postreset | BRCM_AGENT_IOCTL_CLK);
		sc->sc_buscore_ops->bc_read(sc,
		    core2->co_wrapbase + BRCM_AGENT_IOCTL);
	}
}

void
brcm_chip_dmp_erom_scan(struct brcm_softc *sc)
{
	uint32_t erom, val, base, wrap;
	uint8_t type = 0;
	uint16_t id;
	uint8_t nmw, nsw, rev;
	struct brcm_core *core;

	erom = sc->sc_buscore_ops->bc_read(sc,
	    BRCM_CHIP_BASE + BRCM_CHIP_REG_EROMPTR);
	while (type != BRCM_DMP_DESC_EOT) {
		val = sc->sc_buscore_ops->bc_read(sc, erom);
		type = val & BRCM_DMP_DESC_MASK;
		erom += 4;

		if (type != BRCM_DMP_DESC_COMPONENT)
			continue;

		id = (val & BRCM_DMP_COMP_PARTNUM)
		    >> BRCM_DMP_COMP_PARTNUM_S;

		val = sc->sc_buscore_ops->bc_read(sc, erom);
		type = val & BRCM_DMP_DESC_MASK;
		erom += 4;

		if (type != BRCM_DMP_DESC_COMPONENT) {
			printf("%s: not component descriptor\n", DEVNAME(sc));
			return;
		}

		nmw = (val & BRCM_DMP_COMP_NUM_MWRAP)
		    >> BRCM_DMP_COMP_NUM_MWRAP_S;
		nsw = (val & BRCM_DMP_COMP_NUM_SWRAP)
		    >> BRCM_DMP_COMP_NUM_SWRAP_S;
		rev = (val & BRCM_DMP_COMP_REVISION)
		    >> BRCM_DMP_COMP_REVISION_S;

		if (nmw + nsw == 0 && id != BRCM_AGENT_CORE_PMU &&
		    id != BRCM_AGENT_CORE_GCI)
			continue;

		if (brcm_chip_dmp_get_regaddr(sc, &erom, &base, &wrap))
			continue;

		core = malloc(sizeof(*core), M_DEVBUF, M_WAITOK);
		core->co_id = id;
		core->co_base = base;
		core->co_wrapbase = wrap;
		core->co_rev = rev;
		LIST_INSERT_HEAD(&sc->sc_chip.ch_list, core, co_link);
	}
}

int
brcm_chip_dmp_get_regaddr(struct brcm_softc *sc, uint32_t *erom,
    uint32_t *base, uint32_t *wrap)
{
	uint8_t type = 0, mpnum = 0;
	uint8_t stype, sztype, wraptype;
	uint32_t val;

	*base = 0;
	*wrap = 0;

	val = sc->sc_buscore_ops->bc_read(sc, *erom);
	type = val & BRCM_DMP_DESC_MASK;
	if (type == BRCM_DMP_DESC_MASTER_PORT) {
		mpnum = (val & BRCM_DMP_MASTER_PORT_NUM)
		    >> BRCM_DMP_MASTER_PORT_NUM_S;
		wraptype = BRCM_DMP_SLAVE_TYPE_MWRAP;
		*erom += 4;
	} else if ((type & ~BRCM_DMP_DESC_ADDRSIZE_GT32) ==
	    BRCM_DMP_DESC_ADDRESS)
		wraptype = BRCM_DMP_SLAVE_TYPE_SWRAP;
	else
		return 1;

	do {
		do {
			val = sc->sc_buscore_ops->bc_read(sc, *erom);
			type = val & BRCM_DMP_DESC_MASK;
			if (type == BRCM_DMP_DESC_COMPONENT)
				return 0;
			if (type == BRCM_DMP_DESC_EOT)
				return 1;
			*erom += 4;
		} while ((type & ~BRCM_DMP_DESC_ADDRSIZE_GT32) !=
		     BRCM_DMP_DESC_ADDRESS);

		if (type & BRCM_DMP_DESC_ADDRSIZE_GT32)
			*erom += 4;

		sztype = (val & BRCM_DMP_SLAVE_SIZE_TYPE)
		    >> BRCM_DMP_SLAVE_SIZE_TYPE_S;
		if (sztype == BRCM_DMP_SLAVE_SIZE_DESC) {
			val = sc->sc_buscore_ops->bc_read(sc, *erom);
			type = val & BRCM_DMP_DESC_MASK;
			if (type & BRCM_DMP_DESC_ADDRSIZE_GT32)
				*erom += 8;
			else
				*erom += 4;
		}
		if (sztype != BRCM_DMP_SLAVE_SIZE_4K &&
		    sztype != BRCM_DMP_SLAVE_SIZE_8K)
			continue;

		stype = (val & BRCM_DMP_SLAVE_TYPE) >> BRCM_DMP_SLAVE_TYPE_S;
		if (*base == 0 && stype == BRCM_DMP_SLAVE_TYPE_SLAVE)
			*base = val & BRCM_DMP_SLAVE_ADDR_BASE;
		if (*wrap == 0 && stype == wraptype)
			*wrap = val & BRCM_DMP_SLAVE_ADDR_BASE;
	} while (*base == 0 || *wrap == 0);

	return 0;
}

/* Core configuration */
int
brcm_chip_set_active(struct brcm_softc *sc, uint32_t rstvec)
{
	if (brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CR4) != NULL)
		return brcm_chip_cr4_set_active(sc, rstvec);
	if (brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CA7) != NULL)
		return brcm_chip_ca7_set_active(sc, rstvec);
	if (brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CM3) != NULL)
		return brcm_chip_cm3_set_active(sc);
	return 1;
}

void
brcm_chip_set_passive(struct brcm_softc *sc)
{
	if (brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CR4) != NULL) {
		brcm_chip_cr4_set_passive(sc);
		return;
	}
	if (brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CA7) != NULL) {
		brcm_chip_ca7_set_passive(sc);
		return;
	}
	if (brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CM3) != NULL) {
		brcm_chip_cm3_set_passive(sc);
		return;
	}
}

int
brcm_chip_cr4_set_active(struct brcm_softc *sc, uint32_t rstvec)
{
	struct brcm_core *core;

	sc->sc_buscore_ops->bc_activate(sc, rstvec);
	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CR4);
	sc->sc_chip.ch_core_reset(sc, core,
	    BRCM_AGENT_IOCTL_ARMCR4_CPUHALT, 0, 0);

	return 0;
}

void
brcm_chip_cr4_set_passive(struct brcm_softc *sc)
{
	struct brcm_core *core;
	uint32_t val;
	int i = 0;

	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CR4);
	val = sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL);
	sc->sc_chip.ch_core_reset(sc, core,
	    val & BRCM_AGENT_IOCTL_ARMCR4_CPUHALT,
	    BRCM_AGENT_IOCTL_ARMCR4_CPUHALT,
	    BRCM_AGENT_IOCTL_ARMCR4_CPUHALT);

	while ((core = brcm_chip_get_core_idx(sc, BRCM_AGENT_CORE_80211, i++)))
		sc->sc_chip.ch_core_disable(sc, core,
		    BRCM_AGENT_D11_IOCTL_PHYRESET |
		    BRCM_AGENT_D11_IOCTL_PHYCLOCKEN,
		    BRCM_AGENT_D11_IOCTL_PHYCLOCKEN);
}

int
brcm_chip_ca7_set_active(struct brcm_softc *sc, uint32_t rstvec)
{
	struct brcm_core *core;

	sc->sc_buscore_ops->bc_activate(sc, rstvec);
	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CA7);
	sc->sc_chip.ch_core_reset(sc, core,
	    BRCM_AGENT_IOCTL_ARMCR4_CPUHALT, 0, 0);

	return 0;
}

void
brcm_chip_ca7_set_passive(struct brcm_softc *sc)
{
	struct brcm_core *core;
	uint32_t val;

	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CA7);
	val = sc->sc_buscore_ops->bc_read(sc,
	    core->co_wrapbase + BRCM_AGENT_IOCTL);
	sc->sc_chip.ch_core_reset(sc, core,
	    val & BRCM_AGENT_IOCTL_ARMCR4_CPUHALT,
	    BRCM_AGENT_IOCTL_ARMCR4_CPUHALT,
	    BRCM_AGENT_IOCTL_ARMCR4_CPUHALT);

	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_80211);
	sc->sc_chip.ch_core_reset(sc, core, BRCM_AGENT_D11_IOCTL_PHYRESET |
	    BRCM_AGENT_D11_IOCTL_PHYCLOCKEN, BRCM_AGENT_D11_IOCTL_PHYCLOCKEN,
	    BRCM_AGENT_D11_IOCTL_PHYCLOCKEN);
}

int
brcm_chip_cm3_set_active(struct brcm_softc *sc)
{
	struct brcm_core *core;

	core = brcm_chip_get_core(sc, BRCM_AGENT_INTERNAL_MEM);
	if (!sc->sc_chip.ch_core_isup(sc, core))
		return 1;

	sc->sc_buscore_ops->bc_activate(sc, 0);

	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CM3);
	sc->sc_chip.ch_core_reset(sc, core, 0, 0, 0);

	return 0;
}

void
brcm_chip_cm3_set_passive(struct brcm_softc *sc)
{
	struct brcm_core *core;

	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_ARM_CM3);
	sc->sc_chip.ch_core_disable(sc, core, 0, 0);
	core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_80211);
	sc->sc_chip.ch_core_reset(sc, core, BRCM_AGENT_D11_IOCTL_PHYRESET |
	    BRCM_AGENT_D11_IOCTL_PHYCLOCKEN, BRCM_AGENT_D11_IOCTL_PHYCLOCKEN,
	    BRCM_AGENT_D11_IOCTL_PHYCLOCKEN);
	core = brcm_chip_get_core(sc, BRCM_AGENT_INTERNAL_MEM);
	sc->sc_chip.ch_core_reset(sc, core, 0, 0, 0);

	if (sc->sc_chip.ch_chip == BRCM_CC_43430_CHIP_ID) {
		sc->sc_buscore_ops->bc_write(sc,
		    core->co_base + BRCM_SOCRAM_BANKIDX, 3);
		sc->sc_buscore_ops->bc_write(sc,
		    core->co_base + BRCM_SOCRAM_BANKPDA, 0);
	}
}

int
brcm_chip_sr_capable(struct brcm_softc *sc)
{
	struct brcm_core *core;
	uint32_t reg;

	if (sc->sc_chip.ch_pmurev < 17)
		return 0;

	switch (sc->sc_chip.ch_chip) {
	case BRCM_CC_4345_CHIP_ID:
	case BRCM_CC_4354_CHIP_ID:
	case BRCM_CC_4356_CHIP_ID:
		core = brcm_chip_get_pmu(sc);
		sc->sc_buscore_ops->bc_write(sc, core->co_base +
		    BRCM_CHIP_REG_CHIPCONTROL_ADDR, 3);
		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_CHIPCONTROL_DATA);
		return (reg & (1 << 2)) != 0;
	case BRCM_CC_43241_CHIP_ID:
	case BRCM_CC_4335_CHIP_ID:
	case BRCM_CC_4339_CHIP_ID:
		core = brcm_chip_get_pmu(sc);
		sc->sc_buscore_ops->bc_write(sc, core->co_base +
		    BRCM_CHIP_REG_CHIPCONTROL_ADDR, 3);
		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_CHIPCONTROL_DATA);
		return reg != 0;
	case BRCM_CC_43430_CHIP_ID:
		core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_CHIPCOMMON);
		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_SR_CONTROL1);
		return reg != 0;
	case CY_CC_4373_CHIP_ID:
		core = brcm_chip_get_core(sc, BRCM_AGENT_CORE_CHIPCOMMON);
		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_SR_CONTROL0);
		return (reg & BRCM_CHIP_REG_SR_CONTROL0_ENABLE) != 0;
	case BRCM_CC_4359_CHIP_ID:
	case CY_CC_43752_CHIP_ID:
	case CY_CC_43012_CHIP_ID:
		core = brcm_chip_get_pmu(sc);
		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_RETENTION_CTL);
		return (reg & (BRCM_CHIP_REG_RETENTION_CTL_MACPHY_DIS |
			       BRCM_CHIP_REG_RETENTION_CTL_LOGIC_DIS)) == 0;
	case BRCM_CC_4378_CHIP_ID:
		return 0;
	default:
		core = brcm_chip_get_pmu(sc);
		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_PMUCAPABILITIES_EXT);
		if ((reg & BRCM_CHIP_REG_PMUCAPABILITIES_SR_SUPP) == 0)
			return 0;

		reg = sc->sc_buscore_ops->bc_read(sc, core->co_base +
		    BRCM_CHIP_REG_RETENTION_CTL);
		return (reg & (BRCM_CHIP_REG_RETENTION_CTL_MACPHY_DIS |
			       BRCM_CHIP_REG_RETENTION_CTL_LOGIC_DIS)) == 0;
	}
}

/* RAM size helpers */
void
brcm_chip_socram_ramsize(struct brcm_softc *sc, struct brcm_core *core)
{
	uint32_t coreinfo, nb, lss, banksize, bankinfo;
	uint32_t ramsize = 0, srsize = 0;
	int i;

	if (!sc->sc_chip.ch_core_isup(sc, core))
		sc->sc_chip.ch_core_reset(sc, core, 0, 0, 0);

	coreinfo = sc->sc_buscore_ops->bc_read(sc,
	    core->co_base + BRCM_SOCRAM_COREINFO);
	nb = (coreinfo & BRCM_SOCRAM_COREINFO_SRNB_MASK)
	    >> BRCM_SOCRAM_COREINFO_SRNB_SHIFT;

	if (core->co_rev <= 7 || core->co_rev == 12) {
		banksize = coreinfo & BRCM_SOCRAM_COREINFO_SRBSZ_MASK;
		lss = (coreinfo & BRCM_SOCRAM_COREINFO_LSS_MASK)
		    >> BRCM_SOCRAM_COREINFO_LSS_SHIFT;
		if (lss != 0)
			nb--;
		ramsize = nb * (1 << (banksize + BRCM_SOCRAM_COREINFO_SRBSZ_BASE));
		if (lss != 0)
			ramsize += (1 << ((lss - 1) + BRCM_SOCRAM_COREINFO_SRBSZ_BASE));
	} else {
		for (i = 0; i < nb; i++) {
			sc->sc_buscore_ops->bc_write(sc,
			    core->co_base + BRCM_SOCRAM_BANKIDX,
			    (BRCM_SOCRAM_BANKIDX_MEMTYPE_RAM <<
			    BRCM_SOCRAM_BANKIDX_MEMTYPE_SHIFT) | i);
			bankinfo = sc->sc_buscore_ops->bc_read(sc,
			    core->co_base + BRCM_SOCRAM_BANKINFO);
			banksize = ((bankinfo & BRCM_SOCRAM_BANKINFO_SZMASK) + 1)
			    * BRCM_SOCRAM_BANKINFO_SZBASE;
			ramsize += banksize;
			if (bankinfo & BRCM_SOCRAM_BANKINFO_RETNTRAM_MASK)
				srsize += banksize;
		}
	}

	switch (sc->sc_chip.ch_chip) {
	case BRCM_CC_4334_CHIP_ID:
		if (sc->sc_chip.ch_chiprev < 2)
			srsize = 32 * 1024;
		break;
	case BRCM_CC_43430_CHIP_ID:
		srsize = 64 * 1024;
		break;
	default:
		break;
	}

	sc->sc_chip.ch_ramsize = ramsize;
	sc->sc_chip.ch_srsize = srsize;
}

void
brcm_chip_sysmem_ramsize(struct brcm_softc *sc, struct brcm_core *core)
{
	uint32_t coreinfo, nb, banksize, bankinfo;
	uint32_t ramsize = 0;
	int i;

	if (!sc->sc_chip.ch_core_isup(sc, core))
		sc->sc_chip.ch_core_reset(sc, core, 0, 0, 0);

	coreinfo = sc->sc_buscore_ops->bc_read(sc,
	    core->co_base + BRCM_SOCRAM_COREINFO);
	nb = (coreinfo & BRCM_SOCRAM_COREINFO_SRNB_MASK)
	    >> BRCM_SOCRAM_COREINFO_SRNB_SHIFT;

	for (i = 0; i < nb; i++) {
		sc->sc_buscore_ops->bc_write(sc,
		    core->co_base + BRCM_SOCRAM_BANKIDX,
		    (BRCM_SOCRAM_BANKIDX_MEMTYPE_RAM <<
		    BRCM_SOCRAM_BANKIDX_MEMTYPE_SHIFT) | i);
		bankinfo = sc->sc_buscore_ops->bc_read(sc,
		    core->co_base + BRCM_SOCRAM_BANKINFO);
		banksize = ((bankinfo & BRCM_SOCRAM_BANKINFO_SZMASK) + 1)
		    * BRCM_SOCRAM_BANKINFO_SZBASE;
		ramsize += banksize;
	}

	sc->sc_chip.ch_ramsize = ramsize;
}

void
brcm_chip_tcm_ramsize(struct brcm_softc *sc, struct brcm_core *core)
{
	uint32_t cap, nab, nbb, totb, bxinfo, blksize, ramsize = 0;
	int i;

	cap = sc->sc_buscore_ops->bc_read(sc, core->co_base + BRCM_ARMCR4_CAP);
	nab = (cap & BRCM_ARMCR4_CAP_TCBANB_MASK) >> BRCM_ARMCR4_CAP_TCBANB_SHIFT;
	nbb = (cap & BRCM_ARMCR4_CAP_TCBBNB_MASK) >> BRCM_ARMCR4_CAP_TCBBNB_SHIFT;
	totb = nab + nbb;

	for (i = 0; i < totb; i++) {
		sc->sc_buscore_ops->bc_write(sc,
		    core->co_base + BRCM_ARMCR4_BANKIDX, i);
		bxinfo = sc->sc_buscore_ops->bc_read(sc,
		    core->co_base + BRCM_ARMCR4_BANKINFO);
		if (bxinfo & BRCM_ARMCR4_BANKINFO_BLK_1K_MASK)
			blksize = 1024;
		else
			blksize = 8192;
		ramsize += ((bxinfo & BRCM_ARMCR4_BANKINFO_BSZ_MASK) + 1) *
		    blksize;
	}

	sc->sc_chip.ch_ramsize = ramsize;
}

void
brcm_chip_tcm_rambase(struct brcm_softc *sc)
{
	switch (sc->sc_chip.ch_chip) {
	case BRCM_CC_4345_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x198000;
		break;
	case BRCM_CC_4335_CHIP_ID:
	case BRCM_CC_4339_CHIP_ID:
	case BRCM_CC_4350_CHIP_ID:
	case BRCM_CC_4354_CHIP_ID:
	case BRCM_CC_4356_CHIP_ID:
	case BRCM_CC_43567_CHIP_ID:
	case BRCM_CC_43569_CHIP_ID:
	case BRCM_CC_43570_CHIP_ID:
	case BRCM_CC_4358_CHIP_ID:
	case BRCM_CC_43602_CHIP_ID:
	case BRCM_CC_4371_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x180000;
		break;
	case BRCM_CC_43465_CHIP_ID:
	case BRCM_CC_43525_CHIP_ID:
	case BRCM_CC_4365_CHIP_ID:
	case BRCM_CC_4366_CHIP_ID:
	case BRCM_CC_43664_CHIP_ID:
	case BRCM_CC_43666_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x200000;
		break;
	case BRCM_CC_4359_CHIP_ID:
		if (sc->sc_chip.ch_chiprev < 9)
			sc->sc_chip.ch_rambase = 0x180000;
		else
			sc->sc_chip.ch_rambase = 0x160000;
		break;
	case BRCM_CC_4355_CHIP_ID:
	case BRCM_CC_4364_CHIP_ID:
	case CY_CC_4373_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x160000;
		break;
	case BRCM_CC_4377_CHIP_ID:
	case CY_CC_43752_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x170000;
		break;
	case BRCM_CC_4378_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x352000;
		break;
	case BRCM_CC_4387_CHIP_ID:
		sc->sc_chip.ch_rambase = 0x740000;
		break;
	default:
		printf("%s: unknown chip: %d\n", DEVNAME(sc),
		    sc->sc_chip.ch_chip);
		break;
	}
}

/* BCDC protocol implementation */
int
brcm_proto_bcdc_query_dcmd(struct brcm_softc *sc, int ifidx,
    int cmd, char *buf, size_t *len)
{
	struct brcm_proto_bcdc_dcmd *dcmd;
	size_t size = sizeof(dcmd->hdr) + *len;
	int ret = 1, reqid;

	reqid = sc->sc_bcdc_reqid++;

	if (*len > sizeof(dcmd->buf))
		return ret;

	dcmd = malloc(size, M_TEMP, M_WAITOK | M_ZERO);
	dcmd->hdr.cmd = htole32(cmd);
	dcmd->hdr.len = htole32(*len);
	dcmd->hdr.flags |= BRCM_BCDC_DCMD_GET;
	dcmd->hdr.flags |= BRCM_BCDC_DCMD_ID_SET(reqid);
	dcmd->hdr.flags |= BRCM_BCDC_DCMD_IF_SET(ifidx);
	dcmd->hdr.flags = htole32(dcmd->hdr.flags);
	memcpy(&dcmd->buf, buf, *len);

	if (brcm_proto_bcdc_txctl(sc, reqid, (char *)dcmd, &size)) {
		DPRINTF(("%s: tx failed\n", DEVNAME(sc)));
		return ret;
	}

	if (buf) {
		*len = min(*len, size);
		memcpy(buf, dcmd->buf, *len);
	}

	if (dcmd->hdr.flags & BRCM_BCDC_DCMD_ERROR)
		ret = dcmd->hdr.status;
	else
		ret = 0;
	free(dcmd, M_TEMP, size);
	return ret;
}

int
brcm_proto_bcdc_set_dcmd(struct brcm_softc *sc, int ifidx,
    int cmd, char *buf, size_t len)
{
	struct brcm_proto_bcdc_dcmd *dcmd;
	size_t size = sizeof(dcmd->hdr) + len;
	int ret = 1, reqid;

	reqid = sc->sc_bcdc_reqid++;

	if (len > sizeof(dcmd->buf))
		return ret;

	dcmd = malloc(size, M_TEMP, M_WAITOK | M_ZERO);
	dcmd->hdr.cmd = htole32(cmd);
	dcmd->hdr.len = htole32(len);
	dcmd->hdr.flags |= BRCM_BCDC_DCMD_SET;
	dcmd->hdr.flags |= BRCM_BCDC_DCMD_ID_SET(reqid);
	dcmd->hdr.flags |= BRCM_BCDC_DCMD_IF_SET(ifidx);
	dcmd->hdr.flags = htole32(dcmd->hdr.flags);
	memcpy(&dcmd->buf, buf, len);

	if (brcm_proto_bcdc_txctl(sc, reqid, (char *)dcmd, &size)) {
		DPRINTF(("%s: txctl failed\n", DEVNAME(sc)));
		return ret;
	}

	if (dcmd->hdr.flags & BRCM_BCDC_DCMD_ERROR)
		ret = dcmd->hdr.status;
	else
		ret = 0;
	free(dcmd, M_TEMP, size);
	return ret;
}

int
brcm_proto_bcdc_txctl(struct brcm_softc *sc, int reqid, char *buf, size_t *len)
{
	struct brcm_proto_bcdc_ctl *ctl, *tmp;
	int timeout = 0;

	ctl = malloc(sizeof(*ctl), M_TEMP, M_WAITOK|M_ZERO);
	ctl->reqid = reqid;
	ctl->buf = buf;
	ctl->len = *len;

	if (sc->sc_bus_ops->bs_txctl(sc, ctl)) {
		DPRINTF(("%s: tx failed\n", DEVNAME(sc)));
		return 1;
	}

	if (tsleep_nsec(ctl, PWAIT, "brcm", SEC_TO_NSEC(1)))
		timeout = 1;

	TAILQ_FOREACH_SAFE(ctl, &sc->sc_bcdc_rxctlq, next, tmp) {
		if (ctl->reqid != reqid)
			continue;
		if (ctl->done) {
			TAILQ_REMOVE(&sc->sc_bcdc_rxctlq, ctl, next);
			*len = ctl->len;
			free(ctl, M_TEMP, sizeof(*ctl));
			return 0;
		}
		if (timeout) {
			TAILQ_REMOVE(&sc->sc_bcdc_rxctlq, ctl, next);
			DPRINTF(("%s: timeout waiting for txctl response\n",
			    DEVNAME(sc)));
			free(ctl->buf, M_TEMP, ctl->len);
			free(ctl, M_TEMP, sizeof(*ctl));
			return 1;
		}
		break;
	}

	DPRINTF(("%s: did%s find txctl metadata (timeout %d)\n",
	    DEVNAME(sc), ctl == NULL ? " not": "", timeout));
	return 1;
}

void
brcm_proto_bcdc_rxctl(struct brcm_softc *sc, char *buf, size_t len)
{
	struct brcm_proto_bcdc_dcmd *dcmd;
	struct brcm_proto_bcdc_ctl *ctl, *tmp;

	if (len < sizeof(dcmd->hdr))
		return;

	dcmd = (struct brcm_proto_bcdc_dcmd *)buf;
	dcmd->hdr.cmd = letoh32(dcmd->hdr.cmd);
	dcmd->hdr.len = letoh32(dcmd->hdr.len);
	dcmd->hdr.flags = letoh32(dcmd->hdr.flags);
	dcmd->hdr.status = letoh32(dcmd->hdr.status);

	TAILQ_FOREACH_SAFE(ctl, &sc->sc_bcdc_rxctlq, next, tmp) {
		if (ctl->reqid != BRCM_BCDC_DCMD_ID_GET(dcmd->hdr.flags))
			continue;
		if (ctl->len != len) {
			free(ctl->buf, M_TEMP, ctl->len);
			free(ctl, M_TEMP, sizeof(*ctl));
			return;
		}
		memcpy(ctl->buf, buf, len);
		ctl->done = 1;
		wakeup(ctl);
		return;
	}
}

void
brcm_proto_bcdc_rx(struct brcm_softc *sc, struct mbuf *m, struct mbuf_list *ml)
{
	struct brcm_proto_bcdc_hdr *hdr;

	hdr = mtod(m, struct brcm_proto_bcdc_hdr *);
	if (m->m_len < sizeof(*hdr)) {
		m_freem(m);
		return;
	}
	if (m->m_len < sizeof(*hdr) + (hdr->data_offset << 2)) {
		m_freem(m);
		return;
	}
	m_adj(m, sizeof(*hdr) + (hdr->data_offset << 2));

	brcm_rx(sc, m, ml);
}

/* FW Variable code */
int
brcm_fwvar_cmd_get_data(struct brcm_softc *sc, int cmd, void *data, size_t len)
{
	return sc->sc_proto_ops->proto_query_dcmd(sc, 0, cmd, data, &len);
}

int
brcm_fwvar_cmd_set_data(struct brcm_softc *sc, int cmd, void *data, size_t len)
{
	return sc->sc_proto_ops->proto_set_dcmd(sc, 0, cmd, data, len);
}

int
brcm_fwvar_cmd_get_int(struct brcm_softc *sc, int cmd, uint32_t *data)
{
	int ret;
	ret = brcm_fwvar_cmd_get_data(sc, cmd, data, sizeof(*data));
	*data = letoh32(*data);
	return ret;
}

int
brcm_fwvar_cmd_set_int(struct brcm_softc *sc, int cmd, uint32_t data)
{
	data = htole32(data);
	return brcm_fwvar_cmd_set_data(sc, cmd, &data, sizeof(data));
}

int
brcm_fwvar_var_get_data(struct brcm_softc *sc, char *name, void *data, size_t len)
{
	char *buf;
	int ret;

	buf = malloc(strlen(name) + 1 + len, M_TEMP, M_WAITOK);
	memcpy(buf, name, strlen(name) + 1);
	memcpy(buf + strlen(name) + 1, data, len);
	ret = brcm_fwvar_cmd_get_data(sc, BRCM_C_GET_VAR,
	    buf, strlen(name) + 1 + len);
	memcpy(data, buf, len);
	free(buf, M_TEMP, strlen(name) + 1 + len);
	return ret;
}

int
brcm_fwvar_var_set_data(struct brcm_softc *sc, char *name, void *data, size_t len)
{
	char *buf;
	int ret;

	buf = malloc(strlen(name) + 1 + len, M_TEMP, M_WAITOK);
	memcpy(buf, name, strlen(name) + 1);
	memcpy(buf + strlen(name) + 1, data, len);
	ret = brcm_fwvar_cmd_set_data(sc, BRCM_C_SET_VAR,
	    buf, strlen(name) + 1 + len);
	free(buf, M_TEMP, strlen(name) + 1 + len);
	return ret;
}

int
brcm_fwvar_var_get_int(struct brcm_softc *sc, char *name, uint32_t *data)
{
	int ret;
	ret = brcm_fwvar_var_get_data(sc, name, data, sizeof(*data));
	*data = letoh32(*data);
	return ret;
}

int
brcm_fwvar_var_set_int(struct brcm_softc *sc, char *name, uint32_t data)
{
	data = htole32(data);
	return brcm_fwvar_var_set_data(sc, name, &data, sizeof(data));
}

/* Channel parameters */
uint32_t
brcm_chan2spec(struct brcm_softc *sc, struct ieee80211_channel *c)
{
	if (sc->sc_io_type == BRCM_IO_TYPE_D11N)
		return brcm_chan2spec_d11n(sc, c);
	else
		return brcm_chan2spec_d11ac(sc, c);
}

uint32_t
brcm_chan2spec_d11n(struct brcm_softc *sc, struct ieee80211_channel *c)
{
	uint32_t chanspec;

	chanspec = ieee80211_mhz2ieee(c->ic_freq, 0) & BRCM_CHANSPEC_CHAN_MASK;
	chanspec |= BRCM_CHANSPEC_D11N_SB_N;
	chanspec |= BRCM_CHANSPEC_D11N_BW_20;
	if (IEEE80211_IS_CHAN_2GHZ(c))
		chanspec |= BRCM_CHANSPEC_D11N_BND_2G;
	if (IEEE80211_IS_CHAN_5GHZ(c))
		chanspec |= BRCM_CHANSPEC_D11N_BND_5G;

	return chanspec;
}

uint32_t
brcm_chan2spec_d11ac(struct brcm_softc *sc, struct ieee80211_channel *c)
{
	uint32_t chanspec;

	chanspec = ieee80211_mhz2ieee(c->ic_freq, 0) & BRCM_CHANSPEC_CHAN_MASK;
	chanspec |= BRCM_CHANSPEC_D11AC_SB_LLL;
	chanspec |= BRCM_CHANSPEC_D11AC_BW_20;
	if (IEEE80211_IS_CHAN_2GHZ(c))
		chanspec |= BRCM_CHANSPEC_D11AC_BND_2G;
	if (IEEE80211_IS_CHAN_5GHZ(c))
		chanspec |= BRCM_CHANSPEC_D11AC_BND_5G;

	return chanspec;
}

uint32_t
brcm_spec2chan(struct brcm_softc *sc, uint32_t chanspec)
{
	if (sc->sc_io_type == BRCM_IO_TYPE_D11N)
		return brcm_spec2chan_d11n(sc, chanspec);
	else
		return brcm_spec2chan_d11ac(sc, chanspec);
}

uint32_t
brcm_spec2chan_d11n(struct brcm_softc *sc, uint32_t chanspec)
{
	uint32_t chanidx;

	chanidx = chanspec & BRCM_CHANSPEC_CHAN_MASK;

	switch (chanspec & BRCM_CHANSPEC_D11N_BW_MASK) {
	case BRCM_CHANSPEC_D11N_BW_40:
		switch (chanspec & BRCM_CHANSPEC_D11N_SB_MASK) {
		case BRCM_CHANSPEC_D11N_SB_L:
			chanidx -= 2;
			break;
		case BRCM_CHANSPEC_D11N_SB_U:
			chanidx += 2;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return chanidx;
}

uint32_t
brcm_spec2chan_d11ac(struct brcm_softc *sc, uint32_t chanspec)
{
	uint32_t chanidx;

	chanidx = chanspec & BRCM_CHANSPEC_CHAN_MASK;

	switch (chanspec & BRCM_CHANSPEC_D11AC_BW_MASK) {
	case BRCM_CHANSPEC_D11AC_BW_40:
		switch (chanspec & BRCM_CHANSPEC_D11AC_SB_MASK) {
		case BRCM_CHANSPEC_D11AC_SB_LLL:
			chanidx -= 2;
			break;
		case BRCM_CHANSPEC_D11AC_SB_LLU:
			chanidx += 2;
			break;
		default:
			break;
		}
		break;
	case BRCM_CHANSPEC_D11AC_BW_80:
		switch (chanspec & BRCM_CHANSPEC_D11AC_SB_MASK) {
		case BRCM_CHANSPEC_D11AC_SB_LLL:
			chanidx -= 6;
			break;
		case BRCM_CHANSPEC_D11AC_SB_LLU:
			chanidx -= 2;
			break;
		case BRCM_CHANSPEC_D11AC_SB_LUL:
			chanidx += 2;
			break;
		case BRCM_CHANSPEC_D11AC_SB_LUU:
			chanidx += 6;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return chanidx;
}

/* 802.11 code */
void
brcm_connect(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct brcm_ext_join_params *params;
	uint8_t buf[64];	/* XXX max WPA/RSN/WMM IE length */
	uint8_t *frm;

	/*
	 * OPEN: Open or WPA/WPA2 on newer Chips/Firmware.
	 * SHARED KEY: WEP.
	 * AUTO: Automatic, probably for older Chips/Firmware.
	 */
	if (ic->ic_flags & IEEE80211_F_RSNON) {
		uint32_t wsec = 0;
		uint32_t wpa = 0;

		/* tell firmware to add WPA/RSN IE to (re)assoc request */
		if (ic->ic_bss->ni_rsnprotos == IEEE80211_PROTO_RSN)
			frm = ieee80211_add_rsn(buf, ic, ic->ic_bss);
		else
			frm = ieee80211_add_wpa(buf, ic, ic->ic_bss);
		brcm_fwvar_var_set_data(sc, "wpaie", buf, frm - buf);

		if (ic->ic_rsnprotos & IEEE80211_PROTO_WPA) {
			if (ic->ic_rsnakms & IEEE80211_AKM_PSK)
				wpa |= BRCM_WPA_AUTH_WPA_PSK;
			if (ic->ic_rsnakms & IEEE80211_AKM_8021X)
				wpa |= BRCM_WPA_AUTH_WPA_UNSPECIFIED;
		}
		if (ic->ic_rsnprotos & IEEE80211_PROTO_RSN) {
			if (ic->ic_rsnakms & IEEE80211_AKM_PSK)
				wpa |= BRCM_WPA_AUTH_WPA2_PSK;
			if (ic->ic_rsnakms & IEEE80211_AKM_SHA256_PSK)
				wpa |= BRCM_WPA_AUTH_WPA2_PSK_SHA256;
			if (ic->ic_rsnakms & IEEE80211_AKM_8021X)
				wpa |= BRCM_WPA_AUTH_WPA2_UNSPECIFIED;
			if (ic->ic_rsnakms & IEEE80211_AKM_SHA256_8021X)
				wpa |= BRCM_WPA_AUTH_WPA2_1X_SHA256;
		}
		if (ic->ic_rsnciphers & IEEE80211_WPA_CIPHER_TKIP ||
		    ic->ic_rsngroupcipher & IEEE80211_WPA_CIPHER_TKIP)
			wsec |= BRCM_WSEC_TKIP;
		if (ic->ic_rsnciphers & IEEE80211_WPA_CIPHER_CCMP ||
		    ic->ic_rsngroupcipher & IEEE80211_WPA_CIPHER_CCMP)
			wsec |= BRCM_WSEC_AES;

		brcm_fwvar_var_set_int(sc, "wpa_auth", wpa);
		brcm_fwvar_var_set_int(sc, "wsec", wsec);
	} else {
		brcm_fwvar_var_set_int(sc, "wpa_auth", BRCM_WPA_AUTH_DISABLED);
		brcm_fwvar_var_set_int(sc, "wsec", BRCM_WSEC_NONE);
	}
	brcm_fwvar_var_set_int(sc, "auth", BRCM_AUTH_OPEN);
	brcm_fwvar_var_set_int(sc, "mfp", BRCM_MFP_NONE);

	if (ic->ic_des_esslen && ic->ic_des_esslen <= BRCM_MAX_SSID_LEN) {
		params = malloc(sizeof(*params), M_TEMP, M_WAITOK | M_ZERO);
		memcpy(params->ssid.ssid, ic->ic_des_essid, ic->ic_des_esslen);
		params->ssid.len = htole32(ic->ic_des_esslen);
		memcpy(params->assoc.bssid, ic->ic_bss->ni_bssid,
		    sizeof(params->assoc.bssid));
		params->scan.scan_type = -1;
		params->scan.nprobes = htole32(-1);
		params->scan.active_time = htole32(-1);
		params->scan.passive_time = htole32(-1);
		params->scan.home_time = htole32(-1);
		if (brcm_fwvar_var_set_data(sc, "join", params, sizeof(*params))) {
			struct brcm_join_params join;
			memset(&join, 0, sizeof(join));
			memcpy(join.ssid.ssid, ic->ic_des_essid,
			    ic->ic_des_esslen);
			join.ssid.len = htole32(ic->ic_des_esslen);
			memcpy(join.assoc.bssid, ic->ic_bss->ni_bssid,
			    sizeof(join.assoc.bssid));
			brcm_fwvar_cmd_set_data(sc, BRCM_C_SET_SSID, &join,
			    sizeof(join));
		}
		free(params, M_TEMP, sizeof(*params));
	}
}

#ifndef IEEE80211_STA_ONLY
void
brcm_hostap(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct brcm_join_params join;

	/*
	 * OPEN: Open or WPA/WPA2 on newer Chips/Firmware.
	 * SHARED KEY: WEP.
	 * AUTO: Automatic, probably for older Chips/Firmware.
	 */
	if (ic->ic_flags & IEEE80211_F_RSNON) {
		uint32_t wsec = 0;
		uint32_t wpa = 0;

		/* TODO: Turn off if replay counter set */
		if (ni->ni_rsnprotos & IEEE80211_PROTO_RSN)
			brcm_fwvar_var_set_int(sc, "wme_bss_disable", 1);

		if (ni->ni_rsnprotos & IEEE80211_PROTO_WPA) {
			if (ni->ni_rsnakms & IEEE80211_AKM_PSK)
				wpa |= BRCM_WPA_AUTH_WPA_PSK;
			if (ni->ni_rsnakms & IEEE80211_AKM_8021X)
				wpa |= BRCM_WPA_AUTH_WPA_UNSPECIFIED;
		}
		if (ni->ni_rsnprotos & IEEE80211_PROTO_RSN) {
			if (ni->ni_rsnakms & IEEE80211_AKM_PSK)
				wpa |= BRCM_WPA_AUTH_WPA2_PSK;
			if (ni->ni_rsnakms & IEEE80211_AKM_SHA256_PSK)
				wpa |= BRCM_WPA_AUTH_WPA2_PSK_SHA256;
			if (ni->ni_rsnakms & IEEE80211_AKM_8021X)
				wpa |= BRCM_WPA_AUTH_WPA2_UNSPECIFIED;
			if (ni->ni_rsnakms & IEEE80211_AKM_SHA256_8021X)
				wpa |= BRCM_WPA_AUTH_WPA2_1X_SHA256;
		}
		if (ni->ni_rsnciphers & IEEE80211_WPA_CIPHER_TKIP ||
		    ni->ni_rsngroupcipher & IEEE80211_WPA_CIPHER_TKIP)
			wsec |= BRCM_WSEC_TKIP;
		if (ni->ni_rsnciphers & IEEE80211_WPA_CIPHER_CCMP ||
		    ni->ni_rsngroupcipher & IEEE80211_WPA_CIPHER_CCMP)
			wsec |= BRCM_WSEC_AES;

		brcm_fwvar_var_set_int(sc, "wpa_auth", wpa);
		brcm_fwvar_var_set_int(sc, "wsec", wsec);
	} else {
		brcm_fwvar_var_set_int(sc, "wpa_auth", BRCM_WPA_AUTH_DISABLED);
		brcm_fwvar_var_set_int(sc, "wsec", BRCM_WSEC_NONE);
	}
	brcm_fwvar_var_set_int(sc, "auth", BRCM_AUTH_OPEN);
	brcm_fwvar_var_set_int(sc, "mfp", BRCM_MFP_NONE);

	brcm_fwvar_var_set_int(sc, "mpc", 0);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_INFRA, 1);
	brcm_fwvar_cmd_set_int(sc, BRCM_C_SET_AP, 1);
	brcm_fwvar_var_set_int(sc, "chanspec",
	    brcm_chan2spec(sc, ic->ic_bss->ni_chan));
	brcm_fwvar_cmd_set_int(sc, BRCM_C_UP, 1);

	memset(&join, 0, sizeof(join));
	memcpy(join.ssid.ssid, ic->ic_des_essid, ic->ic_des_esslen);
	join.ssid.len = htole32(ic->ic_des_esslen);
	memset(join.assoc.bssid, 0xff, sizeof(join.assoc.bssid));
	brcm_fwvar_cmd_set_data(sc, BRCM_C_SET_SSID, &join, sizeof(join));
	brcm_fwvar_var_set_int(sc, "closednet",
	    (ic->ic_userflags & IEEE80211_F_HIDENWID) != 0);
}
#endif

void
brcm_scan_v0(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct brcm_escan_params_v0 *params;
	uint32_t nssid = 0, nchan = 0;
	size_t params_size, chan_size, ssid_size;
	struct brcm_ssid *ssid;

	if (ic->ic_flags & IEEE80211_F_ASCAN &&
	    ic->ic_des_esslen && ic->ic_des_esslen <= BRCM_MAX_SSID_LEN)
		nssid = 1;

	chan_size = roundup(nchan * sizeof(uint16_t), sizeof(uint32_t));
	ssid_size = sizeof(struct brcm_ssid) * nssid;
	params_size = sizeof(*params) + chan_size + ssid_size;

	params = malloc(params_size, M_TEMP, M_WAITOK | M_ZERO);
	ssid = (struct brcm_ssid *)
	    (((uint8_t *)params) + sizeof(*params) + chan_size);

	memset(params->scan_params.bssid, 0xff,
	    sizeof(params->scan_params.bssid));
	params->scan_params.bss_type = 2;
	params->scan_params.scan_type = BRCM_SCANTYPE_PASSIVE;
	params->scan_params.nprobes = htole32(-1);
	params->scan_params.active_time = htole32(-1);
	params->scan_params.passive_time = htole32(-1);
	params->scan_params.home_time = htole32(-1);
	params->version = htole32(BRCM_ESCAN_REQ_VERSION);
	params->action = htole16(WL_ESCAN_ACTION_START);
	params->sync_id = htole16(0x1234);

	if (ic->ic_flags & IEEE80211_F_ASCAN &&
	    ic->ic_des_esslen && ic->ic_des_esslen <= BRCM_MAX_SSID_LEN) {
		params->scan_params.scan_type = BRCM_SCANTYPE_ACTIVE;
		ssid->len = htole32(ic->ic_des_esslen);
		memcpy(ssid->ssid, ic->ic_des_essid, ic->ic_des_esslen);
	}

	params->scan_params.channel_num = htole32(
	    nssid << BRCM_CHANNUM_NSSID_SHIFT |
	    nchan << BRCM_CHANNUM_NCHAN_SHIFT);

#if 0
	/* Scan a specific channel */
	params->scan_params.channel_list[0] = htole16(
	    (1 & 0xff) << 0 |
	    (3 & 0x3) << 8 |
	    (2 & 0x3) << 10 |
	    (2 & 0x3) << 12
	    );
#endif

	brcm_fwvar_var_set_data(sc, "escan", params, params_size);
	free(params, M_TEMP, params_size);
}

void
brcm_scan_v2(struct brcm_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct brcm_escan_params_v2 *params;
	uint32_t nssid = 0, nchan = 0;
	size_t params_size, chan_size, ssid_size;
	struct brcm_ssid *ssid;

	if (ic->ic_flags & IEEE80211_F_ASCAN &&
	    ic->ic_des_esslen && ic->ic_des_esslen <= BRCM_MAX_SSID_LEN)
		nssid = 1;

	chan_size = roundup(nchan * sizeof(uint16_t), sizeof(uint32_t));
	ssid_size = sizeof(struct brcm_ssid) * nssid;
	params_size = sizeof(*params) + chan_size + ssid_size;

	params = malloc(params_size, M_TEMP, M_WAITOK | M_ZERO);
	ssid = (struct brcm_ssid *)
	    (((uint8_t *)params) + sizeof(*params) + chan_size);

	params->scan_params.version = 2;
	params->scan_params.length = params_size;
	memset(params->scan_params.bssid, 0xff,
	    sizeof(params->scan_params.bssid));
	params->scan_params.bss_type = 2;
	params->scan_params.scan_type = BRCM_SCANTYPE_PASSIVE;
	params->scan_params.nprobes = htole32(-1);
	params->scan_params.active_time = htole32(-1);
	params->scan_params.passive_time = htole32(-1);
	params->scan_params.home_time = htole32(-1);
	params->version = htole32(BRCM_ESCAN_REQ_VERSION_V2);
	params->action = htole16(WL_ESCAN_ACTION_START);
	params->sync_id = htole16(0x1234);

	if (ic->ic_flags & IEEE80211_F_ASCAN &&
	    ic->ic_des_esslen && ic->ic_des_esslen <= BRCM_MAX_SSID_LEN) {
		params->scan_params.scan_type = BRCM_SCANTYPE_ACTIVE;
		ssid->len = htole32(ic->ic_des_esslen);
		memcpy(ssid->ssid, ic->ic_des_essid, ic->ic_des_esslen);
	}

	params->scan_params.channel_num = htole32(
	    nssid << BRCM_CHANNUM_NSSID_SHIFT |
	    nchan << BRCM_CHANNUM_NCHAN_SHIFT);

#if 0
	/* Scan a specific channel */
	params->scan_params.channel_list[0] = htole16(
	    (1 & 0xff) << 0 |
	    (3 & 0x3) << 8 |
	    (2 & 0x3) << 10 |
	    (2 & 0x3) << 12
	    );
#endif

	brcm_fwvar_var_set_data(sc, "escan", params, params_size);
	free(params, M_TEMP, params_size);
}

void
brcm_scan(struct brcm_softc *sc)
{
	if (sc->sc_scan_ver == 0)
		brcm_scan_v0(sc);
	else
		brcm_scan_v2(sc);
}

void
brcm_scan_abort_v0(struct brcm_softc *sc)
{
	struct brcm_escan_params_v0 *params;
	size_t params_size;

	params_size = sizeof(*params) + sizeof(uint16_t);
	params = malloc(params_size, M_TEMP, M_WAITOK | M_ZERO);
	memset(params->scan_params.bssid, 0xff,
	    sizeof(params->scan_params.bssid));
	params->scan_params.bss_type = 2;
	params->scan_params.scan_type = BRCM_SCANTYPE_PASSIVE;
	params->scan_params.nprobes = htole32(-1);
	params->scan_params.active_time = htole32(-1);
	params->scan_params.passive_time = htole32(-1);
	params->scan_params.home_time = htole32(-1);
	params->version = htole32(BRCM_ESCAN_REQ_VERSION);
	params->action = htole16(WL_ESCAN_ACTION_START);
	params->sync_id = htole16(0x1234);
	params->scan_params.channel_num = htole32(1);
	params->scan_params.channel_list[0] = htole16(-1);
	brcm_fwvar_var_set_data(sc, "escan", params, params_size);
	free(params, M_TEMP, params_size);
}

void
brcm_scan_abort_v2(struct brcm_softc *sc)
{
	struct brcm_escan_params_v2 *params;
	size_t params_size;

	params_size = sizeof(*params) + sizeof(uint16_t);
	params = malloc(params_size, M_TEMP, M_WAITOK | M_ZERO);
	params->scan_params.version = 2;
	params->scan_params.length = params_size;
	memset(params->scan_params.bssid, 0xff,
	    sizeof(params->scan_params.bssid));
	params->scan_params.bss_type = 2;
	params->scan_params.scan_type = BRCM_SCANTYPE_PASSIVE;
	params->scan_params.nprobes = htole32(-1);
	params->scan_params.active_time = htole32(-1);
	params->scan_params.passive_time = htole32(-1);
	params->scan_params.home_time = htole32(-1);
	params->version = htole32(BRCM_ESCAN_REQ_VERSION_V2);
	params->action = htole16(WL_ESCAN_ACTION_START);
	params->sync_id = htole16(0x1234);
	params->scan_params.channel_num = htole32(1);
	params->scan_params.channel_list[0] = htole16(-1);
	brcm_fwvar_var_set_data(sc, "escan", params, params_size);
	free(params, M_TEMP, params_size);
}

void
brcm_scan_abort(struct brcm_softc *sc)
{
	if (sc->sc_scan_ver == 0)
		brcm_scan_abort_v0(sc);
	else
		brcm_scan_abort_v2(sc);
}

struct mbuf *
brcm_newbuf(void)
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

void
brcm_rx(struct brcm_softc *sc, struct mbuf *m, struct mbuf_list *ml)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct ieee80211_node *ni;
	struct brcm_event *e;

#ifdef __STRICT_ALIGNMENT
	/* Remaining data is an ethernet packet, so align. */
	if ((mtod(m, paddr_t) & 0x3) != ETHER_ALIGN) {
		struct mbuf *m0;
		m0 = m_dup_pkt(m, ETHER_ALIGN, M_WAITOK);
		m_freem(m);
		if (m0 == NULL) {
			ifp->if_ierrors++;
			return;
		}
		m = m0;
	}
#endif

	e = mtod(m, struct brcm_event *);
	if (m->m_len >= sizeof(e->ehdr) &&
	    ntohs(e->ehdr.ether_type) == BRCM_ETHERTYPE_LINK_CTL &&
	    memcmp(BRCM_BRCM_OUI, e->hdr.oui, sizeof(e->hdr.oui)) == 0 &&
	    ntohs(e->hdr.usr_subtype) == BRCM_BRCM_SUBTYPE_EVENT) {
		brcm_rx_event(sc, m);
		return;
	}

	/* Drop network packets if we are not in RUN state. */
	if (ic->ic_state != IEEE80211_S_RUN) {
		m_freem(m);
		return;
	}

	if ((ic->ic_flags & IEEE80211_F_RSNON) &&
	    m->m_len >= sizeof(e->ehdr) &&
	    ntohs(e->ehdr.ether_type) == ETHERTYPE_EAPOL) {
		ifp->if_ipackets++;
#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_IN);
#endif
#ifndef IEEE80211_STA_ONLY
		if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
			ni = ieee80211_find_node(ic,
			    (void *)&e->ehdr.ether_shost);
			if (ni == NULL) {
				m_freem(m);
				return;
			}
		} else
#endif
			ni = ic->ic_bss;
		ieee80211_eapol_key_input(ic, m, ni);
	} else
		ml_enqueue(ml, m);
}

#ifndef IEEE80211_STA_ONLY
void
brcm_rx_auth_ind(struct brcm_softc *sc, struct brcm_event *e, size_t len)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct ieee80211_rxinfo rxi;
	struct ieee80211_frame *wh;
	struct mbuf *m;
	uint32_t pktlen, ieslen;

	/* Build a fake beacon frame to let net80211 do all the parsing. */
	ieslen = betoh32(e->msg.datalen);
	pktlen = sizeof(*wh) + ieslen + 6;
	if (pktlen > MCLBYTES)
		return;
	m = brcm_newbuf();
	if (m == NULL)
		return;
	wh = mtod(m, struct ieee80211_frame *);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    IEEE80211_FC0_SUBTYPE_AUTH;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->i_dur = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, &e->msg.addr);
	IEEE80211_ADDR_COPY(wh->i_addr3, ic->ic_bss->ni_bssid);
	*(uint16_t *)wh->i_seq = 0;
	((uint16_t *)(&wh[1]))[0] = IEEE80211_AUTH_ALG_OPEN;
	((uint16_t *)(&wh[1]))[1] = IEEE80211_AUTH_OPEN_REQUEST;
	((uint16_t *)(&wh[1]))[2] = 0;

	/* Finalize mbuf. */
	m->m_pkthdr.len = m->m_len = pktlen;
	memset(&rxi, 0, sizeof(rxi));
	ieee80211_input(ifp, m, ic->ic_bss, &rxi);
}

void
brcm_rx_assoc_ind(struct brcm_softc *sc, struct brcm_event *e, size_t len,
    int reassoc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct ieee80211_rxinfo rxi;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct mbuf *m;
	uint32_t pktlen, ieslen;

	/* Build a fake beacon frame to let net80211 do all the parsing. */
	ieslen = betoh32(e->msg.datalen);
	pktlen = sizeof(*wh) + ieslen + 4;
	if (reassoc)
		pktlen += IEEE80211_ADDR_LEN;
	if (pktlen > MCLBYTES)
		return;
	m = brcm_newbuf();
	if (m == NULL)
		return;
	wh = mtod(m, struct ieee80211_frame *);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT;
	if (reassoc)
	    wh->i_fc[0] |= IEEE80211_FC0_SUBTYPE_REASSOC_REQ;
	else
	    wh->i_fc[0] |= IEEE80211_FC0_SUBTYPE_ASSOC_REQ;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->i_dur = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, &e->msg.addr);
	IEEE80211_ADDR_COPY(wh->i_addr3, ic->ic_bss->ni_bssid);
	*(uint16_t *)wh->i_seq = 0;
	((uint16_t *)(&wh[1]))[0] = IEEE80211_CAPINFO_ESS; /* XXX */
	((uint16_t *)(&wh[1]))[1] = 100; /* XXX */
	if (reassoc) {
		memset(((uint8_t *)&wh[1]) + 4, 0, IEEE80211_ADDR_LEN);
		memcpy(((uint8_t *)&wh[1]) + 4 + IEEE80211_ADDR_LEN,
		    &e[1], ieslen);
	} else
		memcpy(((uint8_t *)&wh[1]) + 4, &e[1], ieslen);

	/* Finalize mbuf. */
	m->m_pkthdr.len = m->m_len = pktlen;
	ni = ieee80211_find_node(ic, wh->i_addr2);
	if (ni == NULL) {
		m_freem(m);
		return;
	}
	memset(&rxi, 0, sizeof(rxi));
	ieee80211_input(ifp, m, ni, &rxi);
}

void
brcm_rx_deauth_ind(struct brcm_softc *sc, struct brcm_event *e, size_t len)
{
	brcm_rx_leave_ind(sc, e, len, IEEE80211_FC0_SUBTYPE_DEAUTH);
}

void
brcm_rx_disassoc_ind(struct brcm_softc *sc, struct brcm_event *e, size_t len)
{
	brcm_rx_leave_ind(sc, e, len, IEEE80211_FC0_SUBTYPE_DISASSOC);
}

void
brcm_rx_leave_ind(struct brcm_softc *sc, struct brcm_event *e, size_t len,
    int subtype)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct ieee80211_rxinfo rxi;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct mbuf *m;
	uint32_t pktlen;

	/* Build a fake beacon frame to let net80211 do all the parsing. */
	pktlen = sizeof(*wh) + 2;
	if (pktlen > MCLBYTES)
		return;
	m = brcm_newbuf();
	if (m == NULL)
		return;
	wh = mtod(m, struct ieee80211_frame *);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    subtype;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->i_dur = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, &e->msg.addr);
	IEEE80211_ADDR_COPY(wh->i_addr3, ic->ic_bss->ni_bssid);
	*(uint16_t *)wh->i_seq = 0;
	memset((uint8_t *)&wh[1], 0, 2);

	/* Finalize mbuf. */
	m->m_pkthdr.len = m->m_len = pktlen;
	ni = ieee80211_find_node(ic, wh->i_addr2);
	if (ni == NULL) {
		m_freem(m);
		return;
	}
	memset(&rxi, 0, sizeof(rxi));
	ieee80211_input(ifp, m, ni, &rxi);
}
#endif

void
brcm_rx_event(struct brcm_softc *sc, struct mbuf *m)
{
	int s;

	s = splnet();
	ml_enqueue(&sc->sc_evml, m);
	splx(s);

	task_add(sc->sc_taskq, &sc->sc_task);
}

void
brcm_rx_event_cb(struct brcm_softc *sc, struct mbuf *m)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct brcm_event *e = mtod(m, void *);
	size_t len = m->m_len;

	if (ntohl(e->msg.event_type) >= BRCM_E_LAST) {
		m_freem(m);
		return;
	}

	switch (ntohl(e->msg.event_type)) {
	case BRCM_E_ESCAN_RESULT: {
		struct brcm_escan_results *res;
		struct brcm_bss_info *bss;
		size_t reslen;
		int i;
		/* Abort event triggered by SCAN -> INIT */
		if (ic->ic_state == IEEE80211_S_INIT &&
		    ntohl(e->msg.status) == BRCM_E_STATUS_ABORT)
			break;
		if (ic->ic_state != IEEE80211_S_SCAN) {
			DPRINTF(("%s: scan result (%u) while not in SCAN\n",
			    DEVNAME(sc), ntohl(e->msg.status)));
			break;
		}
		if (ntohl(e->msg.status) != BRCM_E_STATUS_SUCCESS &&
		    ntohl(e->msg.status) != BRCM_E_STATUS_PARTIAL) {
			DPRINTF(("%s: unexpected scan result (%u)\n",
			    DEVNAME(sc), ntohl(e->msg.status)));
			break;
		}
		if (ntohl(e->msg.status) == BRCM_E_STATUS_SUCCESS) {
			ieee80211_end_scan(ifp);
			break;
		}
		len -= sizeof(*e);
		if (len < sizeof(*res)) {
			DPRINTF(("%s: results too small\n", DEVNAME(sc)));
			m_freem(m);
			return;
		}
		reslen = len;
		res = malloc(len, M_TEMP, M_WAITOK);
		memcpy(res, (void *)&e[1], len);
		if (len < letoh32(res->buflen)) {
			DPRINTF(("%s: results too small\n", DEVNAME(sc)));
			free(res, M_TEMP, reslen);
			m_freem(m);
			return;
		}
		len -= sizeof(*res);
		if (len < letoh16(res->bss_count) * sizeof(struct brcm_bss_info)) {
			DPRINTF(("%s: results too small\n", DEVNAME(sc)));
			free(res, M_TEMP, reslen);
			m_freem(m);
			return;
		}
		bss = &res->bss_info[0];
		for (i = 0; i < letoh16(res->bss_count); i++) {
			brcm_scan_node(sc, &res->bss_info[i], len);
			len -= sizeof(*bss) + letoh32(bss->length);
			bss = (void *)((char *)bss) + letoh32(bss->length);
			if (len <= 0)
				break;
		}
		free(res, M_TEMP, reslen);
		break;
		}
	case BRCM_E_AUTH:
		if (ntohl(e->msg.status) == BRCM_E_STATUS_SUCCESS &&
		    ic->ic_state == IEEE80211_S_AUTH)
			ieee80211_new_state(ic, IEEE80211_S_ASSOC, -1);
		else
			ieee80211_begin_scan(ifp);
		break;
	case BRCM_E_ASSOC:
		if (ntohl(e->msg.status) == BRCM_E_STATUS_SUCCESS &&
		    ic->ic_state == IEEE80211_S_ASSOC)
			ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
		else if (ntohl(e->msg.status) != BRCM_E_STATUS_UNSOLICITED)
			ieee80211_begin_scan(ifp);
		break;
	case BRCM_E_DEAUTH:
	case BRCM_E_DISASSOC:
		if (ic->ic_state > IEEE80211_S_SCAN)
			ieee80211_begin_scan(ifp);
		break;
	case BRCM_E_LINK:
		if (ntohl(e->msg.status) == BRCM_E_STATUS_SUCCESS &&
		    ntohl(e->msg.reason) == 0)
			break;
		/* Link status has changed */
		if (ic->ic_state > IEEE80211_S_SCAN)
			ieee80211_begin_scan(ifp);
		break;
#ifndef IEEE80211_STA_ONLY
	case BRCM_E_AUTH_IND:
		brcm_rx_auth_ind(sc, e, len);
		break;
	case BRCM_E_ASSOC_IND:
		brcm_rx_assoc_ind(sc, e, len, 0);
		break;
	case BRCM_E_REASSOC_IND:
		brcm_rx_assoc_ind(sc, e, len, 1);
		break;
	case BRCM_E_DEAUTH_IND:
		brcm_rx_deauth_ind(sc, e, len);
		break;
	case BRCM_E_DISASSOC_IND:
		brcm_rx_disassoc_ind(sc, e, len);
		break;
#endif
	default:
		DPRINTF(("%s: len %lu datalen %u code %u status %u"
		    " reason %u\n", __func__, len, ntohl(e->msg.datalen),
		    ntohl(e->msg.event_type), ntohl(e->msg.status),
		    ntohl(e->msg.reason)));
		break;
	}

	m_freem(m);
}

void
brcm_scan_node(struct brcm_softc *sc, struct brcm_bss_info *bss, size_t len)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct ieee80211_rxinfo rxi;
	struct mbuf *m;
	uint32_t pktlen, ieslen;
	uint16_t iesoff;
	int chanidx;

	iesoff = letoh16(bss->ie_offset);
	ieslen = letoh32(bss->ie_length);
	if (ieslen > len - iesoff)
		return;

	/* Build a fake beacon frame to let net80211 do all the parsing. */
	pktlen = sizeof(*wh) + ieslen + 12;
	if (pktlen > MCLBYTES)
		return;
	m = brcm_newbuf();
	if (m == NULL)
		return;
	wh = mtod(m, struct ieee80211_frame *);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    IEEE80211_FC0_SUBTYPE_BEACON;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	*(uint16_t *)wh->i_dur = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
	IEEE80211_ADDR_COPY(wh->i_addr2, bss->bssid);
	IEEE80211_ADDR_COPY(wh->i_addr3, bss->bssid);
	*(uint16_t *)wh->i_seq = 0;
	memset(&wh[1], 0, 12);
	((uint16_t *)(&wh[1]))[4] = bss->beacon_period;
	((uint16_t *)(&wh[1]))[5] = bss->capability;
	memcpy(((uint8_t *)&wh[1]) + 12, ((uint8_t *)bss) + iesoff, ieslen);

	/* Finalize mbuf. */
	m->m_pkthdr.len = m->m_len = pktlen;
	ni = ieee80211_find_rxnode(ic, wh);
	/* Channel mask equals IEEE80211_CHAN_MAX */
	chanidx = brcm_spec2chan(sc, letoh32(bss->chanspec));
	/* Supply RSSI */
	memset(&rxi, 0, sizeof(rxi));
	rxi.rxi_rssi = (int16_t)letoh16(bss->rssi);
	rxi.rxi_chan = chanidx;
	ieee80211_input(ifp, m, ni, &rxi);
	/* Node is no longer needed. */
	ieee80211_release_node(ic, ni);
}

void
brcm_task(void *arg)
{
	struct brcm_softc *sc = arg;
	struct brcm_host_cmd_ring *ring = &sc->sc_cmdq;
	struct brcm_host_cmd *cmd;
	struct mbuf *m;
	int s;

	s = splnet();
	while (ring->next != ring->cur) {
		cmd = &ring->cmd[ring->next];
		splx(s);
		cmd->cb(sc, cmd->data);
		s = splnet();
		ring->queued--;
		ring->next = (ring->next + 1) % BRCM_HOST_CMD_RING_COUNT;
	}
	splx(s);

	s = splnet();
	while ((m = ml_dequeue(&sc->sc_evml)) != NULL) {
		splx(s);
		brcm_rx_event_cb(sc, m);
		s = splnet();
	}
	splx(s);
}

void
brcm_do_async(struct brcm_softc *sc,
    void (*cb)(struct brcm_softc *, void *), void *arg, int len)
{
	struct brcm_host_cmd_ring *ring = &sc->sc_cmdq;
	struct brcm_host_cmd *cmd;
	int s;

	s = splnet();
	KASSERT(ring->queued < BRCM_HOST_CMD_RING_COUNT);
	if (ring->queued >= BRCM_HOST_CMD_RING_COUNT) {
		splx(s);
		return;
	}
	cmd = &ring->cmd[ring->cur];
	cmd->cb = cb;
	KASSERT(len <= sizeof(cmd->data));
	memcpy(cmd->data, arg, len);
	ring->cur = (ring->cur + 1) % BRCM_HOST_CMD_RING_COUNT;
	ring->queued++;
	task_add(sc->sc_taskq, &sc->sc_task);
	splx(s);
}

int
brcm_send_mgmt(struct ieee80211com *ic, struct ieee80211_node *ni,
    int type, int arg1, int arg2)
{
#ifdef BRCM_DEBUG
	struct brcm_softc *sc = ic->ic_softc;
	DPRINTF(("%s: %s\n", DEVNAME(sc), __func__));
#endif
	return 0;
}

int
brcm_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct brcm_cmd_key cmd;

	cmd.ni = ni;
	cmd.k = k;
	brcm_do_async(sc, brcm_set_key_cb, &cmd, sizeof(cmd));
	sc->sc_key_tasks++;
	return EBUSY;
}

void
brcm_set_key_cb(struct brcm_softc *sc, void *arg)
{
	struct brcm_cmd_key *cmd = arg;
	struct ieee80211_key *k = cmd->k;
	struct ieee80211_node *ni = cmd->ni;
	struct ieee80211com *ic = &sc->sc_ic;
	struct brcm_wsec_key key;
	uint32_t wsec, wsec_enable;
	int ext_key = 0;

	sc->sc_key_tasks--;

	if ((k->k_flags & IEEE80211_KEY_GROUP) == 0 &&
	    k->k_cipher != IEEE80211_CIPHER_WEP40 &&
	    k->k_cipher != IEEE80211_CIPHER_WEP104)
		ext_key = 1;

	memset(&key, 0, sizeof(key));
	if (ext_key && !IEEE80211_IS_MULTICAST(ni->ni_macaddr))
		memcpy(key.ea, ni->ni_macaddr, sizeof(key.ea));
	key.index = htole32(k->k_id);
	key.len = htole32(k->k_len);
	memcpy(key.data, k->k_key, sizeof(key.data));
	if (!ext_key)
		key.flags = htole32(BRCM_WSEC_PRIMARY_KEY);

	switch (k->k_cipher) {
	case IEEE80211_CIPHER_WEP40:
		key.algo = htole32(BRCM_CRYPTO_ALGO_WEP1);
		wsec_enable = BRCM_WSEC_WEP;
		break;
	case IEEE80211_CIPHER_WEP104:
		key.algo = htole32(BRCM_CRYPTO_ALGO_WEP128);
		wsec_enable = BRCM_WSEC_WEP;
		break;
	case IEEE80211_CIPHER_TKIP:
		key.algo = htole32(BRCM_CRYPTO_ALGO_TKIP);
		wsec_enable = BRCM_WSEC_TKIP;
		break;
	case IEEE80211_CIPHER_CCMP:
		key.algo = htole32(BRCM_CRYPTO_ALGO_AES_CCM);
		wsec_enable = BRCM_WSEC_AES;
		break;
	default:
		printf("%s: cipher %x not supported\n", DEVNAME(sc),
		    k->k_cipher);
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		return;
	}

	delay(100);

	brcm_fwvar_var_set_data(sc, "wsec_key", &key, sizeof(key));
	brcm_fwvar_var_get_int(sc, "wsec", &wsec);
	wsec |= wsec_enable;
	brcm_fwvar_var_set_int(sc, "wsec", wsec);

	if (sc->sc_key_tasks == 0) {
		DPRINTF(("%s: marking port %s valid\n", DEVNAME(sc),
		    ether_sprintf(cmd->ni->ni_macaddr)));
		cmd->ni->ni_port_valid = 1;
		ieee80211_set_link_state(ic, LINK_STATE_UP);
	}
}

void
brcm_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct brcm_cmd_key cmd;

	cmd.ni = ni;
	cmd.k = k;
	brcm_do_async(sc, brcm_delete_key_cb, &cmd, sizeof(cmd));
}

void
brcm_delete_key_cb(struct brcm_softc *sc, void *arg)
{
	struct brcm_cmd_key *cmd = arg;
	struct ieee80211_key *k = cmd->k;
	struct brcm_wsec_key key;

	memset(&key, 0, sizeof(key));
	key.index = htole32(k->k_id);
	key.flags = htole32(BRCM_WSEC_PRIMARY_KEY);
	brcm_fwvar_var_set_data(sc, "wsec_key", &key, sizeof(key));
}

int
brcm_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct brcm_softc *sc = ic->ic_softc;
	struct ifnet *ifp = &ic->ic_if;
	int s;

	s = splnet();

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ic->ic_state == IEEE80211_S_SCAN)
			brcm_scan_abort(sc);
		break;
	case IEEE80211_S_SCAN:
#ifndef IEEE80211_STA_ONLY
		/* Don't start a scan if we already have a channel. */
		if (ic->ic_state == IEEE80211_S_INIT &&
		    ic->ic_opmode == IEEE80211_M_HOSTAP &&
		    ic->ic_des_chan != IEEE80211_CHAN_ANYC) {
			break;
		}
#endif
		/* If we tried to connect, abort. */
		if (ic->ic_state > IEEE80211_S_SCAN)
			brcm_fwvar_cmd_set_data(sc, BRCM_C_DISASSOC, NULL, 0);
		/* Initiate scan. */
		brcm_scan(sc);
		if (ifp->if_flags & IFF_DEBUG)
			printf("%s: %s -> %s\n", DEVNAME(sc),
			    ieee80211_state_name[ic->ic_state],
			    ieee80211_state_name[nstate]);
		/* No need to do this again. */
		if (ic->ic_state == IEEE80211_S_SCAN) {
			splx(s);
			return 0;
		}
		ieee80211_set_link_state(ic, LINK_STATE_DOWN);
		ieee80211_free_allnodes(ic, 1);
		ic->ic_state = nstate;
		splx(s);
		return 0;
	case IEEE80211_S_AUTH:
		ic->ic_bss->ni_rsn_supp_state = RSNA_SUPP_INITIALIZE;
		brcm_connect(sc);
		if (ifp->if_flags & IFF_DEBUG)
			printf("%s: %s -> %s\n", DEVNAME(sc),
			    ieee80211_state_name[ic->ic_state],
			    ieee80211_state_name[nstate]);
		ic->ic_state = nstate;
		if (ic->ic_flags & IEEE80211_F_RSNON)
			ic->ic_bss->ni_rsn_supp_state = RSNA_SUPP_PTKSTART;
		splx(s);
		return 0;
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_S_RUN:
		if (ic->ic_opmode == IEEE80211_M_HOSTAP)
			brcm_hostap(sc);
		break;
#endif
	default:
		break;
	}
	sc->sc_newstate(ic, nstate, arg);
	splx(s);
	return 0;
}

int
brcm_nvram_convert(int node, u_char **bufp, size_t *sizep, size_t *newlenp)
{
	u_char *src, *dst, *end = *bufp + *sizep, *newbuf;
	size_t count = 0, newsize, pad;
	uint32_t token;
	int skip = 0;

	/*
	 * Allocate a new buffer with enough space for the MAC
	 * address, padding and final token.
	 */
	newsize = *sizep + 64;
	newbuf = malloc(newsize, M_DEVBUF, M_NOWAIT);
	if (newbuf == NULL)
		return 1;

	for (src = *bufp, dst = newbuf; src != end; ++src) {
		if (*src == '\n') {
			if (count > 0)
				*dst++ = '\0';
			count = 0;
			skip = 0;
			continue;
		}
		if (skip)
			continue;
		if (*src == '#' && count == 0) {
			skip = 1;
			continue;
		}
		if (*src == '\r')
			continue;
		*dst++ = *src;
		++count;
	}

#if defined(__HAVE_FDT)
	/*
	 * Append MAC address if one is provided in the device tree.
	 * This is needed on Apple Silicon Macs.
	 */
	if (node) {
		u_char enaddr[ETHER_ADDR_LEN];
		char macaddr[32];

		if (OF_getprop(node, "local-mac-address",
		    enaddr, sizeof(enaddr))) {
			snprintf(macaddr, sizeof(macaddr),
			    "macaddr=%02x:%02x:%02x:%02x:%02x:%02x",
			    enaddr[0], enaddr[1], enaddr[2], enaddr[3],
			    enaddr[4], enaddr[5]);
			if (*dst)
				*dst++ = '\0';
			memcpy(dst, macaddr, strlen(macaddr));
			dst += strlen(macaddr);
		}
	}
#endif

	count = dst - newbuf;
	pad = roundup(count + 1, 4) - count;

	memset(dst, 0, pad);
	count += pad;
	dst += pad;

	token = (count / 4) & 0xffff;
	token |= ~token << 16;
	token = htole32(token);

	memcpy(dst, &token, sizeof(token));
	count += sizeof(token);

	free(*bufp, M_DEVBUF, *sizep);
	*bufp = newbuf;
	*sizep = newsize;
	*newlenp = count;
	return 0;
}

void
brcm_process_blob(struct brcm_softc *sc, char *var, u_char **blob,
    size_t *blobsize)
{
	struct brcm_dload_data *data;
	size_t off, remain, len;

	if (*blob == NULL || *blobsize == 0)
		return;

	off = 0;
	remain = *blobsize;
	data = malloc(sizeof(*data) + BRCM_DLOAD_MAX_LEN, M_TEMP, M_WAITOK);

	while (remain) {
		len = min(remain, BRCM_DLOAD_MAX_LEN);

		data->flag = htole16(BRCM_DLOAD_FLAG_HANDLER_VER_1);
		if (off == 0)
			data->flag |= htole16(BRCM_DLOAD_FLAG_BEGIN);
		if (remain <= BRCM_DLOAD_MAX_LEN)
			data->flag |= htole16(BRCM_DLOAD_FLAG_END);
		data->type = htole16(BRCM_DLOAD_TYPE_CLM);
		data->len = htole32(len);
		data->crc = 0;
		memcpy(data->data, *blob + off, len);

		if (brcm_fwvar_var_set_data(sc, var, data,
		    sizeof(*data) + len)) {
			printf("%s: could not load blob (%s)\n", DEVNAME(sc),
			    var);
			goto out;
		}

		off += len;
		remain -= len;
	}

out:
	free(data, M_TEMP, sizeof(*data) + BRCM_DLOAD_MAX_LEN);
	free(*blob, M_DEVBUF, *blobsize);
	*blob = NULL;
	*blobsize = 0;
}

void
brcm_init_board_type(struct brcm_softc *sc)
{
#if defined(__HAVE_FDT)
	char compat[128];
	int len;
	char *p;

	len = OF_getprop(OF_peer(0), "compatible", compat, sizeof(compat));
	if (len > 0 && len < sizeof(compat)) {
		compat[len] = '\0';
		if ((p = strchr(compat, '/')) != NULL)
			*p = '\0';
		strlcpy(sc->sc_board_type, compat, sizeof(sc->sc_board_type));
	}
#endif
}

int
brcm_loadfirmware(struct brcm_softc *sc, const char *chip, const char *bus,
    u_char **ucode, size_t *size, u_char **nvram, size_t *nvsize, size_t *nvlen)
{
	const char *board_type = NULL;
	char name[128];
	int r;

	*ucode = *nvram = NULL;
	*size = *nvsize = *nvlen = 0;

	if (strlen(sc->sc_board_type) > 0)
		board_type = sc->sc_board_type;

	if (board_type != NULL) {
		r = snprintf(name, sizeof(name), "%sbrcmfmac%s%s.%s.bin",
		    sc->sc_fwdir, chip, bus, board_type);
		if ((r > 0 && r < sizeof(name)) &&
		    loadfirmware(name, ucode, size) != 0)
			*size = 0;
	}
	if (*size == 0) {
		snprintf(name, sizeof(name), "%sbrcmfmac%s%s.bin",
		    sc->sc_fwdir, chip, bus);
		if (loadfirmware(name, ucode, size) != 0) {
			snprintf(name, sizeof(name), "%sbrcmfmac%s%s%s%s.bin",
			    sc->sc_fwdir, chip, bus, board_type ? "." : "",
			    board_type ? board_type : "");
			printf("%s: failed loadfirmware of file %s\n",
			    DEVNAME(sc), name);
			return 1;
		}
	}

	/* .txt needs to be processed first */
	if (strlen(sc->sc_modrev) > 0) {
		r = snprintf(name, sizeof(name),
		    "%sbrcmfmac%s%s.%s-%s-%s-%s.txt", sc->sc_fwdir, chip, bus,
		    board_type, sc->sc_module, sc->sc_vendor, sc->sc_modrev);
		if (r > 0 && r < sizeof(name))
			loadfirmware(name, nvram, nvsize);
	}
	if (*nvsize == 0 && strlen(sc->sc_vendor) > 0) {
		r = snprintf(name, sizeof(name),
		    "%sbrcmfmac%s%s.%s-%s-%s.txt", sc->sc_fwdir, chip, bus,
		    board_type, sc->sc_module, sc->sc_vendor);
		if (r > 0 && r < sizeof(name))
			loadfirmware(name, nvram, nvsize);
	}

	if (*nvsize == 0 && board_type != NULL) {
		r = snprintf(name, sizeof(name), "%sbrcmfmac%s%s.%s.txt",
		    sc->sc_fwdir, chip, bus, board_type);
		if (r > 0 && r < sizeof(name))
			loadfirmware(name, nvram, nvsize);
	}

	if (*nvsize == 0) {
		snprintf(name, sizeof(name), "%sbrcmfmac%s%s.txt",
		    sc->sc_fwdir, chip, bus);
		loadfirmware(name, nvram, nvsize);
	}

	if (*nvsize != 0) {
		if (brcm_nvram_convert(sc->sc_node, nvram, nvsize, nvlen)) {
			printf("%s: failed to process file %s\n",
			    DEVNAME(sc), name);
			free(*ucode, M_DEVBUF, *size);
			free(*nvram, M_DEVBUF, *nvsize);
			return 1;
		}
	}

	/* .nvram is the pre-processed version */
	if (*nvlen == 0) {
		snprintf(name, sizeof(name), "%sbrcmfmac%s%s.nvram",
		    sc->sc_fwdir, chip, bus);
		if (loadfirmware(name, nvram, nvsize) == 0)
			*nvlen = *nvsize;
	}

	if (*nvlen == 0 && strcmp(bus, "-sdio") == 0) {
		snprintf(name, sizeof(name), "%sbrcmfmac%s%s%s%s.txt",
		    sc->sc_fwdir, chip, bus, board_type ? "." : "",
		    board_type ? board_type : "");
		printf("%s: failed loadfirmware of file %s\n",
		    DEVNAME(sc), name);
		free(*ucode, M_DEVBUF, *size);
		return 1;
	}

	if (board_type != NULL) {
		r = snprintf(name, sizeof(name), "%sbrcmfmac%s%s.%s.clm_blob",
		    sc->sc_fwdir, chip, bus, board_type);
		if (r > 0 && r < sizeof(name))
			loadfirmware(name, &sc->sc_clm, &sc->sc_clmsize);
	}
	if (sc->sc_clmsize == 0) {
		snprintf(name, sizeof(name), "%sbrcmfmac%s%s.clm_blob",
		    sc->sc_fwdir, chip, bus);
		loadfirmware(name, &sc->sc_clm, &sc->sc_clmsize);
	}

	if (board_type != NULL) {
		r = snprintf(name, sizeof(name),
		    "%sbrcmfmac%s%s.%s.txcap_blob", sc->sc_fwdir,
		    chip, bus, board_type);
		if (r > 0 && r < sizeof(name))
			loadfirmware(name, &sc->sc_txcap, &sc->sc_txcapsize);
	}
	if (sc->sc_txcapsize == 0) {
		snprintf(name, sizeof(name), "%sbrcmfmac%s%s.txcap_blob",
		    sc->sc_fwdir, chip, bus);
		loadfirmware(name, &sc->sc_txcap, &sc->sc_txcapsize);
	}

	return 0;
}

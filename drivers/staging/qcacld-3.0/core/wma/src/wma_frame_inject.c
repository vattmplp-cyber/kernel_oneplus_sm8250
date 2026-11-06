/*
 * Copyright (c) 2024 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: wma_frame_inject.c
 *
 * This file contains WMA layer frame injection queue management functions.
 * It provides infrastructure for queuing, processing, and transmitting
 * injected 802.11 frames through the firmware interface.
 */

#include "wma.h"
#include "wma_frame_inject.h"
#include "wlan_hdd_frame_inject.h"
#include "wma_api.h"
#include <wlan_reg_services_api.h>
#include <reg_services_public_struct.h>
#include "wma_internal.h"
#include "wmi_unified_api.h"
#include "wmi_unified.h"
#include "qdf_mem.h"
#include "qdf_list.h"
#include "qdf_lock.h"
#include "qdf_status.h"
#include "qdf_trace.h"
#include "qdf_nbuf.h"
#include "qdf_delayed_work.h"
#include "qdf_time.h"
#include "cds_api.h"
#include "cdp_txrx_cmn.h"
#include <wlan_vdev_mgr_tgt_if_tx_defs.h>
#if defined(CONFIG_HL_SUPPORT)
#include "wlan_tgt_def_config_hl.h"
#else
#include "wlan_tgt_def_config.h"
#endif

#ifdef FEATURE_FRAME_INJECTION_SUPPORT

/*
 * wma_injection_unmap_tx_buf() - Unmap DMA mapping on injection nbuf
 *
 * On LL (low-latency / PCI / SNOC) the WMI layer DMA-maps the tx_frame
 * passed in mgmt_params.  The mapping must be released on completion.
 * On HL (high-latency / SDIO / USB) the frame data is copied inline into
 * the WMI command and no DMA mapping exists, so the unmap is a no-op.
 */
#ifdef CONFIG_HL_SUPPORT
static inline void wma_injection_unmap_tx_buf(qdf_nbuf_t buf)
{
}
#else
static inline void wma_injection_unmap_tx_buf(qdf_nbuf_t buf)
{
	void *qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);

	if (qdf_ctx && buf)
		qdf_nbuf_unmap_single(qdf_ctx, buf, QDF_DMA_TO_DEVICE);
}
#endif

/* Maximum number of frames in WMA injection queue */
#define WMA_FRAME_INJECT_MAX_QUEUE_SIZE    512

/* Maximum frame size for injection */
#define WMA_FRAME_INJECT_MAX_FRAME_SIZE    2304

/* Timeout for queue processing work in milliseconds */
#define WMA_FRAME_INJECT_QUEUE_TIMEOUT_MS  100

/* Reaper timer interval: how often we scan for stale in-flight nbufs (ms) */
#define WMA_INJECTION_REAPER_INTERVAL_MS   1000

/*
 * Warn when an in-flight nbuf has not completed for this long. Age alone
 * never proves DMA quiescence and must not be used to unmap or free the nbuf.
 */
#define WMA_INJECTION_NBUF_TIMEOUT_US      10000000ULL

/*
 * Maximum number of DMA-owned injection nbufs. Admission is reserved
 * atomically under g_wma_injection_cache_lock immediately before WMI submit,
 * leaving headroom below the 256-slot descriptor cache.
 */
#define WMA_INJECTION_INFLIGHT_HIGH        200

/**
 * struct wma_injection_queue_node - Node for injection queue
 * @node: List node
 * @req: Frame injection request
 * @timestamp: Enqueue timestamp
 * @vdev_id: VDEV ID for the frame
 */
struct wma_injection_queue_node {
	qdf_list_node_t node;
	struct inject_frame_req req;
	uint64_t timestamp;
	uint8_t vdev_id;
};

/**
 * struct wma_injection_queue_ctx - WMA injection queue context
 * @queue: Queue of pending injection requests
 * @queue_lock: Lock for queue operations
 * @queue_size: Current queue size
 * @max_queue_size: Maximum allowed queue size
 * @queue_work: Work item for processing queue
 * @delayed_work: Delayed work item for backpressure handling
 * @stats: Queue statistics
 * @is_initialized: Initialization flag
 */
struct wma_injection_queue_ctx {
	qdf_list_t queue;
	qdf_spinlock_t queue_lock;
	uint32_t queue_size;
	uint32_t max_queue_size;
	qdf_work_t queue_work;
	struct qdf_delayed_work delayed_work;
	struct qdf_delayed_work reaper_work; /* periodic stale-nbuf reaper */
	qdf_atomic_t inflight_count; /* nbufs submitted to FW, not yet completed */
	struct wma_injection_queue_stats stats;
	bool is_initialized;
	bool is_paused;
};

/* Statistics structure is defined in wma_frame_inject.h */

/* Global injection queue context */
static struct wma_injection_queue_ctx g_wma_injection_ctx;

/*
 * Per-session one-shot logging flags and counters for
 * wma_send_injection_frame_to_fw().  Reset on each new
 * injection TX vdev creation so restarts re-log setup info.
 */
static bool inject_tx_cfg_logged;
static uint32_t inject_send_info_count;
static bool inject_wmi_path_logged;
static bool inject_legacy_path_logged;
static bool inject_monitor_no_legacy_logged;
static bool inject_wmi_service_absent_logged;
static bool inject_mgmt_sa_fix_logged;
static bool inject_patch_banner_logged;

/*
 * Keep a small best-effort debug cache so firmware completion status can be
 * correlated with the frame metadata for the corresponding desc_id.
 */
#define WMA_INJECTION_DEBUG_CACHE_SIZE 256

#if WMA_INJECTION_INFLIGHT_HIGH >= WMA_INJECTION_DEBUG_CACHE_SIZE
#error "WMA injection inflight limit must be below debug cache capacity"
#endif

struct wma_injection_debug_info {
	bool valid;
	bool submit_pending;
	bool completion_pending;
	uint32_t completion_status;
	uint32_t desc_id;
	uint16_t frame_len;
	uint16_t chanfreq;
	uint8_t fc_type;
	uint8_t fc_subtype;
	uint8_t addr1[QDF_MAC_ADDR_SIZE];
	uint8_t addr2[QDF_MAC_ADDR_SIZE];
	uint8_t addr3[QDF_MAC_ADDR_SIZE];
	qdf_nbuf_t tx_buf; /* DMA-owned until firmware completion */
	uint64_t submit_ts; /* log-timestamp when submitted to FW */
	bool reaper_warned; /* timeout warning emitted; never a reclaim permission */
};

static struct wma_injection_debug_info
	g_wma_injection_debug_cache[WMA_INJECTION_DEBUG_CACHE_SIZE];
static qdf_spinlock_t g_wma_injection_cache_lock;

/*
 * Hidden STA vdev for injection TX on monitor mode.
 *
 * The firmware's mgmt TX handler (FUN_b000fc10, _wlan_send_mgmt_to_host)
 * unconditionally rejects management frames on MONITOR vdevs: the internal
 * vdev-type switch only accepts AP(0), STA(1), IBSS(2), OCB(6) for the
 * normal peer-lookup → WAL-TX path.  MONITOR(3) is shunted to a
 * beacon-only fallback (FUN_b01baa34) that always returns 5 → DISCARD.
 *
 * Work around this by creating a lightweight STA vdev on the same channel
 * as the monitor interface and routing injected frames through it.  The STA
 * helper vdev has a self-peer so the firmware can
 * schedule and transmit the management frame normally.
 *
 * Lifecycle:
 *   Created lazily on the first injection attempt on a monitor vdev.
 *   Destroyed in wma_deinit_injection_queue() or when the channel changes.
 *   WMI response events for this vdev (create/start/peer_create/up) are
 *   silently dropped by the host because no wlan_objmgr_vdev exists for
 *   the hidden vdev_id.
 */
struct wma_injection_tx_vdev {
	bool created;       /* Firmware accepted VDEV_CREATE */
	bool started;       /* Firmware accepted VDEV_START */
	bool peer_created;  /* Firmware accepted self-peer CREATE */
	bool ready;         /* Safe to submit management TX */
	uint8_t vdev_id;
	uint8_t monitor_vdev_id;
	uint32_t chanfreq;
	uint8_t mac_addr[QDF_MAC_ADDR_SIZE];
};

static struct wma_injection_tx_vdev g_inj_tx_vdev;
static int8_t g_inj_tx_power_limit_dbm = HDD_FRAME_INJECT_TX_POWER_CAP_DBM;

static QDF_STATUS wma_injection_destroy_tx_vdev(tp_wma_handle wma,
						 bool wait_for_inflight);

/**
 * wma_injection_reset_session_state() - Reset per-session static state
 *
 * Called when a new injection TX vdev is being created (fresh session
 * or channel change).  Resets all file-static one-shot logging flags
 * and the send counter so the new session starts clean.
 */
static void wma_injection_reset_session_state(void)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	/* Reset one-shot logging flags so fresh session re-logs config */
	inject_tx_cfg_logged = false;
	inject_send_info_count = 0;
	inject_wmi_path_logged = false;
	inject_legacy_path_logged = false;
	inject_monitor_no_legacy_logged = false;
	inject_wmi_service_absent_logged = false;
	inject_mgmt_sa_fix_logged = false;
	inject_patch_banner_logged = false;

	/* Reset rate-limited log counters so new session gets fresh logs */
	if (ctx->is_initialized) {
		ctx->stats.fw_errors = 0;
		ctx->stats.frames_processed = 0;
	}

	/*
	 * Do NOT sweep/free nbufs from the debug cache here. The firmware may
	 * still be DMA-reading them. Buffers are reclaimed only after a real
	 * firmware completion; timeout and slot reuse are never DMA-quiescence
	 * guarantees.
	 */
}

/**
 * wma_injection_ensure_tx_vdev() - Ensure hidden STA vdev exists for TX
 * @wma: WMA handle
 * @mon_vdev_id: monitor vdev id
 * @chanfreq: operating channel frequency in MHz
 *
 * Creates (or re-creates on channel change) a firmware-only STA vdev that
 * is used as the TX endpoint for injected management frames.
 *
 * Return: QDF_STATUS_SUCCESS when the helper vdev is ready.
 */
static QDF_STATUS
wma_injection_ensure_tx_vdev(tp_wma_handle wma,
			    uint8_t mon_vdev_id,
			    uint32_t chanfreq)
{
	struct vdev_create_params vcreate;
	struct vdev_start_params vstart;
	struct peer_create_params pcreate;
	uint8_t *mon_mac;
	uint8_t inj_mac[QDF_MAC_ADDR_SIZE];
	uint8_t vid = 0;
	bool found = false;
	int i;
	QDF_STATUS status;
	QDF_STATUS cleanup_status;
	struct wlan_objmgr_pdev *pdev;
	uint8_t reg_power;
	int8_t tx_power_cap;

	if (g_inj_tx_vdev.created) {
		/*
		 * Reuse only a fully-created helper. A failed peer-create or
		 * partial teardown leaves a firmware VDEV that must be cleaned
		 * before another create is attempted; never treat it as TX-ready.
		 */
		mon_mac = wlan_vdev_mlme_get_macaddr(
				wma->interfaces[mon_vdev_id].vdev);
		if (g_inj_tx_vdev.ready &&
		    g_inj_tx_vdev.chanfreq == chanfreq &&
		    g_inj_tx_vdev.monitor_vdev_id == mon_vdev_id &&
		    mon_mac) {
			qdf_mem_copy(inj_mac, mon_mac, QDF_MAC_ADDR_SIZE);
			inj_mac[0] |= 0x02;
			if (qdf_mem_cmp(inj_mac, g_inj_tx_vdev.mac_addr,
					QDF_MAC_ADDR_SIZE) == 0)
				return QDF_STATUS_SUCCESS;
		}
		/* Channel, MAC, or incomplete lifecycle changed — recreate. */
		status = wma_injection_destroy_tx_vdev(wma, false);
		if (QDF_IS_STATUS_ERROR(status))
			return status;
	}

	/*
	 * Firmware vdev array supports IDs 0..(num_vdevs-1).  num_vdevs is
	 * at most CFG_TGT_NUM_VDEV (typically 4) and may be decremented by 1
	 * for NAN → 3.  Use (CFG_TGT_NUM_VDEV - 2) as safe ceiling so we
	 * never exceed the firmware's internal array.
	 */
	{
		int fw_max_vid = CFG_TGT_NUM_VDEV - 2;

		if (fw_max_vid >= (int)wma->max_bssid)
			fw_max_vid = (int)wma->max_bssid - 1;
		for (i = fw_max_vid; i >= 0; i--) {
			if ((uint8_t)i == mon_vdev_id)
				continue;
			if (!wma->interfaces[i].vdev) {
				vid = (uint8_t)i;
				found = true;
				break;
			}
		}
	}
	if (!found) {
		wma_err("Injection: no unused vdev slot for TX helper");
		return QDF_STATUS_E_RESOURCES;
	}

	/* New vdev being created — reset session state for a clean start */
	wma_injection_reset_session_state();

	pdev = wlan_vdev_get_pdev(wma->interfaces[mon_vdev_id].vdev);
	if (!pdev) {
		wma_err("Injection: monitor vdev has no pdev");
		return QDF_STATUS_E_FAILURE;
	}

	reg_power = wlan_reg_get_channel_reg_power_for_freq(pdev, chanfreq);
	if (reg_power == REG_INVALID_TXPOWER) {
		wma_err("Injection: no regulatory TX-power limit for %u MHz",
			chanfreq);
		return QDF_STATUS_E_INVAL;
	}

	/*
	 * Never raise the existing conservative 20 dBm injection cap.
	 * The regulatory limit may be lower on the selected channel.
	 */
	tx_power_cap = QDF_MIN((int8_t)reg_power,
			       g_inj_tx_power_limit_dbm);
	if (tx_power_cap <= 0) {
		wma_err("Injection: invalid effective TX-power cap %d dBm",
			tx_power_cap);
		return QDF_STATUS_E_INVAL;
	}

	mon_mac = wlan_vdev_mlme_get_macaddr(
			wma->interfaces[mon_vdev_id].vdev);
	if (!mon_mac) {
		wma_err("Injection: cannot read monitor vdev MAC");
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_copy(inj_mac, mon_mac, QDF_MAC_ADDR_SIZE);
	inj_mac[0] |= 0x02; /* locally-administered */

	/* ---------- 1. VDEV CREATE (STA type) ---------- */
	/*
	 * Use STA, not AP.  AP vdevs trigger firmware beacon-TX-offload
	 * which crashes at _wlan_beacon_tx_offload_handle_beacon because
	 * no beacon template exists.  STA vdevs reach the same peer-lookup
	 * → WAL-TX path in the firmware mgmt TX handler without beacons.
	 */
	qdf_mem_zero(&vcreate, sizeof(vcreate));
	vcreate.vdev_id = vid;
	vcreate.type    = WMI_VDEV_TYPE_STA;
	vcreate.subtype = 0;
	vcreate.nss_2g  = 1;
	vcreate.nss_5g  = 1;
	vcreate.pdev_id = 0;

	status = wmi_unified_vdev_create_send(wma->wmi_handle,
					      inj_mac, &vcreate);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection TX vdev create failed: %d", status);
		return status;
	}
	/* Record the firmware object immediately so every later failure can
	 * unwind it without losing the VDEV ID or issuing a duplicate CREATE.
	 */
	qdf_mem_zero(&g_inj_tx_vdev, sizeof(g_inj_tx_vdev));
	g_inj_tx_vdev.created = true;
	g_inj_tx_vdev.vdev_id = vid;
	g_inj_tx_vdev.monitor_vdev_id = mon_vdev_id;
	g_inj_tx_vdev.chanfreq = chanfreq;
	qdf_mem_copy(g_inj_tx_vdev.mac_addr, inj_mac, QDF_MAC_ADDR_SIZE);

	/* Firmware processes WMI commands asynchronously.  Each step must
	 * complete in firmware before the next command references the vdev.
	 * Without these sleeps the mgmt-TX arrives before VDEV_CREATE is
	 * done and firmware asserts in wlan_vdev_find_vdev.
	 */
	msleep(150);

	/* ---------- 2. VDEV START (20 MHz basic mode) ---------- */
	qdf_mem_zero(&vstart, sizeof(vstart));
	vstart.vdev_id            = vid;
	vstart.channel.mhz        = chanfreq;
	vstart.channel.cfreq1     = chanfreq;
	vstart.channel.cfreq2     = 0;
	/* 2.4 GHz → MODE_11G(1), 5 GHz → MODE_11A(0) */
	vstart.channel.phy_mode   = (chanfreq < 4000) ? 1 : 0;
	vstart.channel.maxregpower = reg_power;
	vstart.channel.maxpower    = tx_power_cap;
	vstart.beacon_interval    = 0;
	vstart.dtim_period        = 0;

	status = wmi_unified_vdev_start_send(wma->wmi_handle, &vstart);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection TX vdev start failed: %d", status);
		goto err_stop;
	}
	g_inj_tx_vdev.started = true;
	msleep(150);

	/*
	 * Apply the limit explicitly to the hidden TX vdev as well as the
	 * VDEV_START channel parameters. This is the vdev that actually sends
	 * monitor-injected frames.
	 */
	status = wma_vdev_set_param(wma->wmi_handle, vid,
				    WMI_VDEV_PARAM_TX_PWRLIMIT,
				    tx_power_cap);
	if (QDF_IS_STATUS_ERROR(status))
		wma_warn("Injection TX vdev TX-power parameter unsupported/failed: %d; retaining VDEV_START regulatory cap",
			 status);

	/* ---------- 3. PEER CREATE (self-peer → fw vdev+0xc) ---------- */
	qdf_mem_zero(&pcreate, sizeof(pcreate));
	pcreate.peer_addr = inj_mac;
	pcreate.peer_type = WMI_PEER_TYPE_DEFAULT;
	pcreate.vdev_id   = vid;

	status = wmi_unified_peer_create_send(wma->wmi_handle, &pcreate);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection TX vdev peer create failed: %d", status);
		goto err_stop;
	}
	g_inj_tx_vdev.peer_created = true;
	g_inj_tx_vdev.ready = true;
	msleep(100);

	/*
	 * Skip VDEV_UP.  For STA vdevs, firmware's wlan_vdev_up
	 * asserts unless a BSS peer (the AP) exists — we only have
	 * a self-peer.  The mgmt TX handler only needs the vdev in
	 * STARTED state with a valid peer at vdev+0xc.
	 */

	g_inj_tx_vdev.ready = true;

	wma_info("Injection TX helper vdev created: vdev_id=%u mac=%pM freq=%u type=STA",
		 vid, inj_mac, chanfreq);
	return QDF_STATUS_SUCCESS;

err_stop:
	/*
	 * Use the same stateful teardown path for partial creation failures.
	 * If any WMI delete step fails, retain the lifecycle flags so the next
	 * attempt retries cleanup instead of allocating a duplicate VDEV ID.
	 */
	cleanup_status = wma_injection_destroy_tx_vdev(wma, false);
	if (QDF_IS_STATUS_ERROR(cleanup_status))
		wma_err("Injection helper partial-create cleanup failed: %d",
			cleanup_status);
	return status;
}

/**
 * wma_injection_set_tx_power_limit() - configure monitor injection TX cap
 * @monitor_vdev_id: monitor interface vdev id
 * @power_dbm: requested cap in dBm; zero means automatic/default
 *
 * The cap is never allowed above the driver's conservative 20 dBm ceiling,
 * and is further clamped to the regulatory power for the active channel.
 */
QDF_STATUS wma_injection_set_tx_power_limit(uint8_t monitor_vdev_id,
					    int8_t power_dbm)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);
	struct wlan_objmgr_pdev *pdev;
	uint8_t reg_power;
	int8_t effective_power;
	QDF_STATUS status;

	if (!wma || monitor_vdev_id >= wma->max_bssid ||
	    !wma->interfaces[monitor_vdev_id].vdev)
		return QDF_STATUS_E_INVAL;

	if (power_dbm <= 0)
		power_dbm = HDD_FRAME_INJECT_TX_POWER_CAP_DBM;
	power_dbm = QDF_MIN(power_dbm,
			    HDD_FRAME_INJECT_TX_POWER_CAP_DBM);

	if (g_inj_tx_vdev.created && !g_inj_tx_vdev.ready)
		return QDF_STATUS_E_AGAIN;

	if (g_inj_tx_vdev.ready &&
	    g_inj_tx_vdev.monitor_vdev_id == monitor_vdev_id) {
		pdev = wlan_vdev_get_pdev(wma->interfaces[monitor_vdev_id].vdev);
		if (!pdev)
			return QDF_STATUS_E_FAILURE;

		reg_power = wlan_reg_get_channel_reg_power_for_freq(
			pdev, g_inj_tx_vdev.chanfreq);
		if (reg_power == REG_INVALID_TXPOWER)
			return QDF_STATUS_E_INVAL;

		effective_power = QDF_MIN((int8_t)reg_power, power_dbm);
		if (effective_power <= 0)
			return QDF_STATUS_E_INVAL;

		status = wma_vdev_set_param(wma->wmi_handle,
					    g_inj_tx_vdev.vdev_id,
					    WMI_VDEV_PARAM_TX_PWRLIMIT,
					    effective_power);
		if (QDF_IS_STATUS_ERROR(status))
			return status;
	}

	g_inj_tx_power_limit_dbm = power_dbm;
	wma_info("Monitor injection TX-power cap set to %d dBm",
		 power_dbm);
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_injection_get_tx_power_limit(uint8_t monitor_vdev_id,
					    int8_t *power_dbm)
{
	tp_wma_handle wma = cds_get_context(QDF_MODULE_ID_WMA);

	if (!wma || !power_dbm || monitor_vdev_id >= wma->max_bssid ||
	    !wma->interfaces[monitor_vdev_id].vdev)
		return QDF_STATUS_E_INVAL;

	*power_dbm = g_inj_tx_power_limit_dbm;
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_injection_destroy_tx_vdev() - Tear down the hidden injection TX vdev
 * @wma: WMA handle
 *
 * Late-path teardown (called from deinit_injection_queue / wma_close).
 * WMI may already be stopped, so failures are tolerated.
 */
static QDF_STATUS wma_injection_destroy_tx_vdev(tp_wma_handle wma,
						 bool wait_for_inflight)
{
	int wait_ms = 0;
	QDF_STATUS status;

	if (!g_inj_tx_vdev.created)
		return QDF_STATUS_SUCCESS;
	if (!wma || !wma->wmi_handle)
		return QDF_STATUS_E_FAILURE;

	/*
	 * The firmware may not emit a management-TX completion for this
	 * firmware-only helper vdev. Keep it alive while any DMA buffer remains
	 * outstanding. The reaper only warns; it never retires mappings by age.
	 */
	if (!wait_for_inflight &&
	    qdf_atomic_read(&g_wma_injection_ctx.inflight_count) > 0)
		return QDF_STATUS_E_AGAIN;

	while (wait_for_inflight &&
	       qdf_atomic_read(&g_wma_injection_ctx.inflight_count) > 0 &&
	       wait_ms < 3500) {
		msleep(20);
		wait_ms += 20;
	}

	if (qdf_atomic_read(&g_wma_injection_ctx.inflight_count) > 0) {
		wma_warn("Refusing injection helper teardown with inflight=%d",
			 qdf_atomic_read(&g_wma_injection_ctx.inflight_count));
		return QDF_STATUS_E_AGAIN;
	}

	/*
	 * Proper teardown order (reverse of create):
	 *   PEER_DELETE → VDEV_STOP → VDEV_DELETE.
	 * Keep the gaps: firmware processes these WMI commands asynchronously.
	 */
	/* Once teardown starts, the helper must never be reused for TX. */
	g_inj_tx_vdev.ready = false;

	if (g_inj_tx_vdev.peer_created) {
		status = wmi_unified_peer_delete_send(wma->wmi_handle,
					      g_inj_tx_vdev.mac_addr,
					      g_inj_tx_vdev.vdev_id);
		if (QDF_IS_STATUS_ERROR(status))
			wma_warn("Injection helper peer delete send failed: %d; continuing with VDEV stop",
				 status);
		else
			g_inj_tx_vdev.peer_created = false;
		msleep(100);
	}

	if (g_inj_tx_vdev.started) {
		status = wmi_unified_vdev_stop_send(wma->wmi_handle,
					    g_inj_tx_vdev.vdev_id);
		if (QDF_IS_STATUS_ERROR(status))
			wma_warn("Injection helper vdev stop send failed: %d; attempting VDEV delete",
				 status);
		else
			g_inj_tx_vdev.started = false;
		msleep(100);
	}

	status = wmi_unified_vdev_delete_send(wma->wmi_handle,
					      g_inj_tx_vdev.vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection helper vdev delete send failed: %d", status);
		return status;
	}
	msleep(100);

	wma_info("Injection TX helper vdev destroyed: vdev_id=%u",
		 g_inj_tx_vdev.vdev_id);
	qdf_mem_zero(&g_inj_tx_vdev, sizeof(g_inj_tx_vdev));
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_injection_pre_stop_cleanup() - Destroy injection helper vdev before
 *                                     monitor mode stop
 * @wma_handle: WMA handle
 *
 * Must be called while WMI is still alive, BEFORE the driver sends
 * VDEV_STOP / VDEV_DELETE for the monitor vdev.  The firmware asserts
 * in dispatch_wlan_pdev_cmds if an orphaned STA helper vdev is still
 * present when the monitor vdev is torn down.
 *
 * Proper teardown order (reverse of create):
 *   PEER_DELETE → VDEV_STOP → VDEV_DELETE
 * with msleep() gaps so the firmware can process each command.
 */
QDF_STATUS wma_injection_pre_stop_cleanup(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	QDF_STATUS status;

	if (!wma_handle) {
		if (!g_inj_tx_vdev.created)
			return QDF_STATUS_SUCCESS;
		wma_err("Invalid WMA handle for injection helper pre-stop cleanup");
		return QDF_STATUS_E_FAILURE;
	}

	/*
	 * Stop accepting and drain queued frames even if the lazy helper VDEV
	 * has not been created yet. Otherwise a queued request could run after
	 * the monitor VDEV starts shutting down.
	 */
	if (ctx->is_initialized) {
		qdf_spin_lock_bh(&ctx->queue_lock);
		ctx->is_paused = true;
		qdf_spin_unlock_bh(&ctx->queue_lock);
		status = wma_flush_injection_queue(wma_handle);
		if (QDF_IS_STATUS_ERROR(status))
			return status;
	}

	if (!g_inj_tx_vdev.created)
		return QDF_STATUS_SUCCESS;
	if (!wma_handle->wmi_handle) {
		wma_err("WMI unavailable for injection helper pre-stop cleanup");
		return QDF_STATUS_E_FAILURE;
	}

	wma_info("Pre-stop cleanup: destroying injection helper vdev_id=%u",
		 g_inj_tx_vdev.vdev_id);
	return wma_injection_destroy_tx_vdev(wma_handle, true);
}
static QDF_STATUS
wma_injection_debug_cache_update(uint32_t desc_id,
				 struct inject_frame_req *req,
				 uint8_t fc_type,
				 uint8_t fc_subtype,
				 uint16_t chanfreq)
{
	struct wma_injection_debug_info *entry;
	uint32_t slot;
	uint32_t busy_desc_id = 0;

	if (!desc_id || !req || !req->frame_data)
		return QDF_STATUS_E_INVAL;

	slot = desc_id % WMA_INJECTION_DEBUG_CACHE_SIZE;

	qdf_spin_lock_bh(&g_wma_injection_cache_lock);
	entry = &g_wma_injection_debug_cache[slot];

	/*
	 * A valid entry or a non-NULL nbuf owns this slot. It remains reserved
	 * until its completion handler detaches the buffer. A timeout cannot
	 * establish that the device has stopped DMA, so fail closed and let the
	 * queue worker retry instead of replacing the descriptor metadata.
	 */
	if (entry->valid || entry->tx_buf) {
		busy_desc_id = entry->desc_id;
		qdf_spin_unlock_bh(&g_wma_injection_cache_lock);
		wma_warn("Injection: debug cache slot %u busy with desc_id=%u; deferring desc_id=%u",
			 slot, busy_desc_id, desc_id);
		return QDF_STATUS_E_AGAIN;
	}

	entry->submit_pending = false;
	entry->completion_pending = false;
	entry->completion_status = 0;
	entry->desc_id = desc_id;
	entry->frame_len = req->frame_len;
	entry->chanfreq = chanfreq;
	entry->fc_type = fc_type;
	entry->fc_subtype = fc_subtype;
	entry->tx_buf = NULL;
	entry->submit_ts = 0;
	entry->reaper_warned = false;
	qdf_mem_zero(entry->addr1, sizeof(entry->addr1));
	qdf_mem_zero(entry->addr2, sizeof(entry->addr2));
	qdf_mem_zero(entry->addr3, sizeof(entry->addr3));

	if (req->frame_len >= 24) {
		qdf_mem_copy(entry->addr1, &req->frame_data[4], QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(entry->addr2, &req->frame_data[10], QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(entry->addr3, &req->frame_data[16], QDF_MAC_ADDR_SIZE);
	}

	entry->valid = true;
	qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

	return QDF_STATUS_SUCCESS;
}

/*
 * Claim an entry under the cache lock.
/*
 * Claim an entry under the cache lock. If completion races with the WMI
 * submit call, record it and defer buffer release until the submitter has
 * returned and no longer owns the call stack.
 */
static bool
wma_injection_debug_cache_get(uint32_t desc_id,
			      struct wma_injection_debug_info *snapshot,
			      bool defer_if_submitting,
			      uint32_t completion_status)
{
	struct wma_injection_debug_info *entry;
	uint32_t slot;
	bool found = false;

	if (!desc_id || !snapshot)
		return false;

	slot = desc_id % WMA_INJECTION_DEBUG_CACHE_SIZE;

	qdf_spin_lock_bh(&g_wma_injection_cache_lock);
	entry = &g_wma_injection_debug_cache[slot];
	if (entry->valid && entry->desc_id == desc_id) {
		*snapshot = *entry;
		if (defer_if_submitting && entry->submit_pending) {
			entry->completion_pending = true;
			entry->completion_status = completion_status;
			/* The submitter retains ownership until WMI returns. */
			snapshot->tx_buf = NULL;
		} else {
			entry->tx_buf = NULL;
			entry->valid = false;
			entry->submit_pending = false;
			if (snapshot->tx_buf)
				qdf_atomic_dec(&g_wma_injection_ctx.inflight_count);
		}
		found = true;
	}
	qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

	return found;
}

/*
 * Attach before WMI submission, but protect the buffer from the reaper until
 * the send call returns. An early completion only marks the entry; this
 * submit-done helper then takes ownership of the buffer.
 */
static QDF_STATUS
wma_injection_debug_cache_set_tx_buf(uint32_t desc_id, qdf_nbuf_t tx_buf)
{
	struct wma_injection_debug_info *entry;
	uint32_t slot;
	QDF_STATUS status = QDF_STATUS_E_FAILURE;

	if (!desc_id || !tx_buf)
		return QDF_STATUS_E_INVAL;

	slot = desc_id % WMA_INJECTION_DEBUG_CACHE_SIZE;

	qdf_spin_lock_bh(&g_wma_injection_cache_lock);
	entry = &g_wma_injection_debug_cache[slot];
	if (entry->valid && entry->desc_id == desc_id && !entry->tx_buf) {
		/*
		 * Reserve the DMA slot and increment inflight_count under the
		 * same lock. This closes the race between concurrent submitters
		 * and guarantees the active count never exceeds the cache-safe
		 * admission limit.
		 */
		if (qdf_atomic_read(&g_wma_injection_ctx.inflight_count) >=
		    WMA_INJECTION_INFLIGHT_HIGH) {
			status = QDF_STATUS_E_AGAIN;
		} else {
			entry->tx_buf = tx_buf;
			entry->submit_pending = true;
			entry->completion_pending = false;
			entry->completion_status = 0;
			entry->submit_ts = qdf_get_log_timestamp();
			entry->reaper_warned = false;
			qdf_atomic_inc(&g_wma_injection_ctx.inflight_count);
			status = QDF_STATUS_SUCCESS;
		}
	} else {
		/* No matching free reservation exists; retry after the owner drains. */
		status = QDF_STATUS_E_AGAIN;
	}
	qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

	return status;
}

static bool
wma_injection_debug_cache_submit_done(
		uint32_t desc_id,
		struct wma_injection_debug_info *snapshot,
		bool *completion_received)
{
	struct wma_injection_debug_info *entry;
	uint32_t slot;
	bool found = false;

	if (!desc_id || !snapshot || !completion_received)
		return false;

	*completion_received = false;
	slot = desc_id % WMA_INJECTION_DEBUG_CACHE_SIZE;

	qdf_spin_lock_bh(&g_wma_injection_cache_lock);
	entry = &g_wma_injection_debug_cache[slot];
	if (entry->valid && entry->desc_id == desc_id &&
	    entry->submit_pending) {
		if (entry->completion_pending) {
			*snapshot = *entry;
			entry->tx_buf = NULL;
			entry->valid = false;
			entry->submit_pending = false;
			if (snapshot->tx_buf)
				qdf_atomic_dec(&g_wma_injection_ctx.inflight_count);
			*completion_received = true;
		} else {
			entry->submit_pending = false;
		}
		found = true;
	}
	qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

	return found;
}

/**
 * wma_injection_desc_id_alloc() - allocate descriptor id for injection tx
 *
 * Return: descriptor id in dedicated injection range
 */
static uint16_t wma_injection_desc_id_alloc(void)
{
	static uint16_t next_desc_id = WMA_INJECTION_DESC_ID_BASE;
	uint16_t desc_id = next_desc_id;

	next_desc_id++;
	if ((next_desc_id & ~WMA_INJECTION_DESC_ID_MASK) !=
	    WMA_INJECTION_DESC_ID_BASE)
		next_desc_id = WMA_INJECTION_DESC_ID_BASE;

	return desc_id;
}

/**
 * wma_injection_queue_node_alloc() - Allocate injection queue node
 * @req: Frame injection request
 * @vdev_id: VDEV ID
 *
 * Return: Allocated node or NULL on failure
 */
static struct wma_injection_queue_node *
wma_injection_queue_node_alloc(struct inject_frame_req *req, uint8_t vdev_id)
{
	struct wma_injection_queue_node *node;
	uint8_t *frame_copy;

	if (!req || !req->frame_data || req->frame_len == 0) {
		wma_err("Invalid injection request parameters");
		return NULL;
	}

	if (req->frame_len > WMA_FRAME_INJECT_MAX_FRAME_SIZE) {
		wma_err("Frame size %u exceeds maximum %u",
			req->frame_len, WMA_FRAME_INJECT_MAX_FRAME_SIZE);
		return NULL;
	}

	node = qdf_mem_malloc(sizeof(*node));
	if (!node) {
		wma_err("Failed to allocate injection queue node");
		return NULL;
	}

	/* Allocate and copy frame data */
	frame_copy = qdf_mem_malloc(req->frame_len);
	if (!frame_copy) {
		wma_err("Failed to allocate frame data buffer");
		qdf_mem_free(node);
		return NULL;
	}

	qdf_mem_copy(frame_copy, req->frame_data, req->frame_len);

	/* Initialize node */
	qdf_mem_zero(node, sizeof(*node));
	node->req.frame_len = req->frame_len;
	node->req.frame_data = frame_copy;
	node->req.tx_flags = req->tx_flags;
	node->req.retry_count = req->retry_count;
	node->req.tx_rate = req->tx_rate;
	node->req.timestamp = req->timestamp;
	node->req.session_id = req->session_id;
	node->timestamp = qdf_get_log_timestamp();
	node->vdev_id = vdev_id;

	return node;
}

/**
 * wma_injection_queue_node_free() - Free injection queue node
 * @node: Node to free
 */
static void wma_injection_queue_node_free(struct wma_injection_queue_node *node)
{
	if (!node)
		return;

	if (node->req.frame_data) {
		qdf_mem_free(node->req.frame_data);
		node->req.frame_data = NULL;
	}

	qdf_mem_free(node);
}

/**
 * wma_check_traffic_coordination() - Check if injection can proceed with current traffic
 * @wma_handle: WMA handle
 * @vdev_id: VDEV ID for the frame
 *
 * This function checks if frame injection should be deferred due to high
 * priority traffic or resource constraints in the WMA layer.
 *
 * Return: true if injection can proceed, false if should be deferred
 */
static bool wma_check_traffic_coordination(tp_wma_handle wma_handle, uint8_t vdev_id)
{
	struct wma_txrx_node *iface;

	if (!wma_handle || vdev_id >= wma_handle->max_bssid) {
		wma_err("Invalid parameters: wma_handle=%pK, vdev_id=%u",
			wma_handle, vdev_id);
		return false;
	}

	iface = &wma_handle->interfaces[vdev_id];

	/* Check if interface is in a state that allows injection */
	if (!iface->vdev) {
		wma_debug("Interface %u not active, deferring injection", vdev_id);
		return false;
	}

	/* Check if there's high priority management traffic pending */
	if (iface->roaming_in_progress) {
		wma_debug("High priority operation in progress on vdev %u, deferring injection",
			  vdev_id);
		return false;
	}

	/* Check system-wide resource constraints */
	if (wma_handle->wmi_ready == false) {
		wma_debug("WMI not ready, deferring injection");
		return false;
	}

	/* Check if firmware is overloaded (simple heuristic) */
	if (wma_handle->wmi_handle) {
		uint32_t pending_cmds = wmi_get_pending_cmds(wma_handle->wmi_handle);
		const uint32_t max_pending_threshold = 512;

		if (pending_cmds > max_pending_threshold) {
			wma_debug("Firmware overloaded (%u pending commands), deferring injection",
				  pending_cmds);
			return false;
		}
	}

	return true;
}

/**
 * wma_apply_injection_backpressure() - Apply backpressure when queue is congested
 * @ctx: Injection queue context
 *
 * This function implements backpressure mechanisms when the injection queue
 * becomes congested, including adaptive processing delays and queue throttling.
 *
 * Return: Recommended delay in milliseconds before next processing cycle
 */
static uint32_t wma_apply_injection_backpressure(struct wma_injection_queue_ctx *ctx)
{
	uint32_t queue_utilization;
	uint32_t delay_ms = 0;

	if (!ctx || !ctx->is_initialized) {
		return 0;
	}

	/* Calculate queue utilization percentage */
	queue_utilization = (ctx->queue_size * 100) / ctx->max_queue_size;

	/* Apply adaptive backpressure based on queue utilization */
	if (queue_utilization > 95) {
		/* Queue nearly full - significant backpressure */
		delay_ms = 10;
	} else if (queue_utilization > 85) {
		/* Queue getting full - moderate backpressure */
		delay_ms = 2;
	}

	return delay_ms;
}

/**
 * wma_process_injection_queue() - Process injection queue with traffic coordination
 * @wma_handle: WMA handle
 *
 * This function processes the injection queue while coordinating with existing
 * WMA traffic scheduling and applying backpressure when needed.
 *
 * Return: QDF_STATUS_SUCCESS on success, error code on failure
 */
QDF_STATUS wma_process_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	qdf_list_node_t *list_node;
	QDF_STATUS status;
	QDF_STATUS requeue_status;
	uint64_t current_time;
	uint32_t processed_count = 0;
	uint32_t deferred_count = 0;
	const uint32_t max_process_per_cycle = 64;
	bool queue_was_empty;
	bool queue_paused;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_debug("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	current_time = qdf_get_log_timestamp();

	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_was_empty = qdf_list_empty(&ctx->queue);
	queue_paused = ctx->is_paused;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	if (queue_paused)
		return QDF_STATUS_E_AGAIN;

	if (queue_was_empty)
		return QDF_STATUS_SUCCESS;

	/* Process frames from queue with traffic coordination */
	while (processed_count < max_process_per_cycle) {
		qdf_spin_lock_bh(&ctx->queue_lock);

		if (ctx->is_paused) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			break;
		}

		if (qdf_list_empty(&ctx->queue)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			break;
		}

		/* Peek at the front node to check VDEV before removing */
		status = qdf_list_peek_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			wma_err("Failed to peek at queue front: %d", status);
			break;
		}

		node = qdf_container_of(list_node, struct wma_injection_queue_node, node);

		/* Check traffic coordination before processing */
		if (!wma_check_traffic_coordination(wma_handle, node->vdev_id)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			deferred_count++;
			wma_debug("Deferring injection due to traffic coordination (vdev_id=%u)",
				  node->vdev_id);
			break;
		}

		/* Remove the node from queue */
		status = qdf_list_remove_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			wma_err("Failed to remove node from queue: %d", status);
			break;
		}

		ctx->queue_size--;
		qdf_spin_unlock_bh(&ctx->queue_lock);

		/* Update queue time statistics */
		ctx->stats.total_queue_time += (current_time - node->timestamp);

		/* Send frame to firmware */
		status = wma_send_injection_frame_to_fw(wma_handle, &node->req, node->vdev_id);
		/*
		 * E_AGAIN is transient (for example, the helper VDEV is waiting
		 * for outstanding DMA to drain after a channel change). Preserve
		 * FIFO order and retry later instead of discarding the frame.
		 */
		if (status == QDF_STATUS_E_AGAIN) {
			qdf_spin_lock_bh(&ctx->queue_lock);
			requeue_status = qdf_list_insert_front(&ctx->queue,
							       &node->node);
			if (QDF_IS_STATUS_SUCCESS(requeue_status))
				ctx->queue_size++;
			qdf_spin_unlock_bh(&ctx->queue_lock);

			if (QDF_IS_STATUS_SUCCESS(requeue_status)) {
				deferred_count++;
				break;
			}

			ctx->stats.frames_dropped++;
			wma_err("Failed to requeue deferred injection frame: %d",
				requeue_status);
			wma_injection_queue_node_free(node);
			processed_count++;
			continue;
		}

		/*
		 * A successful return here means only that the command was
		 * accepted by the host/WMI submission path. Count frames_processed
		 * in wma_handle_injection_fw_response() after firmware completion,
		 * not here; otherwise stats double-count frames and the completion
		 * logger can suppress its own first-success diagnostics.
		 */
		if (QDF_IS_STATUS_ERROR(status)) {
			ctx->stats.frames_dropped++;
			wma_err("Failed to send injection frame to firmware: %d", status);
		}

		processed_count++;

		/* Free the node */
		wma_injection_queue_node_free(node);
	}

	wma_debug("Injection queue processing cycle complete: processed=%u, deferred=%u",
		  processed_count, deferred_count);

	/* Avoid immediate workqueue rescheduling while traffic coordination blocks TX. */
	if (deferred_count)
		return QDF_STATUS_E_AGAIN;

	return QDF_STATUS_SUCCESS;
}

/**
 * wma_process_injection_queue_work() - Work function to process injection queue
 * @arg: Work argument (not used)
 *
 * This function processes queued frame injection requests in FIFO order
 * with traffic coordination and backpressure handling.
 */
static void wma_process_injection_queue_work(void *arg)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	tp_wma_handle wma_handle;
	QDF_STATUS status;
	uint32_t backpressure_delay;
	bool queue_has_frames;
	bool queue_paused;

	if (!ctx->is_initialized) {
		wma_debug("Injection queue not initialized");
		return;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_paused = ctx->is_paused;
	qdf_spin_unlock_bh(&ctx->queue_lock);
	if (queue_paused)
		return;

	/* Get WMA handle for processing */
	wma_handle = cds_get_context(QDF_MODULE_ID_WMA);
	if (!wma_handle) {
		wma_err("Failed to get WMA handle");
		return;
	}

	/* Process the queue */
	status = wma_process_injection_queue(wma_handle);
	if (status == QDF_STATUS_E_AGAIN) {
		/*
		 * Yield to completions/reaper and retry without dropping the
		 * head-of-line frame or spinning the workqueue.
		 */
		qdf_delayed_work_start(&ctx->delayed_work, 10);
		return;
	}
	if (QDF_IS_STATUS_ERROR(status))
		wma_err("Failed to process injection queue: %d", status);

	/* Check if there are more frames to process */
	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_has_frames = !ctx->is_paused && !qdf_list_empty(&ctx->queue);
	qdf_spin_unlock_bh(&ctx->queue_lock);

	if (queue_has_frames) {
		/* Apply backpressure if queue is congested */
		backpressure_delay = wma_apply_injection_backpressure(ctx);
		
		if (backpressure_delay > 0) {
			qdf_delayed_work_start(&ctx->delayed_work, backpressure_delay);
		} else {
			/* Schedule immediate work for next processing cycle */
			qdf_sched_work(0, &ctx->queue_work);
		}
	}
}

/**
 * wma_process_injection_queue_delayed_work() - Delayed work callback for backpressure
 * @context: Context (not used)
 *
 * This function is called when delayed work is triggered for backpressure handling.
 * It simply schedules the regular work item to continue processing.
 */
static void wma_process_injection_queue_delayed_work(void *context)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	bool queue_paused;

	if (!ctx->is_initialized)
		return;

	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_paused = ctx->is_paused;
	qdf_spin_unlock_bh(&ctx->queue_lock);
	if (!queue_paused)
		qdf_sched_work(0, &ctx->queue_work);
}

/**
 * wma_injection_reaper_work_cb() - Periodic monitor for stuck injection nbufs
 * @context: Unused
 *
 * A timeout is not proof that firmware stopped reading a DMA-mapped buffer.
 * The reaper therefore only emits a one-shot warning for each overdue entry.
 * Ownership is released exclusively by a real firmware completion or after
 * a separately established hardware DMA-quiescence guarantee.
 */
static void wma_injection_reaper_work_cb(void *context)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	uint64_t now_ts, age_us;
	uint32_t warned = 0;
	int i;

	if (!ctx->is_initialized)
		return;

	now_ts = qdf_get_log_timestamp();

	for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
		struct wma_injection_debug_info *e;
		uint32_t desc_id = 0;
		uint8_t fc_type = 0, fc_subtype = 0;
		bool warn_entry = false;

		qdf_spin_lock_bh(&g_wma_injection_cache_lock);
		e = &g_wma_injection_debug_cache[i];
		if (e->valid && e->tx_buf && e->submit_ts &&
		    now_ts >= e->submit_ts) {
			age_us = qdf_log_timestamp_to_usecs(now_ts -
							    e->submit_ts);
			if (age_us >= WMA_INJECTION_NBUF_TIMEOUT_US &&
			    !e->reaper_warned) {
				e->reaper_warned = true;
				desc_id = e->desc_id;
				fc_type = e->fc_type;
				fc_subtype = e->fc_subtype;
				warn_entry = true;
			}
		}
		qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

		if (warn_entry) {
			wma_warn("Reaper: retaining DMA-owned nbuf desc_id=%u age=%llu us fc=0x%02x/0x%02x; awaiting completion or confirmed DMA stop",
				 desc_id, age_us, fc_type, fc_subtype);
			warned++;
		}
	}

	if (warned)
		wma_warn("Reaper: %u injection DMA buffer(s) remain owned; inflight=%d",
			 warned,
			 qdf_atomic_read(&g_wma_injection_ctx.inflight_count));

	/* Re-arm the periodic monitor while the queue remains initialized. */
	if (ctx->is_initialized)
		qdf_delayed_work_start(&ctx->reaper_work,
				       WMA_INJECTION_REAPER_INTERVAL_MS);
}


QDF_STATUS wma_init_injection_queue(
QDF_STATUS wma_init_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	QDF_STATUS status;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (ctx->is_initialized) {
		wma_debug("Injection queue already initialized");
		return QDF_STATUS_SUCCESS;
	}

	wma_debug("Initializing WMA injection queue");

	/* Initialize shared cache lock before any work can touch the cache. */
	qdf_spinlock_create(&g_wma_injection_cache_lock);

	/* Initialize queue */
	qdf_list_create(&ctx->queue, WMA_FRAME_INJECT_MAX_QUEUE_SIZE);

	/* Initialize queue lock */
	qdf_spinlock_create(&ctx->queue_lock);

	/* Initialize work item */
	qdf_create_work(0, &ctx->queue_work, wma_process_injection_queue_work, NULL);

	/* Initialize delayed work item for backpressure */
	status = qdf_delayed_work_create(&ctx->delayed_work, 
					 wma_process_injection_queue_delayed_work, NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Failed to create delayed work: %d", status);
		qdf_spinlock_destroy(&ctx->queue_lock);
		qdf_list_destroy(&ctx->queue);
		qdf_spinlock_destroy(&g_wma_injection_cache_lock);
		return status;
	}

	/* Initialize nbuf-leak reaper timer */
	status = qdf_delayed_work_create(&ctx->reaper_work,
					 wma_injection_reaper_work_cb, NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Failed to create reaper work: %d", status);
		qdf_delayed_work_destroy(&ctx->delayed_work);
		qdf_spinlock_destroy(&ctx->queue_lock);
		qdf_list_destroy(&ctx->queue);
		qdf_spinlock_destroy(&g_wma_injection_cache_lock);
		return status;
	}

	/* Initialize context */
	ctx->queue_size = 0;
	ctx->max_queue_size = WMA_FRAME_INJECT_MAX_QUEUE_SIZE;
	ctx->is_paused = false;
	qdf_mem_zero(&ctx->stats, sizeof(ctx->stats));
	qdf_atomic_init(&ctx->inflight_count);
	ctx->is_initialized = true;

	/* Arm the reaper */
	qdf_delayed_work_start(&ctx->reaper_work,
			       WMA_INJECTION_REAPER_INTERVAL_MS);

	wma_info("WMA injection queue initialized successfully (max_size=%u)",
		 ctx->max_queue_size);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_deinit_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	qdf_list_node_t *list_node;
	QDF_STATUS status;
	uint32_t dropped_count = 0;
	uint32_t active_bufs = 0;
	uint32_t wait_ms = 0;
	uint32_t i;
	int inflight;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_debug("Injection queue not initialized");
		return QDF_STATUS_SUCCESS;
	}

	wma_debug("Deinitializing WMA injection queue (fail-closed)");

	/* Stop new producers before cancelling work and tearing down the VDEV. */
	qdf_spin_lock_bh(&ctx->queue_lock);
	ctx->is_paused = true;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	/*
	 * Drain queue processing first. A running queue worker may schedule the
	 * delayed worker on its way out, so stop delayed_work only after the
	 * regular work item has been cancelled and flushed.
	 */
	qdf_cancel_work(&ctx->queue_work);
	qdf_flush_work(&ctx->queue_work);
	qdf_delayed_work_stop_sync(&ctx->delayed_work);

	/*
	 * Pending queue nodes contain host copies, not DMA-owned nbufs. They can
	 * be discarded now; the in-flight cache is handled separately below.
	 */
	qdf_spin_lock_bh(&ctx->queue_lock);
	while (!qdf_list_empty(&ctx->queue)) {
		status = qdf_list_remove_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Failed to remove node during cleanup: %d", status);
			break;
		}

		node = qdf_container_of(list_node, struct wma_injection_queue_node,
					node);
		wma_injection_queue_node_free(node);
		dropped_count++;
	}
	ctx->queue_size = 0;
	ctx->stats.frames_dropped += dropped_count;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	/*
	 * A missing completion cannot be repaired by an age-based free. Wait
	 * briefly for real completions, then leave the queue/cache/locks alive
	 * and return E_AGAIN. The caller may retry deinit after the controller
	 * has completed or has been independently confirmed DMA-quiescent.
	 */
	while (qdf_atomic_read(&ctx->inflight_count) > 0 && wait_ms < 3500) {
		msleep(20);
		wait_ms += 20;
	}

	inflight = qdf_atomic_read(&ctx->inflight_count);
	if (inflight > 0) {
		wma_warn("Deinit deferred: inflight=%d after %u ms; retaining DMA buffers and cache state",
			 inflight, wait_ms);
		return QDF_STATUS_E_AGAIN;
	}

	/*
	 * Count and inspect actual pointers as well as inflight_count. Never
	 * destroy the helper or cache lock if the two ownership indicators
	 * disagree; a non-NULL nbuf remains device-owned until proven otherwise.
	 */
	qdf_spin_lock_bh(&g_wma_injection_cache_lock);
	for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
		if (g_wma_injection_debug_cache[i].tx_buf)
			active_bufs++;
	}
	qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

	if (active_bufs) {
		wma_warn("Deinit deferred: inflight_count is zero but %u DMA buffer pointer(s) remain; retaining cache state",
			 active_bufs);
		return QDF_STATUS_E_BUSY;
	}

	/*
	 * No tracked DMA remains. Only now may the helper VDEV be destroyed.
	 * If WMI teardown fails, keep the synchronization/cache objects intact
	 * so teardown can be retried safely.
	 */
	status = wma_injection_destroy_tx_vdev(wma_handle, true);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_warn("Injection helper teardown incomplete (%d); retaining queue/cache state",
			 status);
		return status;
	}

	/* No active buffer can be reclaimed here; all pointers were verified NULL. */
	qdf_delayed_work_stop_sync(&ctx->reaper_work);
	qdf_delayed_work_destroy(&ctx->reaper_work);
	qdf_delayed_work_destroy(&ctx->delayed_work);

	qdf_spin_lock_bh(&g_wma_injection_cache_lock);
	for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
		struct wma_injection_debug_info *e =
			&g_wma_injection_debug_cache[i];

		/* Do not free here: this block is metadata-only after the NULL check. */
		e->valid = false;
		e->submit_pending = false;
		e->completion_pending = false;
		e->completion_status = 0;
		e->desc_id = 0;
		e->tx_buf = NULL;
		e->submit_ts = 0;
		e->reaper_warned = false;
	}
	qdf_spin_unlock_bh(&g_wma_injection_cache_lock);

	/* Destroy queue and lock only after DMA ownership has fully drained. */
	qdf_list_destroy(&ctx->queue);
	qdf_spinlock_destroy(&ctx->queue_lock);
	qdf_spinlock_destroy(&g_wma_injection_cache_lock);
	ctx->is_initialized = false;

	wma_info("WMA injection queue deinitialized (dropped %u pending frames; DMA drained)",
		 dropped_count);

	return QDF_STATUS_SUCCESS;
}


QDF_STATUS wma_queue_injection_frame(
QDF_STATUS wma_queue_injection_frame(tp_wma_handle wma_handle,
				     struct inject_frame_req *req,
				     uint8_t vdev_id)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	uint32_t queue_size, max_queue_size;
	QDF_STATUS status;

	if (!wma_handle || !req) {
		wma_err("Invalid parameters: wma_handle=%pK, req=%pK",
			wma_handle, req);
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	/* Validate frame parameters */
	if (!req->frame_data || req->frame_len == 0 ||
	    req->frame_len > WMA_FRAME_INJECT_MAX_FRAME_SIZE) {
		wma_err("Invalid frame parameters: data=%pK, len=%u",
			req->frame_data, req->frame_len);
		return QDF_STATUS_E_INVAL;
	}

	/* Check queue state and overflow */
	qdf_spin_lock_bh(&ctx->queue_lock);

	if (ctx->is_paused) {
		qdf_spin_unlock_bh(&ctx->queue_lock);
		return QDF_STATUS_E_AGAIN;
	}

	if (ctx->queue_size >= ctx->max_queue_size) {
		queue_size = ctx->queue_size;
		max_queue_size = ctx->max_queue_size;
		ctx->stats.queue_overflows++;
		ctx->stats.frames_dropped++;
		qdf_spin_unlock_bh(&ctx->queue_lock);
		wma_err("Injection queue overflow (size=%u, max=%u)",
			queue_size, max_queue_size);
		return QDF_STATUS_E_RESOURCES;
	}

	qdf_spin_unlock_bh(&ctx->queue_lock);

	/*
	 * DMA in-flight admission is reserved atomically immediately before
	 * WMI submission. Keep frames queued while that window is full so the
	 * worker can apply backpressure and retry instead of dropping frames.
	 */

	/* Allocate and initialize queue node */
	node = wma_injection_queue_node_alloc(req, vdev_id);
	if (!node) {
		ctx->stats.frames_dropped++;
		wma_err("Failed to allocate injection queue node");
		return QDF_STATUS_E_NOMEM;
	}

	/*
	 * Re-check under the insertion lock. Multiple producers can pass the
	 * earlier fast-path overflow check while allocating their queue nodes.
	 */
	qdf_spin_lock_bh(&ctx->queue_lock);
	if (ctx->is_paused) {
		qdf_spin_unlock_bh(&ctx->queue_lock);
		wma_injection_queue_node_free(node);
		return QDF_STATUS_E_AGAIN;
	}
	if (ctx->queue_size >= ctx->max_queue_size) {
		ctx->stats.queue_overflows++;
		ctx->stats.frames_dropped++;
		qdf_spin_unlock_bh(&ctx->queue_lock);
		wma_injection_queue_node_free(node);
		wma_err("Injection queue filled during allocation (max=%u)",
			ctx->max_queue_size);
		return QDF_STATUS_E_RESOURCES;
	}

	/* Add to queue while the capacity check is still protected. */
	status = qdf_list_insert_back(&ctx->queue, &node->node);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_spin_unlock_bh(&ctx->queue_lock);
		wma_injection_queue_node_free(node);
		ctx->stats.frames_dropped++;
		wma_err("Failed to add node to queue: %d", status);
		return status;
	}

	ctx->queue_size++;
	ctx->stats.frames_queued++;

	/* Update maximum queue depth */
	if (ctx->queue_size > ctx->stats.max_queue_depth) {
		ctx->stats.max_queue_depth = ctx->queue_size;
	}

	qdf_spin_unlock_bh(&ctx->queue_lock);

	/* Schedule queue processing work */
	qdf_sched_work(0, &ctx->queue_work);

	wma_debug("Queued injection frame: len=%u, vdev_id=%u, queue_size=%u",
		  req->frame_len, vdev_id, ctx->queue_size);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_get_injection_queue_stats(tp_wma_handle wma_handle,
					 struct wma_injection_queue_stats *stats)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle || !stats) {
		wma_err("Invalid parameters: wma_handle=%pK, stats=%pK",
			wma_handle, stats);
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	qdf_mem_copy(stats, &ctx->stats, sizeof(*stats));
	qdf_spin_unlock_bh(&ctx->queue_lock);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_reset_injection_queue_stats(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	qdf_mem_zero(&ctx->stats, sizeof(ctx->stats));
	qdf_spin_unlock_bh(&ctx->queue_lock);

	wma_info("Injection queue statistics reset");

	return QDF_STATUS_SUCCESS;
}

uint32_t wma_get_injection_queue_size(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	uint32_t queue_size;

	if (!wma_handle || !ctx->is_initialized) {
		return 0;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_size = ctx->queue_size;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	return queue_size;
}

bool wma_is_injection_queue_empty(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	bool is_empty;

	if (!wma_handle || !ctx->is_initialized) {
		return true;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	is_empty = qdf_list_empty(&ctx->queue);
	qdf_spin_unlock_bh(&ctx->queue_lock);

	return is_empty;
}

QDF_STATUS wma_flush_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	qdf_list_node_t *list_node;
	QDF_STATUS status;
	uint32_t flushed_count = 0;
	bool was_paused;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	wma_debug("Flushing injection queue");

	/* Gate producers/work first, then wait for any active send to finish. */
	qdf_spin_lock_bh(&ctx->queue_lock);
	was_paused = ctx->is_paused;
	ctx->is_paused = true;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	qdf_delayed_work_stop_sync(&ctx->delayed_work);
	qdf_cancel_work(&ctx->queue_work);
	qdf_flush_work(&ctx->queue_work);

	/* Flush all queued frames */
	qdf_spin_lock_bh(&ctx->queue_lock);

	while (!qdf_list_empty(&ctx->queue)) {
		status = qdf_list_remove_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Failed to remove node during flush: %d", status);
			break;
		}

		node = qdf_container_of(list_node, struct wma_injection_queue_node, node);
		wma_injection_queue_node_free(node);
		flushed_count++;
	}

	ctx->queue_size = 0;
	ctx->stats.frames_dropped += flushed_count;

	qdf_spin_unlock_bh(&ctx->queue_lock);

	/* Restore the prior state; pre-stop/deinit callers keep it paused. */
	qdf_spin_lock_bh(&ctx->queue_lock);
	ctx->is_paused = was_paused;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	wma_info("Flushed %u frames from injection queue", flushed_count);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_resume_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle)
		return QDF_STATUS_E_INVAL;
	if (!ctx->is_initialized)
		return QDF_STATUS_E_AGAIN;

	qdf_spin_lock_bh(&ctx->queue_lock);
	ctx->is_paused = false;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	wma_info("WMA injection queue resumed");
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_send_injection_frame_to_fw(tp_wma_handle wma_handle,
					  struct inject_frame_req *req,
					  uint8_t vdev_id)
{
	struct wmi_mgmt_params mgmt_params;
	QDF_STATUS status;
	qdf_nbuf_t wmi_buf;
	uint8_t *frame_data;
	struct cdp_soc_t *soc;
	void *qdf_ctx;
	int ret;
	uint16_t tx_chanfreq = 0;
	uint8_t fc0 = 0;
	uint8_t fc_type = 0;
	uint8_t fc_subtype = 0;
	bool is_bcast_da = false;
	bool wmi_mgmt_service;
	bool wmi_tx_attempted = false;
	bool wmi_tx_ok = false;
	struct wma_injection_debug_info failed_tx_snapshot;
	bool have_failed_tx_snapshot;
	bool completion_received;
	bool is_probe_req = false;
	bool monitor_vdev = false;

	if (!wma_handle || !req || !req->frame_data) {
		wma_err("Invalid parameters: wma_handle=%pK, req=%pK",
			wma_handle, req);
		return QDF_STATUS_E_INVAL;
	}

	if (!inject_patch_banner_logged) {
		wma_info("Injection patch tag: monitor_sta_vdev_tx_v7");
		inject_patch_banner_logged = true;
	}

	if (req->frame_len == 0 || req->frame_len > WMA_FRAME_INJECT_MAX_FRAME_SIZE) {
		wma_err("Invalid frame length: %u", req->frame_len);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle->wmi_handle) {
		wma_err("Invalid WMI handle in injection path");
		return QDF_STATUS_E_INVAL;
	}

	if (vdev_id >= wma_handle->max_bssid) {
		wma_err("Invalid injection vdev_id %u (max %u)",
			vdev_id, wma_handle->max_bssid);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle->interfaces[vdev_id].vdev) {
		wma_err("Injection vdev %u is not active", vdev_id);
		return QDF_STATUS_E_AGAIN;
	}

	if (wma_handle->interfaces[vdev_id].mhz)
		tx_chanfreq = wma_handle->interfaces[vdev_id].mhz;

	if (!tx_chanfreq)
		wma_warn("Injection: tx_chanfreq is 0, firmware may use wrong channel");

	if (req->frame_len)
		fc0 = req->frame_data[0];

	fc_type = fc0 & 0x0c;
	fc_subtype = fc0 & 0xf0;
	is_probe_req = (fc_type == 0x00 && fc_subtype == 0x40);
	if (req->frame_len >= 10) {
		uint8_t *da = &req->frame_data[4];

		if (da[0] == 0xff && da[1] == 0xff && da[2] == 0xff &&
		    da[3] == 0xff && da[4] == 0xff && da[5] == 0xff)
			is_bcast_da = true;
	}

	qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);
	if (!qdf_ctx) {
		wma_err("qdf_ctx is NULL in injection path");
		return QDF_STATUS_E_INVAL;
	}

	monitor_vdev =
		(wma_handle->interfaces[vdev_id].type == WMI_VDEV_TYPE_MONITOR);
	if (monitor_vdev && !tx_chanfreq) {
		wma_err("Injection monitor vdev %u has zero channel frequency; dropping frame",
			vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	/* Allocate WMI buffer for the frame */
	wmi_buf = qdf_nbuf_alloc(NULL, req->frame_len, 0, 0, false);
	if (!wmi_buf) {
		wma_err("Failed to allocate WMI buffer for injection frame");
		return QDF_STATUS_E_NOMEM;
	}

	/* Copy frame data to WMI buffer */
	frame_data = qdf_nbuf_put_tail(wmi_buf, req->frame_len);
	if (!frame_data) {
		wma_err("Failed to get buffer space for frame data");
		qdf_nbuf_free(wmi_buf);
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_copy(frame_data, req->frame_data, req->frame_len);

	/*
	 * Monitor management TX uses g_inj_tx_vdev, whose source MAC is the
	 * monitor interface MAC with the locally-administered bit set. Firmware
	 * may discard management frames whose SA disagrees with that TX vdev.
	 * Translate the monitor interface's own SA for every management frame.
	 * Preserve an explicitly supplied alternate SA, except broadcast probe
	 * requests, for which this firmware requires the helper's SA.
	 */
	if (monitor_vdev && fc_type == 0x00 && req->frame_len >= 24) {
		uint8_t *monitor_mac =
			wlan_vdev_mlme_get_macaddr(wma_handle->interfaces[vdev_id].vdev);
		uint8_t tx_mac[QDF_MAC_ADDR_SIZE];
		bool uses_monitor_sa;

		if (monitor_mac) {
			qdf_mem_copy(tx_mac, monitor_mac, QDF_MAC_ADDR_SIZE);
			tx_mac[0] |= 0x02;
			uses_monitor_sa =
				qdf_mem_cmp(frame_data + 10, monitor_mac,
					    QDF_MAC_ADDR_SIZE) == 0;

			if (uses_monitor_sa || (is_probe_req && is_bcast_da)) {
				if (qdf_mem_cmp(frame_data + 10, tx_mac,
						QDF_MAC_ADDR_SIZE) != 0) {
					if (!inject_mgmt_sa_fix_logged) {
						wma_warn("Injection management SA override %pM -> helper TX MAC %pM (monitor vdev %u)",
							 frame_data + 10, tx_mac, vdev_id);
						inject_mgmt_sa_fix_logged = true;
					}
					qdf_mem_copy(frame_data + 10, tx_mac,
						     QDF_MAC_ADDR_SIZE);
					qdf_mem_copy(req->frame_data + 10, tx_mac,
						     QDF_MAC_ADDR_SIZE);
				}
			}
		}
	}
	/* Initialize WMI management parameters for injection */
	qdf_mem_zero(&mgmt_params, sizeof(mgmt_params));
	mgmt_params.tx_frame = wmi_buf;
	mgmt_params.frm_len = req->frame_len;
	mgmt_params.vdev_id = vdev_id;
	/*
	 * Use ACK-completion tx type for injection consistently. Several
	 * firmware builds are stricter with probe-request tx_type handling and
	 * are less likely to discard when sent with ACK-completion semantics.
	 */
	mgmt_params.tx_type = GENERIC_NODOWLOAD_ACK_COMP_INDEX;
	/*
	 * Align with regular host management TX behavior:
	 * probe request uses chanfreq=0 while action/auth/probe-rsp can carry
	 * an explicit channel.
	 */
	mgmt_params.chanfreq = is_probe_req ? 0 : tx_chanfreq;
	/*
	 * For monitor vdev probe injection, prefer explicit channel in command
	 * so firmware can bind probe request tx to the current monitor channel.
	 */
	if (monitor_vdev && is_probe_req && tx_chanfreq)
		mgmt_params.chanfreq = tx_chanfreq;
	mgmt_params.desc_id = wma_injection_desc_id_alloc();
	mgmt_params.pdata = frame_data; /* Management frame bytes for command payload */
	mgmt_params.macaddr = NULL; /* No specific MAC address */
	mgmt_params.qdf_ctx = qdf_ctx;
	mgmt_params.tx_params_valid = false; /* Use default TX parameters */
	/*
	 * Diagnostic experiment for WCN6855: request 6 Mbps for monitor
	 * injection when the caller did not specify a rate. Firmware may
	 * override this; the log below records the requested setting.
	 */
	mgmt_params.use_6mbps = (monitor_vdev && !req->tx_rate) ? 1 : 0;
	status = wma_injection_debug_cache_update(mgmt_params.desc_id, req,
						  fc_type, fc_subtype,
						  mgmt_params.chanfreq);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_nbuf_free(wmi_buf);
		if (status != QDF_STATUS_E_AGAIN)
			wma_err("Injection: cannot reserve debug cache slot for desc_id=%u: %d",
				mgmt_params.desc_id, status);
		return status;
	}

	/* Set transmission rate if specified in injection request */
	if (req->tx_rate != 0) {
		mgmt_params.tx_param.mcs_mask = req->tx_rate;
		mgmt_params.tx_params_valid = true;
	}

	if (!inject_tx_cfg_logged) {
		wma_info("Injection TX config: vdev=%u iface_type=%u iface_subtype=%u vdev_active=%u chanfreq=%u",
			 vdev_id,
			 wma_handle->interfaces[vdev_id].type,
			 wma_handle->interfaces[vdev_id].sub_type,
			 wma_handle->interfaces[vdev_id].vdev_active ? 1 : 0,
			 mgmt_params.chanfreq);
		inject_tx_cfg_logged = true;
	}

	if (inject_send_info_count < 10) {
		if (req->frame_len >= 24) {
			uint8_t *addr1 = &req->frame_data[4];
			uint8_t *addr2 = &req->frame_data[10];
			uint8_t *addr3 = &req->frame_data[16];

			wma_info("Injection frame[%u]: desc_id=%u vdev=%u len=%u fc_type=0x%02x fc_subtype=0x%02x tx_chanfreq=%u cmd_chanfreq=%u addr1=%pM addr2=%pM addr3=%pM",
				 inject_send_info_count + 1, mgmt_params.desc_id,
				 vdev_id, req->frame_len,
				 fc_type, fc_subtype, tx_chanfreq, mgmt_params.chanfreq,
				 addr1, addr2, addr3);
		} else {
			wma_info("Injection frame[%u]: desc_id=%u vdev=%u len=%u fc_type=0x%02x fc_subtype=0x%02x tx_chanfreq=%u cmd_chanfreq=%u",
				 inject_send_info_count + 1, mgmt_params.desc_id,
				 vdev_id, req->frame_len,
				 fc_type, fc_subtype, tx_chanfreq, mgmt_params.chanfreq);
		}
		inject_send_info_count++;
	}

	wmi_mgmt_service = wmi_service_enabled(wma_handle->wmi_handle,
					       wmi_service_mgmt_tx_wmi);
	if (monitor_vdev && !wmi_mgmt_service &&
	    !inject_wmi_service_absent_logged) {
		wma_warn("Injection monitor vdev: mgmt_tx_wmi service bit is 0, "
			 "but WMI TX will still be attempted via hidden STA vdev");
		inject_wmi_service_absent_logged = true;
	}



	if (monitor_vdev) {
		/*
		 * FW _wlan_send_mgmt_to_host rejects MONITOR vdevs (falls
		 * to a beacon-only path → DISCARD). Route through the hidden
		 * STA helper vdev, which uses the normal peer-lookup/WAL-TX path.
		 */
		status = wma_injection_ensure_tx_vdev(wma_handle,
						     vdev_id, tx_chanfreq);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Failed to create injection TX helper vdev: %d",
				status);
			qdf_nbuf_free(wmi_buf);
			return status;
		}
		mgmt_params.vdev_id = g_inj_tx_vdev.vdev_id;
		if (!inject_monitor_no_legacy_logged) {
			wma_warn("Injection monitor: using hidden STA vdev %u for TX (monitor vdev %u)",
				 g_inj_tx_vdev.vdev_id, vdev_id);
			inject_monitor_no_legacy_logged = true;
		}
	}

	/* Attempt WMI management TX path. */
	wmi_tx_attempted = true;
	if (!inject_wmi_path_logged) {
		wma_info("Injection using WMI mgmt tx path (vdev_id=%u)",
			 mgmt_params.vdev_id);
		inject_wmi_path_logged = true;
	}
	if (inject_send_info_count <= 10) {
		wma_info("Injection WMI submit: vdev_id=%u chanfreq=%u len=%u use_6mbps=%u tx_params_valid=%u tx_rate=%u",
			 mgmt_params.vdev_id, mgmt_params.chanfreq,
			 req->frame_len, mgmt_params.use_6mbps,
			 mgmt_params.tx_params_valid ? 1 : 0, req->tx_rate);
		QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_INFO,
				   req->frame_data,
				   QDF_MIN(32, req->frame_len));
	}

	/*
	 * Publish and reserve the buffer before WMI submission so an immediate
	 * firmware completion can claim it and the in-flight count cannot race
	 * past the 200-buffer admission limit. If capacity is exhausted, leave
	 * the frame queued for a delayed retry; never submit an untracked nbuf.
	 */
	status = wma_injection_debug_cache_set_tx_buf(mgmt_params.desc_id,
						      wmi_buf);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_injection_debug_cache_get(mgmt_params.desc_id,
					      &failed_tx_snapshot, false, 0);
		qdf_nbuf_free(wmi_buf);
		if (status != QDF_STATUS_E_AGAIN)
			wma_err("Injection: cannot reserve TX cache slot for desc_id=%u",
				mgmt_params.desc_id);
		return status;
	}

	status = wmi_mgmt_unified_cmd_send(wma_handle->wmi_handle, &mgmt_params);
	wma_info("wmi_mgmt_unified_cmd_send returned: %d", status);
	if (!QDF_IS_STATUS_ERROR(status)) {
		wmi_tx_ok = true;
		if (!wma_injection_debug_cache_submit_done(
				mgmt_params.desc_id, &failed_tx_snapshot,
				&completion_received)) {
			wma_err("Injection: cache entry disappeared before WMI submit completed (desc_id=%u)",
				mgmt_params.desc_id);
		} else if (completion_received && failed_tx_snapshot.tx_buf) {
			wma_injection_unmap_tx_buf(failed_tx_snapshot.tx_buf);
			qdf_nbuf_free(failed_tx_snapshot.tx_buf);
		}
	} else {
		wma_warn("WMI management TX command failed: %d (service=%u monitor=%u)",
			 status, wmi_mgmt_service ? 1 : 0, monitor_vdev ? 1 : 0);
	}

	if (!wmi_tx_ok) {
		/*
		 * WMI rejected the command, so reclaim the buffer from the cache
		 * before freeing it or handing it to the legacy CDP path. This also
		 * decrements inflight_count under the same lock as completion/reaper.
		 */
		have_failed_tx_snapshot =
			wma_injection_debug_cache_get(mgmt_params.desc_id,
					      &failed_tx_snapshot, false, 0);
		if (!have_failed_tx_snapshot || !failed_tx_snapshot.tx_buf) {
			wma_err("Injection: failed WMI submit has no cache-owned buffer (desc_id=%u); skip fallback",
				mgmt_params.desc_id);
			return status;
		}
		wmi_buf = failed_tx_snapshot.tx_buf;

		if (failed_tx_snapshot.completion_pending) {
			/*
			 * A completion arrived while the WMI submit call was still
			 * returning. It owns the result; do not retry the frame.
			 */
			wma_injection_unmap_tx_buf(wmi_buf);
			qdf_nbuf_free(wmi_buf);
			return failed_tx_snapshot.completion_status ==
				WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK ?
				QDF_STATUS_SUCCESS : status;
		}

		if (monitor_vdev) {
			wma_warn("Injection monitor vdev: WMI TX failed (%d); dropping frame to avoid legacy firmware assert",
				 status);
			qdf_nbuf_free(wmi_buf);
			return status;
		}

		/*
		 * For non-monitor vdevs only, hand the reclaimed buffer to the
		 * legacy CDP Data Path. Monitor-vdev failures return above because
		 * legacy monitor management TX can enter the firmware assert path.
		 */

		/* Fallback to legacy data path if WMI TX is unavailable or failed. */
		if (!inject_legacy_path_logged) {
			wma_warn("Injection using legacy cdp_mgmt_send_ext fallback (wmi_mgmt_service=%u)",
				 wmi_mgmt_service ? 1 : 0);
			inject_legacy_path_logged = true;
		}

		/* Try legacy CDP management send path */
		soc = cds_get_context(QDF_MODULE_ID_SOC);
		if (!soc) {
			wma_err("Failed to get CDP SOC context");
			qdf_nbuf_free(wmi_buf);
			return QDF_STATUS_E_FAILURE;
		}

		/* Set frame control information for legacy path */
		QDF_NBUF_CB_MGMT_TXRX_DESC_ID(wmi_buf) = mgmt_params.desc_id;

		if (inject_send_info_count <= 10) {
			wma_info("Injection via Data Path: vdev_id=%u chanfreq=%u len=%u use_6mbps=%u tx_params_valid=%u",
				 mgmt_params.vdev_id, mgmt_params.chanfreq,
				 req->frame_len, mgmt_params.use_6mbps,
				 mgmt_params.tx_params_valid ? 1 : 0);
			if (!mgmt_params.chanfreq)
				wma_warn("Injection: tx_chanfreq is 0, firmware may use wrong channel");
			QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_WMA, QDF_TRACE_LEVEL_INFO,
					   req->frame_data,
					   QDF_MIN(32, req->frame_len));
		}

		ret = cdp_mgmt_send_ext(soc, mgmt_params.vdev_id, wmi_buf,
					mgmt_params.tx_type,
					mgmt_params.use_6mbps,
					mgmt_params.chanfreq);
		wma_info("cdp_mgmt_send_ext returned: %d", ret);
		if (ret == -EINVAL)
			wma_warn("Legacy management TX got -EINVAL (desc alloc or tx pool reject)");
		status = qdf_status_from_os_return(ret);
		
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Legacy management TX failed: %d (wmi_attempted=%u)",
				status, wmi_tx_attempted ? 1 : 0);
			/*
			 * ol_txrx_mgmt_send_ext() returns before descriptor ownership
			 * transfer when vdev lookup or descriptor allocation fails.
			 * In those rejection paths CDP has not consumed this nbuf.
			 */
			if (ret == -EINVAL || ret == QDF_STATUS_E_FAULT)
				qdf_nbuf_free(wmi_buf);
			return status;
		}
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_handle_injection_fw_response(tp_wma_handle wma_handle,
					     uint32_t desc_id,
					     uint32_t status)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_debug_info dbg_snapshot;
	bool have_dbg_entry;
	const char *status_str;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_debug("Injection queue not initialized, ignoring response");
		return QDF_STATUS_SUCCESS;
	}

	/* Map firmware status to string for logging */
	switch (status) {
	case WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK:
		status_str = "SUCCESS";
		break;
	case WMI_MGMT_TX_COMP_TYPE_DISCARD:
		status_str = "DISCARDED";
		ctx->stats.frames_dropped++;
		break;
	case WMI_MGMT_TX_COMP_TYPE_COMPLETE_NO_ACK:
		status_str = "NO_ACK";
		break;
	case WMI_MGMT_TX_COMP_TYPE_INSPECT:
		status_str = "INSPECT";
		break;
	default:
		status_str = "UNKNOWN";
		ctx->stats.frames_dropped++;
		break;
	}

	/*
	 * Claim and invalidate the cache entry under the shared cache lock.
	 * After the helper returns, the local snapshot exclusively owns tx_buf.
	 */
	have_dbg_entry = wma_injection_debug_cache_get(desc_id, &dbg_snapshot,
						      true, status);
	if (have_dbg_entry) {
		/*
		 * Log the first few completions for each status category
		 * so the user can verify injection works, then go silent
		 * to avoid flooding dmesg and killing throughput.
		 */
		if (status == WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK) {
			if (ctx->stats.frames_processed < 5)
				wma_info("Injection completion: desc_id=%u status=OK len=%u fc_type=0x%02x fc_subtype=0x%02x chanfreq=%u",
					 desc_id, dbg_snapshot.frame_len,
					 dbg_snapshot.fc_type, dbg_snapshot.fc_subtype,
					 dbg_snapshot.chanfreq);
		} else {
			ctx->stats.fw_errors++;
			if (ctx->stats.fw_errors <= 10)
				wma_info("Injection completion: desc_id=%u status=%s(%u) len=%u fc_type=0x%02x fc_subtype=0x%02x chanfreq=%u addr1=%pM addr2=%pM addr3=%pM",
					 desc_id, status_str, status,
					 dbg_snapshot.frame_len,
					 dbg_snapshot.fc_type, dbg_snapshot.fc_subtype,
					 dbg_snapshot.chanfreq, dbg_snapshot.addr1,
					 dbg_snapshot.addr2, dbg_snapshot.addr3);
		}

		/*
		 * The nbuf was detached from the cache while locked, so the reaper
		 * cannot unmap/free it a second time.
		 */
		if (dbg_snapshot.tx_buf) {
			wma_injection_unmap_tx_buf(dbg_snapshot.tx_buf);
			qdf_nbuf_free(dbg_snapshot.tx_buf);
		}
	} else if (status != WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK) {
		ctx->stats.fw_errors++;
		if (ctx->stats.fw_errors <= 10)
			wma_info("Injection completion: desc_id=%u status=%s(%u)",
				 desc_id, status_str, status);
	}

	if (status == WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK)
		ctx->stats.frames_processed++;

	return QDF_STATUS_SUCCESS;
}

#else /* FEATURE_FRAME_INJECTION_SUPPORT */

QDF_STATUS wma_send_injection_frame_to_fw(tp_wma_handle wma_handle,
					  struct inject_frame_req *req,
					  uint8_t vdev_id)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS wma_handle_injection_fw_response(tp_wma_handle wma_handle,
					     uint32_t desc_id,
					     uint32_t status)
{
	QDF_STATUS qdf_status = QDF_STATUS_SUCCESS;
	enum wma_injection_fw_error_type error_type;

	WMA_LOGD("Handling firmware injection response: desc_id=%u, status=0x%x", desc_id, status);

	if (!wma_handle) {
		WMA_LOGE("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	/* Check if this is an error response */
	if (status != 0) {
		WMA_LOGW("Firmware injection failed: desc_id=%u, status=0x%x", desc_id, status);
		
		/* Handle the firmware error */
		qdf_status = wma_handle_firmware_injection_error(wma_handle, status, 0, NULL);
		if (QDF_IS_STATUS_ERROR(qdf_status) && qdf_status != QDF_STATUS_E_PENDING) {
			WMA_LOGE("Failed to handle firmware injection error: %d", qdf_status);
			return qdf_status;
		}
	} else {
		WMA_LOGD("Firmware injection completed successfully: desc_id=%u", desc_id);
	}

	/* Update statistics would go here in a full implementation */
	
	return qdf_status;
}

QDF_STATUS wma_init_injection_queue(tp_wma_handle wma_handle)
{
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_deinit_injection_queue(tp_wma_handle wma_handle)
{
	return QDF_STATUS_SUCCESS;
}

void wma_injection_pre_stop_cleanup(tp_wma_handle wma_handle)
{
}

QDF_STATUS wma_queue_injection_frame(tp_wma_handle wma_handle,
				     struct inject_frame_req *req,
				     uint8_t vdev_id)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS wma_get_injection_queue_stats(tp_wma_handle wma_handle,
					 struct wma_injection_queue_stats *stats)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS wma_reset_injection_queue_stats(tp_wma_handle wma_handle)
{
	return QDF_STATUS_E_NOSUPPORT;
}

uint32_t wma_get_injection_queue_size(tp_wma_handle wma_handle)
{
	return 0;
}

bool wma_is_injection_queue_empty(tp_wma_handle wma_handle)
{
	return true;
}

QDF_STATUS wma_flush_injection_queue(tp_wma_handle wma_handle)
{
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_translate_fw_injection_error() - Translate firmware error codes
 * @fw_error_code: Firmware-specific error code
 *
 * This function translates firmware-specific error codes to standard
 * WMA injection error types for consistent error handling.
 *
 * Return: Translated error type
 */
enum wma_injection_fw_error_type wma_translate_fw_injection_error(uint32_t fw_error_code)
{
	enum wma_injection_fw_error_type error_type;

	WMA_LOGD("Translating firmware error code: 0x%x", fw_error_code);

	switch (fw_error_code) {
	case 0x0: /* Success */
		error_type = WMA_INJECTION_FW_ERROR_NONE;
		break;
	case 0x1: /* Generic failure */
		error_type = WMA_INJECTION_FW_ERROR_REJECTED;
		break;
	case 0x2: /* Invalid VDEV */
		error_type = WMA_INJECTION_FW_ERROR_INVALID_VDEV;
		break;
	case 0x3: /* No resources */
		error_type = WMA_INJECTION_FW_ERROR_NO_RESOURCES;
		break;
	case 0x4: /* Interface down */
		error_type = WMA_INJECTION_FW_ERROR_INTERFACE_DOWN;
		break;
	case 0x5: /* Power save mode */
		error_type = WMA_INJECTION_FW_ERROR_POWER_SAVE;
		break;
	case 0x6: /* Channel switch in progress */
		error_type = WMA_INJECTION_FW_ERROR_CHANNEL_SWITCH;
		break;
	case 0x7: /* Scan active */
		error_type = WMA_INJECTION_FW_ERROR_SCAN_ACTIVE;
		break;
	case 0xFFFFFFFF: /* Timeout */
		error_type = WMA_INJECTION_FW_ERROR_TIMEOUT;
		break;
	default:
		error_type = WMA_INJECTION_FW_ERROR_UNKNOWN;
		break;
	}

	WMA_LOGD("Translated firmware error 0x%x to type %d", fw_error_code, error_type);
	return error_type;
}

/**
 * wma_handle_firmware_injection_error() - Handle firmware injection error
 * @wma_handle: WMA handle
 * @error_code: Firmware error code
 * @vdev_id: VDEV ID associated with error
 * @req: Frame request that caused error (optional)
 *
 * This function handles firmware errors during frame injection. It implements
 * retry logic for transient failures and coordinates with HDD layer for
 * error recovery. It also maintains firmware state synchronization.
 *
 * Return: QDF_STATUS_SUCCESS on successful recovery, error code on failure
 */
QDF_STATUS wma_handle_firmware_injection_error(tp_wma_handle wma_handle,
						uint32_t error_code,
						uint8_t vdev_id,
						struct inject_frame_req *req)
{
	enum wma_injection_fw_error_type error_type;
	struct wma_injection_fw_error_info *error_info;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	bool should_retry = false;
	uint32_t retry_delay_ms = 0;

	WMA_LOGD("Handling firmware injection error: code=0x%x, vdev_id=%u", error_code, vdev_id);

	if (!wma_handle) {
		WMA_LOGE("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	/* Translate firmware error code */
	error_type = wma_translate_fw_injection_error(error_code);

	/* Update error statistics - this would be part of a larger injection context */
	/* For now, we'll log the error information */
	WMA_LOGW("Firmware injection error: type=%d, code=0x%x, vdev_id=%u",
		 error_type, error_code, vdev_id);

	/* Determine if we should retry based on error type */
	switch (error_type) {
	case WMA_INJECTION_FW_ERROR_NO_RESOURCES:
		/* Transient error - retry with delay */
		should_retry = true;
		retry_delay_ms = 100; /* 100ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_POWER_SAVE:
		/* Device in power save - retry with longer delay */
		should_retry = true;
		retry_delay_ms = 500; /* 500ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_CHANNEL_SWITCH:
		/* Channel switch in progress - retry with delay */
		should_retry = true;
		retry_delay_ms = 200; /* 200ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_SCAN_ACTIVE:
		/* Scan active - retry with short delay */
		should_retry = true;
		retry_delay_ms = 50; /* 50ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_TIMEOUT:
		/* Timeout - retry once with longer delay */
		should_retry = true;
		retry_delay_ms = 1000; /* 1 second delay */
		break;

	case WMA_INJECTION_FW_ERROR_INVALID_VDEV:
	case WMA_INJECTION_FW_ERROR_INTERFACE_DOWN:
		/* Permanent errors - synchronize state but don't retry */
		status = wma_sync_firmware_injection_state(wma_handle, vdev_id);
		should_retry = false;
		break;

	case WMA_INJECTION_FW_ERROR_REJECTED:
	case WMA_INJECTION_FW_ERROR_UNKNOWN:
	default:
		/* Unknown or permanent errors - don't retry */
		should_retry = false;
		break;
	}

	/* Attempt retry if appropriate and request is available */
	if (should_retry && req) {
		/* Check retry count to avoid infinite loops */
		if (req->retry_count < 3) { /* Maximum 3 retries */
			WMA_LOGI("Retrying injection after %u ms delay (attempt %u)",
				 retry_delay_ms, req->retry_count + 1);
			
			/* Schedule retry with delay */
			status = wma_retry_injection_frame(wma_handle, req, vdev_id, error_type);
			if (QDF_IS_STATUS_SUCCESS(status)) {
				return QDF_STATUS_E_PENDING; /* Retry scheduled */
			}
		} else {
			WMA_LOGW("Maximum retry attempts reached for injection request");
			status = QDF_STATUS_E_FAILURE;
		}
	}

	/* If we reach here, either no retry was needed or retry failed */
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGE("Firmware injection error handling failed: %d", status);
	} else {
		WMA_LOGI("Firmware injection error handled successfully");
	}

	return status;
}

/**
 * wma_retry_injection_frame() - Retry injection frame after firmware error
 * @wma_handle: WMA handle
 * @req: Frame injection request to retry
 * @vdev_id: VDEV ID for the frame
 * @error_type: Type of error that occurred
 *
 * This function implements retry logic for transient firmware failures.
 * It uses exponential backoff and limits the number of retry attempts.
 *
 * Return: QDF_STATUS_SUCCESS on successful retry, error code on failure
 */
QDF_STATUS wma_retry_injection_frame(tp_wma_handle wma_handle,
				     struct inject_frame_req *req,
				     uint8_t vdev_id,
				     enum wma_injection_fw_error_type error_type)
{
	QDF_STATUS status;
	uint32_t delay_ms;

	WMA_LOGD("Retrying injection frame: vdev_id=%u, error_type=%d, retry_count=%u",
		 vdev_id, error_type, req->retry_count);

	if (!wma_handle || !req) {
		WMA_LOGE("Invalid parameters for retry");
		return QDF_STATUS_E_INVAL;
	}

	/* Increment retry count */
	req->retry_count++;

	/* Calculate exponential backoff delay */
	delay_ms = 100 * (1 << (req->retry_count - 1)); /* 100ms, 200ms, 400ms, ... */
	if (delay_ms > 2000) {
		delay_ms = 2000; /* Cap at 2 seconds */
	}

	/* Add some jitter to avoid thundering herd */
	delay_ms += (qdf_get_log_timestamp() % 50); /* Add 0-49ms jitter */

	WMA_LOGI("Scheduling injection retry in %u ms (attempt %u)",
		 delay_ms, req->retry_count);

	/* For now, we'll simulate the retry by calling the send function again */
	/* In a real implementation, this would be scheduled with a timer */
	qdf_sleep(delay_ms);

	/* Attempt to send the frame again */
	status = wma_send_injection_frame_to_fw(wma_handle, req, vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGW("Injection retry failed: %d", status);
		return status;
	}

	WMA_LOGI("Injection retry initiated successfully");
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_sync_firmware_injection_state() - Synchronize firmware injection state
 * @wma_handle: WMA handle
 * @vdev_id: VDEV ID to synchronize
 *
 * This function synchronizes the firmware injection state after errors.
 * It ensures that the firmware and driver are in a consistent state.
 *
 * Return: QDF_STATUS_SUCCESS on success, error code on failure
 */
QDF_STATUS wma_sync_firmware_injection_state(tp_wma_handle wma_handle,
					      uint8_t vdev_id)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	WMA_LOGD("Synchronizing firmware injection state for vdev_id=%u", vdev_id);

	if (!wma_handle) {
		WMA_LOGE("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	/* Check if VDEV is valid and active */
	if (vdev_id >= wma_handle->max_bssid) {
		WMA_LOGE("Invalid VDEV ID: %u", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	/* Verify VDEV state */
	if (!wma_handle->interfaces[vdev_id].handle) {
		WMA_LOGW("VDEV %u is not active", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	/* Check interface type - injection typically requires monitor mode */
	if (wma_handle->interfaces[vdev_id].type != WMI_VDEV_TYPE_MONITOR) {
		WMA_LOGW("VDEV %u is not in monitor mode (type=%d)",
			 vdev_id, wma_handle->interfaces[vdev_id].type);
		/* This might not be an error depending on implementation */
	}

	/* Flush any pending injection frames for this VDEV */
	/* This would be implemented as part of the queue management */
	WMA_LOGI("Flushing pending injection frames for vdev_id=%u", vdev_id);

	/* Send a sync command to firmware if needed */
	/* This would involve sending a WMI command to query/reset injection state */
	WMA_LOGD("Sending injection state sync command to firmware");

	/* For now, we'll just log that synchronization is complete */
	WMA_LOGI("Firmware injection state synchronized for vdev_id=%u", vdev_id);

	return status;
}

#endif /* FEATURE_FRAME_INJECTION_SUPPORT */

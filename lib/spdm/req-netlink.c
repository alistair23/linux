// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Requester role: netlink interface
 *
 * Copyright (C) 2025 Intel Corporation
 */

#include "spdm.h"

int spdm_netlink_sig_event(struct spdm_state *spdm_state,
			   enum spdm_reqrsp_code rsp_code, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off,
			   const char *spdm_context)
{
	unsigned int seq, msg_sz, nr_msgs, nr_pages, nr_frags;
	struct sk_buff *msg;
	struct nlattr *nla;
	void *hdr, *ptr;
	int rc, i;

	if (!genl_has_listeners(&spdm_nl_family, &init_net, SPDM_NLGRP_SIG))
		return 0;

	char *devpath __free(kfree) = kobject_get_path(&spdm_state->dev->kobj,
						       GFP_KERNEL);
	if (!devpath)
		return -ENOMEM;

	nr_pages = spdm_state->transcript_max / PAGE_SIZE;
	nr_msgs = DIV_ROUND_UP(nr_pages, MAX_SKB_FRAGS);

	/* Calculate exact size to avoid reallocation by netlink_trim() */
	msg_sz = nlmsg_total_size(genlmsg_msg_size(
			nla_total_size(strlen(devpath)) +
			nla_total_size(sizeof(u8)) +
			nla_total_size(sizeof(u8)) +
			nla_total_size(sizeof(u16)) +
			nla_total_size(sizeof(u32)) +
			nla_total_size(sizeof(u32)) +
			nla_total_size(sizeof(u32)) +
			nla_total_size(SPDM_COMBINED_PREFIX_SZ) +
			nla_total_size(0)));

	msg = genlmsg_new(msg_sz, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &spdm_nl_family,
			  nr_msgs > 1 ? NLM_F_MULTI : 0, SPDM_CMD_SIG);
	if (!hdr) {
		rc = -EMSGSIZE;
		goto err_free_msg;
	}

	if (nla_put_string(msg, SPDM_A_SIG_DEVICE, devpath) ||
	    nla_put_u8(msg, SPDM_A_SIG_RSP_CODE, rsp_code) ||
	    nla_put_u8(msg, SPDM_A_SIG_SLOT, slot) ||
	    nla_put_u16(msg, SPDM_A_SIG_HASH_ALGO,
			spdm_state->base_hash_alg) ||
	    nla_put_u32(msg, SPDM_A_SIG_SIG_OFFSET,
			spdm_state->transcript_end - spdm_state->transcript -
		        spdm_state->sig_len) ||
	    nla_put_u32(msg, SPDM_A_SIG_REQ_NONCE_OFFSET, req_nonce_off) ||
	    nla_put_u32(msg, SPDM_A_SIG_RSP_NONCE_OFFSET, rsp_nonce_off)) {
		rc = -EMSGSIZE;
		goto err_cancel_msg;
	}

	if (spdm_state->version >= 0x12) {
		nla = nla_reserve(msg, SPDM_A_SIG_COMBINED_SPDM_PREFIX,
				  SPDM_COMBINED_PREFIX_SZ);
		if (!nla) {
			rc = -EMSGSIZE;
			goto err_cancel_msg;
		}

		spdm_create_combined_prefix(spdm_state->version, spdm_context,
					    nla_data(nla));
	}

	ptr = spdm_state->transcript;

	/* Loop over Netlink messages - break condition is in loop body */
	for (seq = 1; ; seq++) {
		nla = nla_reserve(msg, SPDM_A_SIG_TRANSCRIPT, 0);
		if (!nla) {
			rc = -EMSGSIZE;
			goto err_cancel_msg;
		}

		nr_frags = min(nr_pages, MAX_SKB_FRAGS);
		nla->nla_len = nr_frags * PAGE_SIZE;
		nr_pages -= nr_frags;

		/* Loop over fragments of this Netlink message */
		for (i = 0; i < nr_frags; i++) {
			struct page *page = vmalloc_to_page(ptr);
			size_t remainder = spdm_state->transcript_end - ptr;
			size_t sz = min(remainder, PAGE_SIZE);

			get_page(page);
			skb_add_rx_frag(msg, i, page, 0, sz, sz);
			ptr += PAGE_SIZE;
		}

		genlmsg_end(msg, hdr);
		rc = genlmsg_multicast(&spdm_nl_family, msg, 0,
				       SPDM_NLGRP_SIG, GFP_KERNEL);
		if (rc)
			return rc;

		if (nr_pages == 0) /* End of loop - entire transcript sent */
			break;

		/* Start new message for remainder of transcript */
		msg_sz = nlmsg_total_size(genlmsg_msg_size(nla_total_size(0)));

		msg = genlmsg_new(msg_sz, GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		hdr = genlmsg_put(msg, 0, seq, &spdm_nl_family,
				  NLM_F_MULTI, SPDM_CMD_SIG);
		if (!hdr) {
			rc = -EMSGSIZE;
			goto err_free_msg;
		}
	}

	return 0;

err_cancel_msg:
	nlmsg_cancel(msg, hdr);
err_free_msg:
	nlmsg_free(msg);
	return rc;
}

static int __init spdm_netlink_init(void)
{
	return genl_register_family(&spdm_nl_family);
}

static void __exit spdm_netlink_exit(void)
{
	genl_unregister_family(&spdm_nl_family);
}

arch_initcall(spdm_netlink_init);
module_exit(spdm_netlink_exit);

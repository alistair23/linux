/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-25 Intel Corporation
 */

#ifndef _LIB_SPDM_H_
#define _LIB_SPDM_H_

#include <uapi/linux/hash_info.h>

#define SPDM_SLOTS 8 /* SPDM 1.0.0 section 4.9.2.1 */

struct spdm_artifacts
{
	/* Negotiated state */
	u8 version;
	enum hash_algo base_hash_alg;
	u32 base_asym_alg;
	u8 provisioned_slots;

	/* Signature algorithm */
	const char *base_asym_enc;
	size_t sig_len;

	/* Transcript */
	const void *transcript;
	size_t transcript_len;

	/* Certificates */
	const void *cert_chain[SPDM_SLOTS];
	size_t cert_chain_len[SPDM_SLOTS];
	struct public_key *leaf_key;
};

#ifdef CONFIG_NET
int spdm_netlink_sig_event(struct device *dev,
			   struct spdm_artifacts artifacts,
			   int rsp_code, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off,
			   const char *spdm_context);
#else
static inline int spdm_netlink_sig_event(struct device *dev,
			   struct spdm_artifacts artifacts,
			   int rsp_code, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off,
			   const char *spdm_context) { return 0; }
#endif

int spdm_chall(struct spdm_state *spdm_state);

#endif /* _LIB_SPDM_H_ */

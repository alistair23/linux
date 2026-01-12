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

#ifdef CONFIG_NET
int spdm_netlink_sig_event(struct device *dev,
			   u8 version,
			   void *transcript,
			   size_t transcript_len,
			   enum hash_algo base_hash_alg,
			   size_t sig_len,
			   int rsp_code, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off,
			   const char *spdm_context);
#else
static inline int spdm_netlink_sig_event(struct device *dev,
			   u8 version,
			   void *transcript,
			   size_t transcript_len,
			   enum hash_algo base_hash_alg,
			   size_t sig_len,
			   int rsp_code, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off,
			   const char *spdm_context) { return 0; }
#endif

#endif /* _LIB_SPDM_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#ifndef _SPDM_H_
#define _SPDM_H_

#include <linux/types.h>

struct key;
struct device;
struct spdm_state;
struct x509_certificate;

typedef int (spdm_transport)(void *priv, struct device *dev,
			     const void *request, size_t request_sz,
			     void *response, size_t response_sz);

typedef int (spdm_validate)(struct device *dev, u8 slot,
			    struct x509_certificate *leaf_cert);

/**
 * spdm_create() - Allocate SPDM session
 * @dev: Responder device. Used for error reporting and passed to @transport.
 * @transport: Transport function to perform one message exchange.
 * @transport_priv: Transport function private data.
 * @transport_sz: Maximum message size the transport is capable of
 *	(in bytes).
 * @validate: Function to validate additional leaf certificate requirements
 *	(optional, may be %NULL).
 *
 * Return a pointer to the allocated SPDM session state or NULL on error.
 * The returned session must be freed with spdm_destroy().
 */
struct spdm_state *spdm_create(struct device *dev, spdm_transport *transport,
			       void *transport_priv, u32 transport_sz,
			       spdm_validate *validate);

/**
 * spdm_authenticate() - Authenticate device
 * @spdm_state: SPDM session state
 *
 * Authenticate a device through a sequence of GET_VERSION, GET_CAPABILITIES,
 * NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE and CHALLENGE exchanges.
 *
 * Return 0 on success or a negative errno. In particular, -EPROTONOSUPPORT
 * indicates authentication is not supported by the device.
 */
int spdm_authenticate(struct spdm_state *spdm_state);

/**
 * spdm_destroy() - Destroy SPDM session
 * @spdm_state: SPDM session state
 *
 * Free a session allocated by spdm_create().
 */
void spdm_destroy(struct spdm_state *spdm_state);

#endif

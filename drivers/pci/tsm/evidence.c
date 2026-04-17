// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Intel Corporation */

#include <crypto/hash_info.h>
#include <linux/bitfield.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/pci.h>
#include <linux/pci-tsm.h>
#include <linux/slab.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "netlink.h"

struct pci_tsm_evidence_ctx {
	struct pci_dev *pdev;
	unsigned long type_mask;
	unsigned long flags;
	void *nonce;
	int generation;
	int type;
	u32 offset;
	u16 nonce_len;
};

#define PCI_TSM_EVIDENCE_START U32_MAX
#define PCI_TSM_EVIDENCE_OBJECT_START (U32_MAX - 1)
int pci_tsm_nl_evidence_read_pre(struct netlink_callback *cb)
{
	struct pci_tsm_evidence_ctx *ctx = (struct pci_tsm_evidence_ctx *)cb->ctx;
	const struct genl_info *info = genl_info_dump(cb);
	unsigned long type_mask_unknown;
	struct nlattr *attr;
	struct device *dev;
	char name[32];

	NL_ASSERT_CTX_FITS(struct pci_tsm_evidence_ctx);

	if (GENL_REQ_ATTR_CHECK(info, PCI_TSM_A_EVIDENCE_OBJECT_TYPE_MASK)) {
		NL_SET_ERR_MSG(info->extack, "missing object request mask");
		return -EINVAL;
	}

	attr = info->attrs[PCI_TSM_A_EVIDENCE_OBJECT_TYPE_MASK];
	ctx->type_mask = nla_get_u32(attr);
	type_mask_unknown = ctx->type_mask & ~PCI_TSM_EVIDENCE_TYPE_FLAG_MASK;
	if (type_mask_unknown) {
		NL_SET_ERR_MSG_FMT(info->extack,
				   "unsupported object request %#lx",
				   type_mask_unknown);
		return -EINVAL;
	}

	attr = info->attrs[PCI_TSM_A_EVIDENCE_OBJECT_FLAGS];
	if (attr) {
		ctx->flags = nla_get_u32(attr);
		if (ctx->flags & ~PCI_TSM_EVIDENCE_FLAG_MASK) {
			NL_SET_BAD_ATTR(info->extack, attr);
			return -EINVAL;
		}
	}

	if (GENL_REQ_ATTR_CHECK(info, PCI_TSM_A_EVIDENCE_OBJECT_DEV_NAME)) {
		NL_SET_ERR_MSG(info->extack, "missing device name");
		return -EINVAL;
	}

	attr = info->attrs[PCI_TSM_A_EVIDENCE_OBJECT_DEV_NAME];
	if (nla_strscpy(name, attr, sizeof(name)) < 0) {
		NL_SET_BAD_ATTR(info->extack, attr);
		return -EINVAL;
	}

	dev = bus_find_device_by_name(&pci_bus_type, NULL, name);
	if (!dev) {
		NL_SET_ERR_MSG_FMT(info->extack, "device '%s' not found", name);
		return -ENODEV;
	}
	ctx->pdev = to_pci_dev(dev);

	ctx->type =
		find_first_bit(&ctx->type_mask, PCI_TSM_EVIDENCE_TYPE_MAX + 1);
	if (ctx->type > PCI_TSM_EVIDENCE_TYPE_MAX) {
		NL_SET_ERR_MSG(info->extack, "no evidence type requested");
		return -EINVAL;
	}
	ctx->offset = PCI_TSM_EVIDENCE_START;

	return 0;
}

int pci_tsm_nl_evidence_read_post(struct netlink_callback *cb)
{
	struct pci_tsm_evidence_ctx *ctx =
		(struct pci_tsm_evidence_ctx *)cb->ctx;

	pci_dev_put(ctx->pdev);
	return 0;
}

static size_t evidence_len(struct pci_tsm_evidence *evidence,
			   struct pci_tsm_evidence_object *obj,
			   unsigned long flags)
{
	if (flags & PCI_TSM_EVIDENCE_FLAG_DIGEST) {
		if (obj->digest)
			return hash_digest_size[evidence->digest_algo];
		return 0;
	}
	return obj->len;
}

static void *evidence_data(struct pci_tsm_evidence_object *obj,
			   unsigned long flags)
{
	if (flags & PCI_TSM_EVIDENCE_FLAG_DIGEST)
		return obj->digest;
	return obj->data;
}

static int __pci_tsm_evidence_read(struct sk_buff *skb,
				   struct netlink_callback *cb)
{
	struct pci_tsm_evidence_ctx *ctx =
		(struct pci_tsm_evidence_ctx *)cb->ctx;
	struct pci_dev *pdev = ctx->pdev;
	struct pci_tsm_evidence *evidence = &pdev->tsm->evidence;
	struct pci_tsm_evidence_object *obj = &evidence->obj[ctx->type];
	size_t object_len = evidence_len(evidence, obj, ctx->flags);
	void *object_data = evidence_data(obj, ctx->flags);
	size_t available, overhead, len;
	void *hdr;
	int rc;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &pci_tsm_nl_family, NLM_F_MULTI,
			  PCI_TSM_CMD_EVIDENCE_READ);
	if (!hdr)
		return -EMSGSIZE;

	if (ctx->offset == PCI_TSM_EVIDENCE_OBJECT_START) {
		rc = nla_put_u32(skb, PCI_TSM_A_EVIDENCE_OBJECT_TYPE,
				 ctx->type);
		if (rc)
			goto out_cancel;
		ctx->offset = 0;
	}

	available = skb_tailroom(skb);
	overhead = nla_total_size(0) + NLA_ALIGNTO;
	if (available <= overhead) {
		rc = -EMSGSIZE;
		goto out_cancel;
	}

	if (object_len)
		len = min(available - overhead, object_len - ctx->offset);
	else
		len = 0;

	rc = nla_put(skb, PCI_TSM_A_EVIDENCE_OBJECT_VAL, len,
		     object_data + ctx->offset);
	if (rc)
		goto out_end;

	ctx->offset += len;
	if (ctx->offset < object_len) {
		rc = 1;
		goto out_end;
	}

	ctx->type = find_next_bit(&ctx->type_mask,
				  PCI_TSM_EVIDENCE_TYPE_MAX + 1, ctx->type + 1);
	/* no more evidence types requested */
	if (ctx->type > PCI_TSM_EVIDENCE_TYPE_MAX) {
		rc = 0;
		goto out_end;
	}
	ctx->offset = PCI_TSM_EVIDENCE_OBJECT_START;
	rc = 1;

out_end:
	genlmsg_end(skb, hdr);
	if (rc > 0)
		return skb->len;
	return rc;

out_cancel:
	genlmsg_cancel(skb, hdr);
	return rc;
}

static int pci_tsm_evidence_read(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	struct pci_tsm_evidence_ctx *ctx =
		(struct pci_tsm_evidence_ctx *)cb->ctx;
	const struct genl_info *info = genl_info_dump(cb);
	struct pci_tsm_evidence *evidence;
	struct pci_dev *pdev = ctx->pdev;
	int rc;

	ACQUIRE(rwsem_read_intr, tsm_lock)(&pci_tsm_rwsem);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &tsm_lock))) {
		NL_SET_ERR_MSG(info->extack,
			       "interrupted acquiring TSM context");
		return rc;
	}

	if (!pdev->tsm) {
		NL_SET_ERR_MSG(info->extack, "no TSM context");
		return -ENXIO;
	}

	evidence = &pdev->tsm->evidence;
	ACQUIRE(rwsem_read_intr, evidence_lock)(&evidence->lock);
	if ((rc = ACQUIRE_ERR(rwsem_read_intr, &evidence_lock))) {
		NL_SET_ERR_MSG(info->extack, "interrupted acquiring evidence");
		return rc;
	}

	/* generation is only valid when non-zero */
	if (ctx->offset == PCI_TSM_EVIDENCE_START) {
		if (!evidence->generation) {
			NL_SET_ERR_MSG(info->extack, "no evidence available");
			return -ENXIO;
		}
		ctx->generation = evidence->generation;
		ctx->offset = PCI_TSM_EVIDENCE_OBJECT_START;
	}

	if (ctx->generation != evidence->generation) {
		NL_SET_ERR_MSG(info->extack, "evidence updated during read");
		return -EAGAIN;
	}

	return __pci_tsm_evidence_read(skb, cb);
}

static int pci_tsm_evidence_refresh(struct pci_tsm_evidence_ctx *ctx)
{
	return -EOPNOTSUPP;
}

int pci_tsm_nl_evidence_read_dumpit(struct sk_buff *skb,
				    struct netlink_callback *cb)
{
	struct pci_tsm_evidence_ctx *ctx =
		(struct pci_tsm_evidence_ctx *)cb->ctx;
	const struct genl_info *info = genl_info_dump(cb);

	/* Attempt one refresh per dump request before reading */
	if (ctx->offset == PCI_TSM_EVIDENCE_START && ctx->nonce) {
		int rc = pci_tsm_evidence_refresh(ctx);

		if (rc) {
			NL_SET_ERR_MSG_FMT(info->extack,
					   "evidence refresh failed: %d", rc);
			return rc;
		}
		ctx->nonce = NULL;
	}
	return pci_tsm_evidence_read(skb, cb);
}

static int __init pci_tsm_nl_init(void)
{
	return genl_register_family(&pci_tsm_nl_family);
}

subsys_initcall(pci_tsm_nl_init);

// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/pci-tsm.yaml */
/* YNL-GEN kernel source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "netlink.h"

#include <uapi/linux/pci-tsm-netlink.h>

/* PCI_TSM_CMD_EVIDENCE_READ - dump */
static const struct nla_policy pci_tsm_evidence_read_nl_policy[PCI_TSM_A_EVIDENCE_OBJECT_NONCE + 1] = {
	[PCI_TSM_A_EVIDENCE_OBJECT_TYPE_MASK] = { .type = NLA_U32, },
	[PCI_TSM_A_EVIDENCE_OBJECT_FLAGS] = { .type = NLA_U32, },
	[PCI_TSM_A_EVIDENCE_OBJECT_DEV_NAME] = { .type = NLA_NUL_STRING, },
	[PCI_TSM_A_EVIDENCE_OBJECT_NONCE] = NLA_POLICY_MAX_LEN(PCI_TSM_MAX_NONCE_SIZE),
};

/* Ops table for pci_tsm */
static const struct genl_split_ops pci_tsm_nl_ops[] = {
	{
		.cmd		= PCI_TSM_CMD_EVIDENCE_READ,
		.start		= pci_tsm_nl_evidence_read_pre,
		.dumpit		= pci_tsm_nl_evidence_read_dumpit,
		.done		= pci_tsm_nl_evidence_read_post,
		.policy		= pci_tsm_evidence_read_nl_policy,
		.maxattr	= PCI_TSM_A_EVIDENCE_OBJECT_NONCE,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DUMP,
	},
};

struct genl_family pci_tsm_nl_family __ro_after_init = {
	.name		= PCI_TSM_FAMILY_NAME,
	.version	= PCI_TSM_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= pci_tsm_nl_ops,
	.n_split_ops	= ARRAY_SIZE(pci_tsm_nl_ops),
};

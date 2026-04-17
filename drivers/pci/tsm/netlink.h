/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/pci-tsm.yaml */
/* YNL-GEN kernel header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_PCI_TSM_GEN_H
#define _LINUX_PCI_TSM_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/pci-tsm-netlink.h>

int pci_tsm_nl_evidence_read_pre(struct netlink_callback *cb);
int pci_tsm_nl_evidence_read_post(struct netlink_callback *cb);

int pci_tsm_nl_evidence_read_dumpit(struct sk_buff *skb,
				    struct netlink_callback *cb);

extern struct genl_family pci_tsm_nl_family;

#endif /* _LINUX_PCI_TSM_GEN_H */

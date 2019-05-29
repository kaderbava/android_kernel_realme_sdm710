/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015 Cumulus Networks, Inc.
 */

#ifndef _NET_MPLS_IPTUNNEL_H
#define _NET_MPLS_IPTUNNEL_H 1

#define MAX_NEW_LABELS 2

struct mpls_iptunnel_encap {
	u32	label[MAX_NEW_LABELS];
	u8	labels;
};

static inline struct mpls_iptunnel_encap *mpls_lwtunnel_encap(struct lwtunnel_state *lwtstate)
{
	return (struct mpls_iptunnel_encap *)lwtstate->data;
}

#endif

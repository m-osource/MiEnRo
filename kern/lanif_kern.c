// SPDX-License-Identifier: GPL-2.0
/***************************************************************************
 *          (C) Copyright 2023 - Marco Giuseppe Spiga                      *
 ***************************************************************************
 *                                                                         *
 *  This file is part of MInimal ENterprise ROuter.                        *
 *                                                                         *
 *  MIENRO is free software: you can redistribute it and/or modify         *
 *  it under the terms of the GNU General Public License as published by   *
 *  the Free Software Foundation, either version 2 of the License, or      *
 *  any later version.                                                     *
 *                                                                         *
 *  MIENRO is distributed in the hope that it will be useful,              *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *  GNU General Public License for more details.                           *
 *                                                                         *
 *  You should have received a copy of the GNU General Public License      *
 *  along with this software. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 **************************************************************************/

/***************************************************************************
 *  Warning:
 *  This source file is divided in two key section:
 *  BPF_FIB_LKUP_RET_NOT_FWDED -> THE INPUT_SECTION
 *  BPF_FIB_LKUP_RET_SUCCESS   -> THE FORWARD_SECTION
 *
 *  Sometime data packets can also handled from FORWARD_SECTION to
 *  INPUT_SECTION (eg. icmp reply in place of the devices to be protected)
 *  and vice versa (eg. dstnat)
 * ************************************************************************/

#define KBUILD_MODNAME "lanforwarder"
#include "common_kern.h"

// TODO testing variables using when forwarding data
static volatile __u64 start_time = 0; // bpf_printk("Cur_time %lu, start_time %lu", bpf_ktime_get_ns() - cur_time, start_time / NANOSEC_PER_SEC); // TODO
static volatile __u32 core_id = 0;
static volatile txports_t TxPorts = { 0, 0, 0, 0 };
static volatile amasks_t AMasks = { 0, 0, 0, 0 };
static volatile in4_addr UnTrustedV4[UNTRUSTED_MAX];
static volatile struct in6_addr UnTrustedV6[UNTRUSTED_MAX];
static volatile struct bpf_fib_lookup fib_params_urpf4, fib_params_urpf6;

struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} xdp_lan_tx_ports SEC(".maps");

static __always_inline void init_variables(void);

static __always_inline int mienro_process_packet(struct xdp_md *ctx, u32 flags)
{
    const __u32 ifingress = ctx->ingress_ifindex;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct bpf_fib_lookup fib_params;
#ifdef TRUNK_PORT
    struct vlan_ethhdr *l2hdr = data;
#else
    struct ethhdr *l2hdr = data;
#endif
    struct ipv6hdr *ip6h = NULL;
    struct iphdr *iph = NULL;
    u16 h_proto;
    u64 nh_off;
    int rc;

    /*
    * Only for debugging
    *
    __u32 coreid = 0;
    if ((coreid = bpf_get_smp_processor_id()) != core_id)
    {
            bpf_printk("for lan core changed from %u to %u", core_id, coreid);
            core_id = coreid;
    } */

    nh_off = L2_HLEN;

#ifdef TRUNK_PORT // Bridged VLAN.
    if (data + nh_off > data_end || // __com001
        unlikely(ntohs(l2hdr->h_vlan_proto) < ETH_P_802_3_MIN)) // Skip non 802.3 Ethertypes
    {
        __u32 key = 0;
        update_stats(bpf_map_lookup_elem(&fail_cnt, &key), (ctx->data_end - ctx->data));

        return XDP_DROP;
    }

    h_proto = l2hdr->h_vlan_proto;

    if (h_proto == htons(ETH_P_8021Q))
    { // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
        if (TxPorts.wan == 0)
            init_variables();

        nh_off = L2_HLEN;

        if (data + nh_off > data_end)
        {
            __u32 key = 0;
            update_stats(bpf_map_lookup_elem(&fail_cnt, &key), (ctx->data_end - ctx->data));

            return XDP_DROP;
        }

        __u16 vlan = (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK);

        xdp_stats_t *stats = bpf_map_lookup_elem(&brvlan_wl, &vlan);

        if (stats && bpf_redirect_map(&xdp_lan_tx_ports, TxPorts.wan, 0) == XDP_REDIRECT)
        {
            stats->packets++;
            stats->bytes += (ctx->data_end - ctx->data);

            return XDP_REDIRECT;
        }

        h_proto = l2hdr->h_vlan_encapsulated_proto;
    }
    else
        return XDP_ABORTED;
#else
    if (data + nh_off > data_end || // __com001
        unlikely(ntohs(l2hdr->h_proto) < ETH_P_802_3_MIN)) // Skip non 802.3 Ethertypes
    {
        __u32 key = 0;
        update_stats(bpf_map_lookup_elem(&fail_cnt, &key), (ctx->data_end - ctx->data));

        return XDP_DROP;
    }

    h_proto = l2hdr->h_proto;
#endif
    if (h_proto == htons(ETH_P_IP))
    {
        iph = data + nh_off;

        if (iph + 1 > data_end || sizeof(*iph) != (iph->ihl * 4))
            MXDP_V4DROP
#ifdef STRICT
        if (update_stats(bpf_map_lookup_elem(&ddos_v4bl, &iph->saddr), (ctx->data_end - ctx->data)) == true) // __com010
            return XDP_DROP;
#endif
        //		if (iph->ttl <= 1) // handle in other sections
        //			return XDP_PASS;

        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
#ifndef TRUNK_PORT
#ifdef STRICT
        fib_params.ipv4_dst = iph->saddr;

        if (check_urpf(ctx, &fib_params, flags, ifingress) == true)
            MXDP_V4DROP
#endif
#endif
        fib_params.ipv4_dst = iph->daddr;
        fib_params.h_vlan_proto = 0;
        fib_params.h_vlan_TCI = 0;

        // bpf_printk("LAN IF: source %pI4 dest %pI4", &iph->saddr, &iph->daddr); // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
    }
    else if (h_proto == htons(ETH_P_IPV6))
    {
        ip6h = data + nh_off;

        if (ip6h + 1 > data_end)
            MXDP_V6DROP

            // block all traffic forwarded from local addresses because it can arrive from lan of nas if configured as private (fc00::/7 - RFC 1918)
            // NOT used because with IPv6 the block occurs later
            //	if ((ip6h->saddr.s6_addr[0] & 0xFE) == 0xFC)
            //		MXDP_V6DROP
#ifdef STRICT
        if (update_stats(bpf_map_lookup_elem(&ddos_v6bl, &ip6h->saddr), (ctx->data_end - ctx->data)) == true) // __com010
            return XDP_DROP;
#endif
        //		if (ip6h->hop_limit <= 1) // handle in other sections
        //			return XDP_PASS;

        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.family = AF_INET6;
        fib_params.flowinfo = *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol = ip6h->nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = ntohs(ip6h->payload_len);
        *((struct in6_addr *)fib_params.ipv6_src) = ip6h->saddr;
#ifndef TRUNK_PORT
#ifdef STRICT
        *((struct in6_addr *)fib_params.ipv6_dst) = ip6h->saddr;

        if (check_urpf(ctx, &fib_params, flags, ifingress) == true)
            MXDP_V6DROP
#endif
#endif
        *((struct in6_addr *)fib_params.ipv6_dst) = ip6h->daddr;
        fib_params.h_vlan_proto = 0;
        fib_params.h_vlan_TCI = 0;

        // bpf_printk("LAN IF: source %pI6 dest %pI6", &ip6h->saddr, &ip6h->daddr); // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
    }
    else if (h_proto == htons(ETH_P_ARP))
        return XDP_PASS; // __com004
    else if (h_proto == htons(ETH_P_RARP))
        return XDP_PASS; // __com004
    else
        return XDP_DROP;

    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
    //
    // Some rc (return codes) from bpf_fib_lookup() are important,
    // to understand how this XDP-prog interacts with network stack.
    //
    // BPF_FIB_LKUP_RET_NO_NEIGH:
    //  Even if route lookup was a success, then the MAC-addresses are also
    //  needed.  This is obtained from arp/neighbour table, but if table is
    //  (still) empty then BPF_FIB_LKUP_RET_NO_NEIGH is returned.  To avoid
    //  doing ARP lookup directly from XDP, then send packet to normal
    //  network stack via XDP_PASS and expect it will do ARP resolution.
    //
    // BPF_FIB_LKUP_RET_FWD_DISABLED:
    //  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
    //  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
    //  enabled this on ingress device.
    //
    if (rc == BPF_FIB_LKUP_RET_FWD_DISABLED)
        return XDP_DROP;
    else if (rc == BPF_FIB_LKUP_RET_SUCCESS) // FORWARD_SECTION
    {
        if (h_proto == htons(ETH_P_IP))
        {
            // Verify egress index has been configured as TX-port.
            //
            // (Note: User can still have inserted an egress ifindex that
            // doesn't support XDP xmit, which will result in packet drops).
            //
            // Note: lookup in devmap supported since 0cdbb4b09a0.
            // If not supported will fail with:
            //  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
            //
            //	if (! bpf_map_lookup_elem(&xdp_lan_tx_ports, &fib_params.ifindex))
            //		MXDP_V4DROP

            // skip icmp reply for time exceeded because Miero simulates single-stage route therefore, it don't decrease ttl when forward packet from lan
            //			if (iph->ttl < 2)
            //				return sendV4icmp(ctx, (in4_addr *)&UnTrustedV4[UNTRUSTED_TO_LOP], ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0); // to use only when packet forwarding

            // nas's private services work only in ipv6 protocol and there is not need of protection with acl
#ifdef TRUNK_PORT
            if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
            else
#else
            if (fib_params.ifindex == TxPorts.wan)
#endif
            {
#ifdef TRUNK_PORT // and mienromonnet up
                if (fib_params.ifindex == TxPorts.wan_xdp)
                    MXDP_V4DROP
                else
                {
                    ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                    if (ifinfo && ifinfo->xdp_idx == TxPorts.wan_xdp)
                    {
                        fib_params.ifindex = ifinfo->xdp_idx;
                        __u32 in_vlanid = (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK);
                        l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
#ifdef STRICT
                        fib_params_urpf4.ipv4_dst = iph->saddr;

                        if (check_urpf(ctx, (void *)&fib_params_urpf4, flags, ifingress, &in_vlanid) == true)
                            MXDP_V4DROP
#endif
                    }
                    else
                        MXDP_V4DROP
                }
#endif
                if (iph->protocol == IPPROTO_ICMP)
                {
                    struct icmphdr *icmph = data + L2_HLEN + sizeof(*iph);

                    if (icmph + 1 > data_end)
                        MXDP_V4DROP

                    // nat only if source address is in the same network of lan interface
                    if (((icmph->type == ICMP_DEST_UNREACH && icmph->code == ICMP_HOST_UNREACH) || (icmph->type == ICMP_TIME_EXCEEDED && icmph->code == ICMP_EXC_TTL)) && netV4cmp((in4_addr *)&UnTrustedV4[UNTRUSTED_TO_LAN], &iph->saddr, ntohs(AMasks.lan)) == true)
                    {
                        struct iphdr *enc_iph = NULL; // enclosed on icmp message

                        enc_iph = data + ETH_HLEN + sizeof(*iph) + sizeof(*icmph);

                        if (enc_iph + 1 > data_end)
                            MXDP_V4DROP

                        __s32 msgroom = (__s32)sizeof(*enc_iph);

                        switch (enc_iph->protocol)
                        {
                        case IPPROTO_ICMP:
                            msgroom += (__s32)sizeof(struct icmphdr);
                            break;
                        case IPPROTO_TCP:
                            msgroom += (__s32)sizeof(struct tcphdr);
                            break;
                        case IPPROTO_UDP:
                            msgroom += (__s32)sizeof(struct udphdr);
                            break;
                        default:
                            MXDP_V4DROP
                        }

                        // leave only protocol headers like openbsd for ipv4 protocol, before forward mikrotik nas icmp diagnostic messages
                        if ((data_end - data) > (L2_HLEN + sizeof(*iph) + sizeof(*icmph) + msgroom))
                        {
                            struct icmphdr *icmph = NULL;
                            __sum16 csum = 0;
                            __u32 _csum = 0;

                            if (bpf_xdp_adjust_tail(ctx, 0 - ((data_end - data) - (ETH_HLEN + sizeof(*iph) + sizeof(*icmph) + msgroom))))
                                MXDP_V4DROP

                            data = (void *)(long)ctx->data;
                            data_end = (void *)(long)ctx->data_end;

                            l2hdr = data;

                            // __com001
                            if (l2hdr + 1 > data_end)
                                return XDP_DROP;

#ifdef TRUNK_PORT
                            if (l2hdr->h_vlan_encapsulated_proto == htons(ETH_P_IP))
#else
                            if (l2hdr->h_proto == htons(ETH_P_IP))
#endif
                            {
                                iph = data + L2_HLEN;

                                if (iph + 1 > data_end || sizeof(*iph) != (iph->ihl * 4))
                                    MXDP_V4DROP
                            }
                            else
                                MXDP_V4DROP

                            iph->tos = 0;
                            iph->ttl = MIPDEFTTL;
                            iph->tot_len = htons((data_end - data) - ETH_HLEN);

                            iph->saddr = UnTrustedV4[SNAT_TO_LOP];

                            iph->check = 0;
                            ipv4_csum(iph, sizeof(struct iphdr), &_csum);
                            iph->check = (__sum16)~_csum;

                            icmph = data + L2_HLEN + sizeof(*iph);

                            if (icmph + 1 > data_end)
                                MXDP_V4DROP

                            icmph->checksum = 0; // check sum must be always reset before recalculate it
                            icmph->un.gateway = 0;

                            csum = icmpV4csum((void *)icmph, data_end, (ntohs(iph->tot_len) - sizeof(*iph)));

                            if (csum == 0)
                                MXDP_V4DROP

                            icmph->checksum = csum;
                        }
                        else
                        {
                            csumV4nat(&iph->check, &iph->saddr, (in4_addr *)&UnTrustedV4[SNAT_TO_LOP]);
                            iph->saddr = UnTrustedV4[SNAT_TO_LOP];
                        }

                        fib_params.ipv4_src = iph->saddr;

                        memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
                        memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

                        if (bpf_redirect_map(&xdp_lan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                            MXDP_V4REDIRECT
                        else
                            MXDP_V4ABORTED
                    }
                }

                // block all traffic forwarded from local addresses because if packet is arrived here, potentially our devices can reach internet (172.16.0.0/12 - RFC 1918)
                if ((iph->saddr & 0x0000F0FF) == 0x000010AC)
                    MXDP_V4DROP

                memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
                memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

                if (bpf_redirect_map(&xdp_lan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                    MXDP_V4REDIRECT
                else
                    MXDP_V4ABORTED
            }
#ifndef TRUNK_PORT
            else if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
#endif

            MXDP_V4DROP
        }
        else if (h_proto == htons(ETH_P_IPV6))
        {
            // Verify egress index has been configured as TX-port.
            //
            // (Note: User can still have inserted an egress ifindex that
            // doesn't support XDP xmit, which will result in packet drops).
            //
            // Note: lookup in devmap supported since 0cdbb4b09a0.
            // If not supported will fail with:
            //  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
            //
            //	if (! bpf_map_lookup_elem(&xdp_lan_tx_ports, &fib_params.ifindex))
            //		MXDP_V6DROP

            // skip icmp reply for time exceeded because Miero simulates single-stage route therefore, it don't decrease ttl when forward packet from lan
            //			if (ip6h->hop_limit < 2)
            //				return sendV6icmp(ctx, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP], ICMPV6_TIME_EXCEED, ICMPV6_EXC_HOPLIMIT, 0); // to use only when packet forwarding

            xdp_stats_t *stats = NULL;
            // clang-format off
                                                             /*************
                                                             *FIREWALL ACL*
                                                             *************/
// clang-format on
#ifdef TRUNK_PORT
            if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
            else
#else
            if (fib_params.ifindex == TxPorts.wan)
#endif
            {
#ifdef TRUNK_PORT // and mienromonnet up
                if (fib_params.ifindex == TxPorts.wan_xdp)
                    MXDP_V6DROP
                else
                {
                    ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                    if (ifinfo && ifinfo->xdp_idx == TxPorts.wan_xdp)
                    {
                        fib_params.ifindex = ifinfo->xdp_idx;
                        __u32 in_vlanid = (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK);
                        l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
#ifdef STRICT
                        *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                        if (check_urpf(ctx, (void *)&fib_params_urpf6, flags, ifingress, &in_vlanid) == true)
                            MXDP_V6DROP
#endif
                    }
                    else
                        MXDP_V6DROP
                }
#endif
                if (ip6h->nexthdr == IPPROTO_ICMPV6)
                {
                    struct icmp6hdr *icmp6h = data + L2_HLEN + sizeof(*ip6h);

                    // __com001
                    if (icmp6h + 1 > data_end)
                        MXDP_V6DROP

                    // all icmpv6 neighbor in forwarding are blocked
                    if (icmp6h->icmp6_type >= NDISC_ROUTER_SOLICITATION && icmp6h->icmp6_type <= NDISC_REDIRECT)
                        MXDP_V6DROP

                    if (((UnTrustedV6[UNTRUSTED_TO_LAN].s6_addr[0] & 0xFE) == 0xFC && netV6cmp(&ip6h->saddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP], (AMasks.lop & 0x00FF)) == true) || netV6cmp(&ip6h->saddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LAN], (AMasks.lan & 0x00FF)) == true)
                    {
                        if (icmp6h->icmp6_type == ICMPV6_DEST_UNREACH && (icmp6h->icmp6_code == ICMPV6_ADDR_UNREACH || icmp6h->icmp6_code == ICMPV6_NOROUTE)) // mikrotik reply with ICMPV6_NOROUTE
                        { // snat to MiEnRo loopback
                            struct ipv6hdr *enc_ip6h = NULL; // enclosed on icmp message
                            void *n_off = NULL;
                            __sum16 csum = 0;

                            enc_ip6h = data + ETH_HLEN + sizeof(*ip6h) + sizeof(*icmp6h);

                            if (enc_ip6h + 1 > data_end)
                                MXDP_V6DROP

                            __s32 msgroom = (__s32)sizeof(*enc_ip6h);

                            switch (enc_ip6h->nexthdr)
                            {
                            case IPPROTO_ICMPV6:
                                msgroom += (__s32)sizeof(struct icmp6hdr);
                                break;
                            case IPPROTO_TCP:
                                msgroom += (__s32)sizeof(struct tcphdr);
                                break;
                            case IPPROTO_UDP:
                                msgroom += (__s32)sizeof(struct udphdr);
                                break;
                            default:
                                MXDP_V6DROP
                            }

                            // leave only protocol headers like openbsd for ipv4 protocol, before forward mikrotik nas icmp diagnostic messages
                            if ((data_end - data) > (L2_HLEN + sizeof(*ip6h) + sizeof(*icmp6h) + msgroom))
                            {
                                struct icmp6hdr *icmp6h = NULL;

                                __u32 _csum = 0;

                                if (bpf_xdp_adjust_tail(ctx, 0 - ((data_end - data) - (L2_HLEN + sizeof(*ip6h) + sizeof(*icmp6h) + msgroom))))
                                    MXDP_V6DROP

                                data = (void *)(long)ctx->data;
                                data_end = (void *)(long)ctx->data_end;

                                l2hdr = data;

                                // __com001
                                if (l2hdr + 1 > data_end)
                                    MXDP_V6DROP;

#ifdef TRUNK_PORT
                                if (l2hdr->h_vlan_encapsulated_proto == htons(ETH_P_IPV6))
#else
                                if (l2hdr->h_proto == htons(ETH_P_IPV6))
#endif
                                {
                                    ip6h = data + L2_HLEN;

                                    if (ip6h + 1 > data_end)
                                        MXDP_V6DROP
                                }
                                else
                                    MXDP_V6DROP

                                ip6h->hop_limit = MIPDEFTTL;
                                ip6h->payload_len = htons((data_end - data) - L2_HLEN - sizeof(*ip6h));
                                ip6h->saddr.s6_addr32[0] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[0];
                                ip6h->saddr.s6_addr32[1] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[1];
                                ip6h->saddr.s6_addr32[2] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[2];
                                ip6h->saddr.s6_addr32[3] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[3];

                                icmp6h = data + L2_HLEN + sizeof(*ip6h);

                                if (icmp6h + 1 > data_end)
                                    MXDP_V6DROP

                                icmp6h->icmp6_cksum = 0; // check sum must be always reset before recalculate it

                                n_off = data + L2_HLEN;

                                csum = icmpV6csum(n_off, data_end, ntohs(ip6h->payload_len));

                                if (csum == 0)
                                    MXDP_V6DROP

                                icmp6h->icmp6_cksum = csum;
                            }
                            else
                            {
                                n_off = data + L2_HLEN;

                                ip6h->saddr.s6_addr32[0] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[0];
                                ip6h->saddr.s6_addr32[1] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[1];
                                ip6h->saddr.s6_addr32[2] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[2];
                                ip6h->saddr.s6_addr32[3] = UnTrustedV6[SNAT_TO_LOP].s6_addr32[3];

                                icmp6h->icmp6_cksum = 0; // check sum must be always reset before recalculate it

                                csum = icmpV6csum(n_off, data_end, ntohs(ip6h->payload_len));

                                if (csum == 0)
                                    MXDP_V6DROP
                                else
                                    icmp6h->icmp6_cksum = csum;
                            }

                            *((struct in6_addr *)fib_params.ipv6_src) = ip6h->saddr;

                            goto v6redirectfast;
                        }
                    }
                    else
                        goto v6redirectfast;

                    MXDP_V6DROP
                }
            }
#ifndef TRUNK_PORT
            else if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
#endif

            MXDP_V6DROP

        v6redirectfast:
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

            if (bpf_redirect_map(&xdp_lan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                MXDP_V6REDIRECT
            else
                MXDP_V6ABORTED
        v6redirect:
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

            if (bpf_redirect_map(&xdp_lan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
            {
                if (stats)
                {
                    stats->packets++;
                    stats->bytes += (ctx->data_end - ctx->data);
                    return XDP_REDIRECT;
                }
                else
                    MXDP_V6REDIRECT
            }
            else
                MXDP_V6ABORTED
        }
    }
    else if (rc == BPF_FIB_LKUP_RET_BLACKHOLE || // dest is blackholed
        rc == BPF_FIB_LKUP_RET_UNREACHABLE || // dest is unreachable and can be dropped from OS
        rc == BPF_FIB_LKUP_RET_PROHIBIT) // dest not allowed and can be dropped from OS
    {
        if (h_proto == htons(ETH_P_IP))
            MXDP_V4DROP
        else if (h_proto == htons(ETH_P_IPV6))
            MXDP_V6DROP
    }
    else if (rc == BPF_FIB_LKUP_RET_UNSUPP_LWT || // fwd requires encapsulation
        rc == BPF_FIB_LKUP_RET_FRAG_NEEDED) // fragmentation required to fwd
    {
        if (h_proto == htons(ETH_P_IP))
            MXDP_V4PASS
        else if (h_proto == htons(ETH_P_IPV6))
            MXDP_V6PASS
    }
    else if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) // INPUT_SECTION
    {
        __be16 icmplen;

        if (h_proto == htons(ETH_P_IP))
        {
            if (iph->protocol == IPPROTO_TCP)
            {
                if ((bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Not Fragmented data
                {
                    struct tcphdr *tcph = data + L2_HLEN + sizeof(*iph);

                    // __com001
                    if (tcph + 1 > data_end)
                        MXDP_V4DROP

                    if (htons(tcph->source) == SERVICE_BGP || htons(tcph->dest) == SERVICE_BGP)
                    {
                        __u32 key = UNTRUSTED_TO_LAN;

                        in4_addr *lanaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                        if (lanaddr == NULL || lanaddr == 0)
                            MXDP_V6DROP

                        if (*lanaddr != iph->daddr)
                            MXDP_V4DROP
                        else
                        {
                            __u32 key = 0;

                            amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                            if (_amasks == NULL)
                                MXDP_V4DROP

                            if (ntohs(_amasks->lan) > 0 && netV4cmp(lanaddr, &iph->saddr, ntohs(_amasks->lan)) == true)
                                MXDP_V4PASS
                        }
                    }
                }
                else
                {
                    __u32 key = UNTRUSTED_TO_LAN;

                    in4_addr *lanaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                    if (lanaddr == NULL || lanaddr == 0)
                        MXDP_V6DROP

                    if (*lanaddr != iph->daddr)
                        MXDP_V4DROP
                    else
                    {
                        __u32 key = 0;

                        amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                        if (_amasks == NULL)
                            MXDP_V4DROP

                        if (ntohs(_amasks->lan) > 0 && netV4cmp(lanaddr, &iph->saddr, ntohs(_amasks->lan)) == true)
                            MXDP_V4PASS
                    }
                }

                MXDP_V4DROP
            }
            else if (iph->protocol == IPPROTO_ICMP && (bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0)
                ; // Not Fragmented data
            else
                MXDP_V4DROP
#ifdef STRICT
            __sum16 csum = 0;
            __sum16 rcvcsum = 0;
#endif
            void *n_off = NULL;
            struct icmphdr *icmph = data + L2_HLEN + sizeof(*iph);

            if (icmph + 1 > data_end)
                MXDP_V4DROP

            if (icmph->type == ICMP_ECHO)
            {
#ifdef STRICT
                if (icmph->code != 0)
                    MXDP_V4DROP

                __u32 key = UNTRUSTED_TO_LAN;

                in4_addr *lanaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                if (lanaddr == NULL || lanaddr == 0)
                    MXDP_V6DROP

                if (*lanaddr != iph->daddr)
                    MXDP_V4DROP
                else
                {
                    __u32 key = 0;

                    amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                    if (_amasks == NULL)
                        MXDP_V4DROP

                    if (ntohs(_amasks->lan) == 0 || netV4cmp(lanaddr, &iph->saddr, ntohs(_amasks->lan)) == false)
                        MXDP_V4DROP
                }
#endif
            }
            else if (icmph->type == ICMP_INFO_REQUEST)
                MXDP_V4DROP
            else
            {
                if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                    MXDP_V4PASS

                __u32 key = 0;
                amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                // __com006
                if (_amasks)
                {
                    __u32 key = UNTRUSTED_TO_LAN;

                    in4_addr *lanaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                    // __com006
                    if (lanaddr && netV4cmp(lanaddr, &iph->saddr, ntohs(_amasks->lan)) == true)
                    {
                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                            dgn_reply_timer = bpf_ktime_get_ns();

                        MXDP_V4PASS
                    }
                }

                MXDP_V4DROP
            }
        icmpV4reply:
            icmph = data + L2_HLEN + sizeof(*iph);

            if (icmph->type != ICMP_ECHO)
                return XDP_ABORTED;

            icmplen = ntohs(iph->tot_len) - sizeof(*iph);

            // __com001
            if (data + L2_HLEN + sizeof(*iph) + icmplen > data_end)
                MXDP_V4DROP

            // __com001
            if (data + L2_HLEN + sizeof(*iph) + sizeof(*icmph) > data_end)
                MXDP_V4DROP

            n_off = data + L2_HLEN + sizeof(*iph);

            __u32 raddr = 0;
#ifdef STRICT
            rcvcsum = icmph->checksum;
            icmph->checksum = 0; // check sum must be always reset before recalculate it

            csum = icmpV4csum(n_off, data_end, icmplen);

            if (csum == 0)
                MXDP_V4DROP
            else if (rcvcsum != csum)
                MXDP_V4DROP
#endif
            // convert request into echo reply
            swap_src_dst_mac(data);
            raddr = iph->saddr;

            if (iph->ttl != MIPDEFTTL)
            {
                iph->ttl = MIPDEFTTL;
                iph->check = 0;
                __u32 _csum = 0;
                ipv4_csum(iph, sizeof(struct iphdr), &_csum);
                iph->check = (__sum16)~_csum; // nedeed when set TTL
            }

            iph->saddr = iph->daddr;
            iph->daddr = raddr;
            icmph->type = ICMP_ECHOREPLY;
            icmph->code = 0;
#ifdef STRICT
            icmph->checksum = rcvcsum;
#endif
            icmph->checksum += 0x0008;

            MXDP_V4TX
        }
        else if (h_proto == htons(ETH_P_IPV6))
        {
            __u8 *nexthdr = &ip6h->nexthdr;
            void *l3hdr = data + L2_HLEN + sizeof(*ip6h);
            struct frag_hdr *fraghdr = NULL;

            // Iterate thrown ipv6 extension headers (RFC 8200 https://datatracker.ietf.org/doc/html/rfc8200)
            // Packet with NEXTHDR_NONE should be ignored by hosts, but passed unaltered by routers (not for MiEnRo)
            // Fragmentation cannot be check by MiEnRo because packet must be riassembled (with too many resource) before forward.
            for (__u8 i = 0; i < IPV6_OPT_MAX; i++)
            {
                switch (*nexthdr)
                {
                case NEXTHDR_ROUTING: // Routing header. // Transparent
                case NEXTHDR_HOP: // Hop-by-hop option header. // Transparent
                case NEXTHDR_DEST: // Destination options header. // Transparent
                    nexthdr = l3hdr;

                    // __com001
                    if (nexthdr + 1 > data_end || *nexthdr == NEXTHDR_NONE)
                        MXDP_V6DROP

                    __u8 *hdrelen = l3hdr + offsetof(struct ipv6_opt_brief, hdrelen);

                    // __com001
                    if (hdrelen + 1 > data_end)
                        MXDP_V6DROP

                    l3hdr += (8 + (*hdrelen * 8));

                    // __com001
                    if (l3hdr + 1 > data_end)
                        MXDP_V6DROP

                    break;
                case NEXTHDR_FRAGMENT:
                    if (fraghdr)
                        MXDP_V6DROP

                    fraghdr = l3hdr;

                    // __com001
                    if (fraghdr + 1 > data_end || *nexthdr == NEXTHDR_NONE)
                        MXDP_V6DROP

                    nexthdr = &fraghdr->nexthdr;
                    /*
                     * Note: For host directly connected there is NO NEED to riassemble packet because they are ordered chronologically. (not important to do now)
                     *
                     * To increase security.
                     * Here we can find key (see struct frag_v4_int_bgp_key_brief_t in common.h) in lru map to store in protocol destination port value
                     * If we want key can be deleted when found last fragment.
                     * Key must be inserted after tcp filter check.
                     * Similar method can be done with ipv4.
                     */

                    l3hdr += sizeof(struct frag_hdr);

                    break;
                case NEXTHDR_TCP: // IPPROTO_TCP
                    i = IPV6_OPT_MAX;

                    break;
                default: // therefore include NEXTHDR_NONE, NEXTHDR_ESP, NEXTHDR_AUTH and so on
                    if (i == 0 && *nexthdr == ip6h->nexthdr) // protocol without options
                    {
                        i = IPV6_OPT_MAX;

                        break;
                    }

                    MXDP_V6DROP
                }
            }

            // __com001
            if (l3hdr + 1 > data_end)
                MXDP_V6DROP

            if (ip6h->nexthdr == IPPROTO_TCP || (fraghdr && (ntohs(fraghdr->frag_off) & 0xFFF9) == 0x0001 && *nexthdr == IPPROTO_TCP)) // For not Fragmented or First Fragment of data check always protocol port
            {
                struct tcphdr *tcph = l3hdr;

                // __com001
                if (tcph + 1 > data_end)
                    MXDP_V6DROP

                __u32 key;

                if (htons(tcph->source) == SERVICE_BGP || htons(tcph->dest) == SERVICE_BGP)
                {
                    __u32 key = UNTRUSTED_TO_LAN;

                    struct in6_addr *lanaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                    if (lanaddr == NULL || lanaddr->s6_addr[0] == 0)
                        MXDP_V6DROP

                    if (addrV6cmp(lanaddr, &ip6h->daddr) == false)
                        MXDP_V6DROP
                    else
                    {
                        __u32 key = 0;

                        amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                        if (_amasks == NULL)
                            MXDP_V6DROP

                        if ((_amasks->lan & 0x00FF) > 0 && netV6cmp(lanaddr, &ip6h->saddr, (_amasks->lan & 0x00FF)) == true)
                            MXDP_V6PASS
                    }
                }

                MXDP_V6DROP
            }
            else if (fraghdr && *nexthdr == IPPROTO_TCP)
            {
                __u32 key = UNTRUSTED_TO_LAN;

                struct in6_addr *lanaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                if (lanaddr == NULL || lanaddr->s6_addr[0] == 0)
                    MXDP_V6DROP

                if (addrV6cmp(lanaddr, &ip6h->daddr) == false)
                    MXDP_V6DROP
                else
                {
                    __u32 key = 0;

                    amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                    if (_amasks == NULL)
                        MXDP_V6DROP

                    if ((_amasks->lan & 0x00FF) > 0 && netV6cmp(lanaddr, &ip6h->saddr, (_amasks->lan & 0x00FF)) == true)
                        MXDP_V6PASS
                }
            }
            else if (ip6h->nexthdr == IPPROTO_ICMPV6)
                ;
            else
                MXDP_V6DROP
#ifdef STRICT
            __sum16 csum = 0;
            __sum16 rcvcsum = 0;
#endif
            //					if (((UnTrustedV6[UNTRUSTED_TO_LAN].s6_addr[0] & 0xFE) == 0xFC && netV6cmp(&ip6h->saddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP], (AMasks.lop & 0x00FF)) == true) ||
            //						netV6cmp(&ip6h->saddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LAN], (AMasks.lan & 0x00FF)) == true)
            struct in6_addr raddr;
            void *n_off = NULL;
            struct icmp6hdr *icmp6h = data + L2_HLEN + sizeof(*ip6h);

            // __com001
            if (icmp6h + 1 > data_end)
                MXDP_V6DROP

            if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST)
            {
                if (icmp6h->icmp6_code != 0)
                    MXDP_V6DROP

                __u32 key = UNTRUSTED_TO_LAN;

                struct in6_addr *lanaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                if (lanaddr == NULL || lanaddr->s6_addr[0] == 0)
                    MXDP_V6DROP

                if (addrV6cmp(lanaddr, &ip6h->daddr) == false)
                    MXDP_V6DROP
                else
                {
                    __u32 key = 0;

                    amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                    if (_amasks == NULL)
                        MXDP_V6DROP

                    if ((_amasks->lan & 0x00FF) == 0 || netV6cmp(lanaddr, &ip6h->saddr, (_amasks->lan & 0x00FF)) == false)
                        MXDP_V6DROP
                }
            } // ICMPV6 neighbor parser section
            else if (icmp6h->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION || icmp6h->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT)
            {
                if (icmp6h->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION && l2hdr->h_dest[0] == 0x33 && l2hdr->h_dest[1] == 0x33 && ip6h->daddr.s6_addr32[0] == 0x000002FF && ip6h->daddr.s6_addr32[1] == 0x00000000 && ip6h->daddr.s6_addr32[2] == 0x01000000 && ip6h->daddr.s6_addr32[3] >= 0x000000FF && ip6h->daddr.s6_addr32[3] <= 0xFFFFFFFF) // __com007
                    return XDP_PASS; // __com004
                else if ((ip6h->saddr.s6_addr16[0] & 0xC0FF) == 0x80FE || (ip6h->daddr.s6_addr16[0] & 0xC0FF) == 0x80FE) // icmpv6 neighbour solicitation messages must be received also via link-local addresses
                    return XDP_PASS; // __com004
                else
                {
                    __u32 key = 0;
                    amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                    // __com006
                    if (_amasks)
                    {
                        __u8 lanipV6mask = (_amasks->lan & 0x00FF);

                        if (lanipV6mask > 128)
                            MXDP_V6ABORTED;

                        __u32 key = UNTRUSTED_TO_LAN;

                        struct in6_addr *lanaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                        // __com006
                        if (lanaddr && lanaddr->s6_addr[0] > 0 && netV6cmp(lanaddr, &ip6h->saddr, lanipV6mask) == true)
                            return XDP_PASS; // __com004
                    }
                }
            }
            else
            {
                switch (icmp6h->icmp6_type)
                {
                case NDISC_NODETYPE_UNSPEC:
                case NDISC_NODETYPE_HOST:
                case NDISC_NODETYPE_NODEFAULT:
                case NDISC_NODETYPE_DEFAULT:
                case NDISC_ROUTER_SOLICITATION:
                case NDISC_ROUTER_ADVERTISEMENT:
                case NDISC_REDIRECT:
                    MXDP_V6DROP
                }

                if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                    MXDP_V6PASS

                __u32 key = 0;
                amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                // __com006
                if (_amasks)
                {
                    __u32 key = UNTRUSTED_TO_LAN;
                    struct in6_addr *lanaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                    // __com006
                    if (lanaddr && lanaddr->s6_addr[0] > 0 && netV6cmp(lanaddr, &ip6h->saddr, (_amasks->lan & 0x00FF)) == true)
                    {
                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                            dgn_reply_timer = bpf_ktime_get_ns();

                        MXDP_V6PASS
                    }
                }

                MXDP_V6DROP
            }
        icmpV6reply:
            icmp6h = data + L2_HLEN + sizeof(*ip6h);

            if (icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST)
                return XDP_ABORTED;

            icmplen = ntohs(ip6h->payload_len);
            n_off = data + L2_HLEN;
#ifdef STRICT
            rcvcsum = icmp6h->icmp6_cksum;
            icmp6h->icmp6_cksum = 0; // check sum must be always reset before recalculate it

            csum = icmpV6csum(n_off, data_end, icmplen);

            if (csum == 0)
                MXDP_V6DROP
            else if (rcvcsum != csum)
                MXDP_V6DROP
#endif
            // convert request into echo reply
            swap_src_dst_mac(data);
            raddr = ip6h->saddr;

            if (ip6h->hop_limit != MIPDEFTTL)
                ip6h->hop_limit = MIPDEFTTL;

            ip6h->saddr = ip6h->daddr;
            ip6h->daddr = raddr;
            icmp6h->icmp6_type = ICMPV6_ECHO_REPLY;
            icmp6h->icmp6_code = 0;
#ifdef STRICT
            icmp6h->icmp6_cksum = rcvcsum;
#endif
            icmp6h->icmp6_cksum -= 0x0001; // it may suffice when few changes are made

            MXDP_V6TX
        }
    }
    else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) // packet handled by OS because mac resolution is needed
    {
        if (h_proto == htons(ETH_P_IP))
            MXDP_V4PASS
        else if (h_proto == htons(ETH_P_IPV6))
            MXDP_V6PASS
    }

    if (h_proto == htons(ETH_P_IP))
        MXDP_V4DROP
    else if (h_proto == htons(ETH_P_IPV6))
        MXDP_V6DROP

    return XDP_DROP;
}

SEC("mienro_lan")
int mienro_lan_prog(struct xdp_md *ctx)
{
    return mienro_process_packet(ctx, 0);
}

SEC("mienro_lan_direct")
int mienro_lan_direct_prog(struct xdp_md *ctx)
{
    return mienro_process_packet(ctx, BPF_FIB_LOOKUP_DIRECT);
}

char _license[] SEC("license") = "GPL";

//
// Description: Increase performances using volatile variables instead of map's values
// Note: Since initialization is done, volatile data can return (outside protection block) unexpected results but this is normal.
//
// Input:
//
// Output:
//
// Return:
//
static __always_inline void init_variables(void)
{
    __u32 key = 0;
    txports_t *_txports = bpf_map_lookup_elem(&txports, &key);

    if (_txports == NULL)
        return;

    amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

    if (_amasks == NULL)
        return;

    key = UNTRUSTED_TO_WAN;

    in4_addr *addrV4wan = bpf_map_lookup_elem(&untrust_v4, &key);

    if (addrV4wan == NULL)
        return;

    key = UNTRUSTED_TO_SSH;

    in4_addr *addrV4ssh = bpf_map_lookup_elem(&untrust_v4, &key);

    if (addrV4ssh == NULL)
        return;

    key = UNTRUSTED_TO_DMZ;

    in4_addr *addrV4dmz = bpf_map_lookup_elem(&untrust_v4, &key);

    if (addrV4dmz == NULL)
        return;

    key = UNTRUSTED_TO_LAN;

    in4_addr *addrV4lan = bpf_map_lookup_elem(&untrust_v4, &key);

    if (addrV4lan == NULL)
        return;

    key = UNTRUSTED_TO_LOP;

    in4_addr *addrV4lop = bpf_map_lookup_elem(&untrust_v4, &key);

    if (addrV4lop == NULL)
        return;

    key = UNTRUSTED_TO_WAN;

    struct in6_addr *addrV6wan = bpf_map_lookup_elem(&untrust_v6, &key);

    if (addrV6wan == NULL)
        return;

    key = UNTRUSTED_TO_SSH;

    struct in6_addr *addrV6ssh = bpf_map_lookup_elem(&untrust_v6, &key);

    if (addrV6ssh == NULL)
        return;

    key = UNTRUSTED_TO_DMZ;

    struct in6_addr *addrV6dmz = bpf_map_lookup_elem(&untrust_v6, &key);

    if (addrV6dmz == NULL)
        return;

    key = UNTRUSTED_TO_LAN;

    struct in6_addr *addrV6lan = bpf_map_lookup_elem(&untrust_v6, &key);

    if (addrV6lan == NULL)
        return;

    key = UNTRUSTED_TO_LOP;

    struct in6_addr *addrV6net = bpf_map_lookup_elem(&untrust_v6, &key);

    if (addrV6net == NULL)
        return;

    // Protect critical section when writing volatile data
    bpf_spin_lock(&_txports->lock);

    if (TxPorts.wan > 0)
    { // Already initialized
        bpf_spin_unlock(&_txports->lock);
        return;
    }

    AMasks.wan = _amasks->wan;
    AMasks.dmz = _amasks->dmz;
    AMasks.lan = _amasks->lan;
    AMasks.lop = _amasks->lop;
    UnTrustedV4[UNTRUSTED_TO_WAN] = *addrV4wan;
    UnTrustedV4[UNTRUSTED_TO_SSH] = *addrV4ssh;
    UnTrustedV4[UNTRUSTED_TO_DMZ] = *addrV4dmz;
    UnTrustedV4[UNTRUSTED_TO_LAN] = *addrV4lan;
    UnTrustedV4[UNTRUSTED_TO_LOP] = *addrV4lop;
    UnTrustedV6[UNTRUSTED_TO_WAN] = (struct in6_addr) { .s6_addr32[0] = addrV6wan->s6_addr32[0], .s6_addr32[1] = addrV6wan->s6_addr32[1], .s6_addr32[2] = addrV6wan->s6_addr32[2], .s6_addr32[3] = addrV6wan->s6_addr32[3] };
    UnTrustedV6[UNTRUSTED_TO_SSH] = (struct in6_addr) { .s6_addr32[0] = addrV6ssh->s6_addr32[0], .s6_addr32[1] = addrV6ssh->s6_addr32[1], .s6_addr32[2] = addrV6ssh->s6_addr32[2], .s6_addr32[3] = addrV6ssh->s6_addr32[3] };
    UnTrustedV6[UNTRUSTED_TO_DMZ] = (struct in6_addr) { .s6_addr32[0] = addrV6dmz->s6_addr32[0], .s6_addr32[1] = addrV6dmz->s6_addr32[1], .s6_addr32[2] = addrV6dmz->s6_addr32[2], .s6_addr32[3] = addrV6dmz->s6_addr32[3] };
    UnTrustedV6[UNTRUSTED_TO_LAN] = (struct in6_addr) { .s6_addr32[0] = addrV6lan->s6_addr32[0], .s6_addr32[1] = addrV6lan->s6_addr32[1], .s6_addr32[2] = addrV6lan->s6_addr32[2], .s6_addr32[3] = addrV6lan->s6_addr32[3] };
    UnTrustedV6[UNTRUSTED_TO_LOP] = (struct in6_addr) { .s6_addr32[0] = addrV6net->s6_addr32[0], .s6_addr32[1] = addrV6net->s6_addr32[1], .s6_addr32[2] = addrV6net->s6_addr32[2], .s6_addr32[3] = addrV6net->s6_addr32[3] };
    TxPorts.wan = _txports->wan;
    TxPorts.wan_xdp = _txports->wan_xdp;
    TxPorts.ssh = _txports->ssh;
    TxPorts.ssh_xdp = _txports->ssh_xdp;
    TxPorts.dmz = _txports->dmz;
    TxPorts.dmz_xdp = _txports->dmz_xdp;
    TxPorts.lan = _txports->lan;
    TxPorts.lan_xdp = _txports->lan_xdp;

    __builtin_memset((void *)&fib_params_urpf4, 0, sizeof(struct bpf_fib_lookup));
    fib_params_urpf4.ifindex = _txports->lan;
    fib_params_urpf4.family = AF_INET;

    __builtin_memset((void *)&fib_params_urpf6, 0, sizeof(struct bpf_fib_lookup));
    fib_params_urpf6.ifindex = _txports->lan;
    fib_params_urpf6.family = AF_INET6;
    bpf_spin_unlock(&_txports->lock);

    bpf_printk("Initialized XDP on lan interface (cpu %u)", bpf_get_smp_processor_id());
}

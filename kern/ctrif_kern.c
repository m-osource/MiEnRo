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

#define KBUILD_MODNAME "ctrforwarder"
#include "common_ctr_kern.h"

// TODO testing variables using when forwarding data
static volatile __u32 core_id = 0;
static volatile txports_t TxPorts = { 0, 0, 0, 0 };
static volatile amasks_t AMasks = { 0, 0, 0, 0 };
static volatile in4_addr UnTrustedV4[UNTRUSTED_MAX];
static volatile struct in6_addr UnTrustedV6[UNTRUSTED_MAX];

struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} xdp_ctr_tx_ports SEC(".maps");

static __always_inline void init_variables(void);

static __always_inline int mienro_process_packet(struct xdp_md *ctx, u32 flags)
{
    const __u32 ifingress = ctx->ingress_ifindex;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *l3hdr = NULL;
    struct bpf_fib_lookup fib_params;
    struct vlan_ethhdr *l2hdr = data;
    struct ipv6hdr *ip6h = NULL;
    struct iphdr *iph = NULL;
    u16 h_proto;
    u64 nh_off;
    int rc;
    bool intcp_echo_request = false; // __com002
    ifidx_t *ifinfo = NULL;

    /*
    * Only for debugging
    *
    __u32 coreid = 0;
    if ((coreid = bpf_get_smp_processor_id()) != core_id)
    {
            bpf_printk("for ctr core changed from %u to %u", core_id, coreid);
            core_id = coreid;
    } */

    nh_off = VLAN_ETH_HLEN;

    // __com001
    if (data + nh_off > data_end || unlikely(ntohs(l2hdr->h_vlan_proto) < ETH_P_802_3_MIN) || // Skip non 802.3 Ethertypes
        unlikely(ntohs(l2hdr->h_vlan_encapsulated_proto) < ETH_P_802_3_MIN)) // Skip non 802.3 Ethertypes
    {
        __u32 key = 0;
        update_stats(bpf_map_lookup_elem(&fail_cnt, &key), (ctx->data_end - ctx->data));

        return XDP_DROP;
    }

    if (l2hdr->h_vlan_proto == htons(ETH_P_8021Q))
    {
        if (VLAN_SSH_VID != (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK) && VLAN_DMZ_VID != (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            return XDP_ABORTED;
    }
    else
        return XDP_ABORTED;

    h_proto = l2hdr->h_vlan_encapsulated_proto;

    if (h_proto == htons(ETH_P_IP))
    {
        iph = data + nh_off;

        if (iph + 1 > data_end || iph->ihl < 5 || iph->ihl > 15)
            MXDP_V4DROP

        // handle time exceeded
        if (VLAN_SSH_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK) && iph->ttl <= 1)
        {
            __u32 key = UNTRUSTED_TO_SSH;

            in4_addr *saddr = bpf_map_lookup_elem(&untrust_v4, &key);

            if (saddr)
                return send_icmp4(ctx, saddr, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL); // to use only when packet forwarding
            else
                MXDP_V4DROP
        }

        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        //		fib_params.sport		= 0; // see __builtin_memset above
        //		fib_params.dport		= 0; // see __builtin_memset above
        fib_params.tot_len = ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
#ifdef STRICT
        fib_params.ipv4_dst = iph->saddr;

        if (TxPorts.dmz > 0 && VLAN_DMZ_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK) && check__urpf(ctx, &fib_params, flags, TxPorts.dmz) == true)
            MXDP_V4DROP
#endif
        fib_params.ipv4_dst = iph->daddr;
        fib_params.h_vlan_proto = 0;
        fib_params.h_vlan_TCI = 0;

        // bpf_printk("CTR IF: source %pI4 dest %pI4", &iph->saddr, &iph->daddr); // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
    }
    else if (h_proto == htons(ETH_P_IPV6))
    {
        ip6h = data + nh_off;

        if (ip6h + 1 > data_end)
            MXDP_V6DROP

        // handle time exceeded
        if (VLAN_SSH_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK) && ip6h->hop_limit <= 1)
        {
            __u32 key = UNTRUSTED_TO_SSH;

            struct in6_addr *saddr = bpf_map_lookup_elem(&untrust_v6, &key);

            if (saddr)
                return send_icmp6(ctx, saddr, ICMPV6_TIME_EXCEED, ICMPV6_EXC_HOPLIMIT); // to use only when packet forwarding
            else
                MXDP_V6DROP
        }

        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.family = AF_INET6;
        fib_params.flowinfo = *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol = ip6h->nexthdr;
        //		fib_params.sport		= 0; // see __builtin_memset above
        //		fib_params.dport		= 0; // see __builtin_memset above
        fib_params.tot_len = ntohs(ip6h->payload_len);
        *((struct in6_addr *)fib_params.ipv6_src) = ip6h->saddr;
#ifdef STRICT
        *((struct in6_addr *)fib_params.ipv6_dst) = ip6h->saddr;

        if (TxPorts.dmz > 0 && VLAN_DMZ_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK) && check__urpf(ctx, &fib_params, flags, TxPorts.dmz) == true)
            MXDP_V6DROP
#endif
        *((struct in6_addr *)fib_params.ipv6_dst) = ip6h->daddr;
        fib_params.h_vlan_proto = 0;
        fib_params.h_vlan_TCI = 0;

        // bpf_printk("CTR IF: source %pI6 dest %pI6", &ip6h->saddr, &ip6h->daddr); // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
    }
    else if (h_proto == htons(ETH_P_ARP) || h_proto == htons(ETH_P_RARP))
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
        // Verify egress index has been configured as TX-port.
        //
        // (Note: User can still have inserted an egress ifindex that
        // doesn't support XDP xmit, which will result in packet drops).
        //
        // Note: lookup in devmap supported since 0cdbb4b09a0.
        // If not supported will fail with:
        //  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
        //
        //	if (! bpf_map_lookup_elem(&xdp_ctr_tx_ports, &fib_params.ifindex))
        //		MXDP_V4DROP

        if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES
            init_variables();

        if (h_proto == htons(ETH_P_IP))
        {
            xdp_stats_t *stats = NULL;
            // clang-format off
                                                             /*************
                                                             *FIREWALL ACL*
                                                             *************/
            // clang-format on
            if (VLAN_DMZ_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                // block all traffic forwarded from local addresses because if packet is arrived here, potentially our devices can reach internet (172.16.0.0/12 - RFC 1918)
                if ((iph->saddr & 0x0000F0FF) == 0x000010AC)
                    MXDP_V4DROP
#ifdef TRUNK_PORT
                ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                if (ifinfo && ifinfo->xdp_idx == TxPorts.wan_xdp)
                {
                    fib_params.ifindex = ifinfo->xdp_idx;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
                }
                else
                    MXDP_V4DROP

                if (ifinfo)
#else
                if (fib_params.ifindex == TxPorts.wan)
#endif
                {
                    __u8 icmp4_type = ICMP_DEST_UNREACH;
                    __u8 icmp4_code = ICMP_PORT_UNREACH;
                    __u8 deltattl = 0;
                    in4_addr saddr = 0;

                    if (iph->ttl < 2)
                        MXDP_V4PASS

                    ip_decrease__ttl(iph); // decrease ttl only if packets come from dmz zone

                    // Do no check TCP or UDP protocol headers because delegated to Controller
                    if (iph->protocol == IPPROTO_TCP)
                    {
                        if ((stats = bpf_map_lookup_elem(&tcp_v4wl, &iph->daddr)) || (stats = bpf_map_lookup_elem(&mon_v4wl, &iph->daddr)))
                            goto v4redirect;
                    }
                    else if (iph->protocol == IPPROTO_UDP)
                    {
                        struct udphdr *udph = data + VLAN_ETH_HLEN + (iph->ihl * 4);

                        // __com001
                        if (udph + 1 > data_end)
                            MXDP_V4DROP

                        // traceroute requests permitted from dmz zone
                        if (udph && (htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                        {
                            if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                                goto v4redirectfast;
                        }

                        if ((stats = bpf_map_lookup_elem(&udp_v4wl, &iph->daddr)) || (stats = bpf_map_lookup_elem(&mon_v4wl, &iph->daddr)))
                            goto v4redirect;
                    }
                    else if (iph->protocol == IPPROTO_ICMP)
                    {
                        if ((bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Not fragmented data
                        {
                            struct icmphdr *icmph = data + VLAN_ETH_HLEN + sizeof(*iph);

                            if (icmph + 1 > data_end)
                                MXDP_V4DROP

                            if (icmph->type == ICMP_ECHO)
                            {
                                if (icmph->code != 0 || (ntohs(iph->tot_len) - sizeof(*iph)) > ICMPV4_MAX_SIZE)
                                    MXDP_V4DROP

                                if (bpf_map_lookup_elem(&icmp_v4wl, &iph->daddr))
                                {
                                    if (bpf_map_lookup_elem(&mon_v4wl, &iph->daddr) && ((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                        dgn_reply_timer = bpf_ktime_get_ns();
                                }
                                else
                                {
                                    if (netV4cmp((in4_addr *)&UnTrustedV4[UNTRUSTED_TO_WAN], &iph->daddr, ntohs(AMasks.wan)) == true)
                                    {
                                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                            dgn_reply_timer = bpf_ktime_get_ns();
                                    }
                                    else if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME) // only to avoid queries to map mon_v6wl when not needed
                                        MXDP_V4DROP
                                }

                                goto v4redirectfast;
                            }
                            else
                            {
                                if (bpf_map_lookup_elem(&icmp_v4wl, &iph->daddr) && netV4cmp((in4_addr *)&UnTrustedV4[UNTRUSTED_TO_DMZ], &iph->saddr, ntohs(AMasks.dmz)) == true)
                                    goto v4redirectfast;

                                MXDP_V4DROP
                            }

                            MXDP_V4DROP
                        }
                        else if (bpf_map_lookup_elem(&icmp_v4wl, &iph->daddr)) // Fragmented icmp protocol can be forward to trusted server
                            goto v4redirectfast;

                        MXDP_V4DROP
                    }
                }
            }
            else if (VLAN_SSH_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                if (iph->protocol == IPPROTO_TCP)
                {
                    __u32 key = 0;

#ifdef TRUNK_PORT
                    ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                    if (ifinfo && ifinfo->xdp_idx == TxPorts.wan_xdp)
                    {
                        fib_params.ifindex = ifinfo->xdp_idx;
                        l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
                    }
                    else
                        MXDP_V4DROP

                    if (ifinfo)
#else
                    if (fib_params.ifindex == TxPorts.wan)
#endif
                    {
                        in4_addr *saddr = NULL;

                        if ((iph->saddr & 0x0000F0FF) == 0x000010AC)
                            MXDP_V4DROP // block all traffic forwarded from local addresses because if packet is arrived here, potentially our devices can reach internet (172.16.0.0/12 - RFC 1918)
                                else
                            {
                                key = UNTRUSTED_TO_LOP;
                                saddr = bpf_map_lookup_elem(&untrust_v4, &key);

                                if (saddr && iph->saddr == *saddr) // check if traffic is received from controller node loopback address
                                {
                                    // struct tcphdr *tcph = data + L2_HLEN + (iph->ihl * 4);
                                    struct tcphdr *tcph = data + VLAN_ETH_HLEN + sizeof(*iph);

                                    // __com001
                                    if ((void *)tcph + sizeof(*tcph) > data_end)
                                        MXDP_V4DROP

                                    if (htons(tcph->source) == SERVICE_SSH_CTR && iph->saddr == UnTrustedV4[UNTRUSTED_TO_LOP])
                                    {
                                        streamV4_t in_id_stream = { 0 };
                                        in_id_stream.saddr = iph->daddr;
                                        in_id_stream.protocol = iph->protocol;
                                        in_id_stream.source = tcph->dest;

                                        streamV4_t *out_id_stream = bpf_map_lookup_elem(&dnat_v4map, &in_id_stream);

                                        if (out_id_stream)
                                        {
                                            const in4_addr saddr = out_id_stream->daddr; // Note: from the point of view of the wan interface ctr source address is saved as the destination address
                                            csumV4nat(&iph->check, &iph->saddr, &saddr);
                                            csumV4nat(&tcph->check, &iph->saddr, &saddr);
                                            iph->saddr = saddr; // snat of source address
                                        }

                                        goto v4redirect;
                                    }
                                }
                            }
                    }
                    else
                        MXDP_V4DROP
                }
                else if (iph->protocol == IPPROTO_ICMP)
                {
                    __u32 key = 0;

                    struct icmphdr *icmph = data + VLAN_ETH_HLEN + sizeof(*iph);

                    if (icmph + 1 > data_end)
                        MXDP_V4DROP

                    // Always do a checksum before make a decision of blacklist an address
                    __sum16 rcvcsum = icmph->checksum;
                    icmph->checksum = 0; // check sum must be always reset before recalculate it

                    __be16 icmplen = ntohs(iph->tot_len) - sizeof(*iph);
                    void *n_off = data + VLAN_ETH_HLEN + sizeof(*iph);
                    __sum16 csum = icmpV4csum(n_off, data_end, icmplen);

                    if (csum == 0)
                        MXDP_V4DROP
                    else if (rcvcsum != csum)
                        MXDP_V4DROP
#ifdef TRUNK_PORT
                    ifidx_t *ifinfo = NULL;

                    ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                    if (ifinfo && ifinfo->xdp_idx == TxPorts.wan_xdp)
                    {
                        fib_params.ifindex = ifinfo->xdp_idx;
                        l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
                    }
                    else
                        MXDP_V4DROP

                    if (ifinfo)
#else
                    if (fib_params.ifindex == TxPorts.wan)
#endif
                    { // Warning: controller reply only with those messages to cracker because pf.conf contain rule: block return-icmp(3,4) quick from <sshbruteforce> (Dest Unreach (3) port unreach ipv4, (4) port unreach ipv6)
                        if (icmph->type == ICMP_DEST_UNREACH && icmph->code == ICMP_PORT_UNREACH)
                        { // Populate or update (ssh bruteforce) ssh_v4timeo map
                            timeo_t *timeo = bpf_map_lookup_elem(&ssh_v4tmo, &iph->daddr);

                            __u64 now = (bpf_ktime_get_ns() / NANOSEC_PER_SEC); // uptime cannot be obtained inside lock's block

                            // Insert or handle remote address in timeout map only if not a monitor addresses
                            if (bpf_map_lookup_elem(&mon_v4wl, &iph->daddr) == NULL)
                            {
                                if (timeo)
                                {
                                    bpf_spin_lock(&timeo->lock);

                                    if (now > timeo->lastuptime + SSH_DENIED_TIME)
                                        timeo->lastuptime = now; // set approximate system uptime

                                    bpf_spin_unlock(&timeo->lock);
                                }
                                else
                                {
                                    timeo_t timeo;
                                    __builtin_memset(&timeo, 0, sizeof(timeo));
                                    timeo.creationtime = now; // set approximate system uptime
                                    timeo.lastuptime = now; // set approximate system uptime

                                    bpf_map_update_elem(&ssh_v4tmo, &iph->daddr, &timeo, BPF_NOEXIST);
                                }
                            }
                        }
                    }
                }
            }

            MXDP_V4DROP

        v4redirectfast:
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);
#ifndef TRUNK_PORT
            // shift on rigth for VLAN_HDR_SIZE bytes, the mac addrs
            __builtin_memmove(data + VLAN_HDR_SIZE, data, (ETH_ALEN * 2)); // Note: LLVM built-in memmove inlining require size to be constant

            // Move on ahead start of packet header seen by Linux kernel stack
            bpf_xdp_adjust_head(ctx, VLAN_HDR_SIZE);
#endif
            if (bpf_redirect_map(&xdp_ctr_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                MXDP_V4REDIRECT
            else
                MXDP_V4ABORTED
        v4redirect:
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);
#ifndef TRUNK_PORT
            // shift on rigth for VLAN_HDR_SIZE bytes, the mac addrs
            __builtin_memmove(data + VLAN_HDR_SIZE, data, (ETH_ALEN * 2)); // Note: LLVM built-in memmove inlining require size to be constant

            // Move on ahead start of packet header seen by Linux kernel stack
            bpf_xdp_adjust_head(ctx, VLAN_HDR_SIZE);
#endif
            if (bpf_redirect_map(&xdp_ctr_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
            {
                if (stats)
                {
                    stats->packets++;
                    stats->bytes += (ctx->data_end - ctx->data);
                    return XDP_REDIRECT;
                }
                else
                    MXDP_V4REDIRECT
            }
            else
                MXDP_V4ABORTED

            MXDP_V4DROP;
        }
        else if (h_proto == htons(ETH_P_IPV6))
        {
            xdp_stats_t *stats = NULL;
            __u8 *nexthdr = NULL;
            struct frag_hdr *fraghdr = NULL;
            bool nexthdr_routing = false;
            bool nexthdr_dest = false;

            nexthdr = &ip6h->nexthdr;
            l3hdr = data + VLAN_ETH_HLEN + sizeof(*ip6h);

#ifdef TRUNK_PORT
            ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

            if (ifinfo)
            {
                if (ifinfo->xdp_idx == TxPorts.wan_xdp)
                    fib_params.ifindex = ifinfo->xdp_idx;
                else
                    MXDP_V6DROP
            }
            else
                MXDP_V6DROP
#endif
            // Iterate thrown ipv6 extension headers (RFC 8200 https://datatracker.ietf.org/doc/html/rfc8200)
            // Packet with NEXTHDR_NONE should be ignored by hosts, but passed unaltered by routers (not for MiEnRo)
            // Fragmentation cannot be check by MiEnRo because packet must be riassembled (with too many resource) before forward.
            for (__u8 i = 0; i < IPV6_OPT_MAX; i++)
            {
                switch (*nexthdr)
                {
                case NEXTHDR_ESP:
                case NEXTHDR_AUTH:
#ifndef TRUNK_PORT
                    if (fib_params.ifindex != TxPorts.wan)
                        MXDP_V6DROP
#endif
                    nexthdr = l3hdr;

                    // __com001
                    if (nexthdr + 1 > data_end || *nexthdr == NEXTHDR_NONE)
                        MXDP_V6DROP

                    if ((stats = bpf_map_lookup_elem(&vpn_v6wl, &ip6h->saddr))) // check if source address is found in map of remote servers and forward to ctr any type of ping
                    {
                        ip6h->hop_limit--; // decrease ttl only for dmz interface

                        goto v6redirect;
                    }
                    else
                        MXDP_V6DROP

                    break;
                case NEXTHDR_ROUTING: // Routing header. // Transparent
                    if (nexthdr_routing == false)
                        nexthdr_routing = true;
                    else
                        MXDP_V6DROP;
                case NEXTHDR_DEST: // Destination options header. // Transparent
                    if (*nexthdr == NEXTHDR_DEST)
                    {
                        if (nexthdr_dest == false)
                            nexthdr_dest = true;
                        else
                            MXDP_V6DROP;
                    }

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

                    l3hdr += sizeof(struct frag_hdr);

                    break;
                case NEXTHDR_TCP: // IPPROTO_TCP
                case NEXTHDR_UDP: // IPPROTO_UDP
                case NEXTHDR_ICMP: // IPPROTO_ICMPV6
                    i = IPV6_OPT_MAX;

                    break;
                default: // therefore include NEXTHDR_HOP, NEXTHDR_NONE
                    MXDP_V6DROP
                }
            }

            // __com001
            if (l3hdr + 1 > data_end)
                MXDP_V6DROP
            // clang-format off
                                                             /*************
                                                             *FIREWALL ACL*
                                                             *************/
            // clang-format on
            if (VLAN_DMZ_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            { // block all traffic forwarded from link-local addresses because if packet is arrived here, potentially our devices can reach internet (fc00::/7 - RFC 1918)
                if ((ip6h->saddr.s6_addr[0] & 0xFE) == 0xFC)
                    MXDP_V6DROP

                if (ifinfo)
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
                else if (fib_params.ifindex != TxPorts.wan)
                    MXDP_V6DROP

                __u8 icmp6_type = ICMPV6_DEST_UNREACH;
                __u8 icmp6_code = ICMPV6_PORT_UNREACH;
                __u8 deltattl = 0;
                struct in6_addr saddr;
                struct tcphdr *tcph = NULL;
                struct udphdr *udph = NULL;
                __be16 *sport = NULL;
                __be16 *dport = NULL;

                if (ip6h->hop_limit < 2)
                    MXDP_V6PASS

                ip6h->hop_limit--;

                if (*nexthdr == IPPROTO_TCP)
                {
                    if ((stats = bpf_map_lookup_elem(&tcp_v6wl, &ip6h->daddr)) || (stats = bpf_map_lookup_elem(&vpn_v6wl, &ip6h->daddr)) || (stats = bpf_map_lookup_elem(&mon_v6wl, &ip6h->daddr)))
                        goto v6redirect;
                }
                else if (*nexthdr == IPPROTO_UDP)
                {
                    struct udphdr *udph = l3hdr;

                    // __com001
                    if (udph + 1 > data_end)
                        MXDP_V6DROP

                    // traceroute requests permitted from dmz zone
                    if (udph && (htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                    {
                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                            goto v6redirectfast;
                    }

                    if ((stats = bpf_map_lookup_elem(&udp_v6wl, &ip6h->daddr)) || (stats = bpf_map_lookup_elem(&vpn_v6wl, &ip6h->daddr)) || (stats = bpf_map_lookup_elem(&mon_v6wl, &ip6h->daddr)))
                        goto v6redirect;
                }
                else if (ip6h->nexthdr == IPPROTO_ICMPV6)
                {
                    struct icmp6hdr *icmp6h = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                    // __com001
                    if (icmp6h + 1 > data_end)
                        MXDP_V6DROP

                    // all icmpv6 neighbor in forwarding are blocked
                    if (icmp6h->icmp6_type >= NDISC_ROUTER_SOLICITATION && icmp6h->icmp6_type <= NDISC_REDIRECT)
                        MXDP_V6DROP

                    if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST)
                    {
                        if (icmp6h->icmp6_code != 0 || ntohs(ip6h->payload_len) > ICMPV6_MAX_SIZE)
                            MXDP_V6DROP

                        ip6h->hop_limit--; // decrease ttl only for dmz interface

                        if (bpf_map_lookup_elem(&icmp_v6wl, &ip6h->daddr))
                        {
                            if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->daddr) && ((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                dgn_reply_timer = bpf_ktime_get_ns();
                        }
                        else
                        {
                            if (netV6cmp((struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_WAN], &ip6h->daddr, (AMasks.wan & 0x00FF)) == true)
                            {
                                if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                    dgn_reply_timer = bpf_ktime_get_ns();
                            }
                            else if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME) // only to avoid queries to map mon_v6wl when not needed
                                MXDP_V6DROP
                        }

                        goto v6redirectfast;
                    } // always permit all remain icmp messages in transit from our remote servers and internet inside a range timeout
                    else if (bpf_map_lookup_elem(&icmp_v6wl, &ip6h->daddr))
                    {
                        ip6h->hop_limit--;
                        goto v6redirectfast;
                    }

                    MXDP_V6DROP
                }
                else if (*nexthdr == IPPROTO_ICMPV6)
                { // always permit all remain icmp messages in transit from our remote servers and internet inside a range timeout
                    if (bpf_map_lookup_elem(&icmp_v6wl, &ip6h->daddr))
                        goto v6redirectfast;
                }
            }
            else if (VLAN_SSH_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                if (*nexthdr == IPPROTO_TCP)
                {
                    __u32 key = 0;

                    if (ifinfo)
                    {
                        if (ifinfo->xdp_idx == TxPorts.wan_xdp)
                            l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
                        else
                            MXDP_V6DROP
                    }
                    else if (fib_params.ifindex != TxPorts.wan)
                        MXDP_V6DROP

                    __u8 *nexthdr = &ip6h->nexthdr;
                    struct frag_hdr *fraghdr = NULL;
                    bool nexthdr_routing = false;
                    bool nexthdr_dest = false;

                    void *l3hdr = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                    // Iterate thrown ipv6 extension headers (RFC 8200 https://datatracker.ietf.org/doc/html/rfc8200)
                    // Packet with NEXTHDR_NONE should be ignored by hosts, but passed unaltered by routers (not for MiEnRo)
                    // Fragmentation cannot be check by MiEnRo because packet must be riassembled (with too many resource) before forward.
                    for (__u8 i = 0; i < IPV6_OPT_MAX; i++)
                    {
                        switch (*nexthdr)
                        {
                        case NEXTHDR_ROUTING: // Routing header. // Transparent
                            if (nexthdr_routing == false)
                                nexthdr_routing = true;
                            else
                                MXDP_V6DROP;
                        case NEXTHDR_DEST: // Destination options header. // Transparent - Mienro accept it only once.
                            if (*nexthdr == NEXTHDR_DEST)
                            {
                                if (nexthdr_dest == false)
                                    nexthdr_dest = true;
                                else
                                    MXDP_V6DROP;
                            }

                            nexthdr = l3hdr; // Note: the nexthdr indicator in the Ipv6 Extention header is the first byte

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
                            if (fraghdr + 1 > data_end || fraghdr->nexthdr == NEXTHDR_NONE)
                                MXDP_V6DROP

                            nexthdr = &fraghdr->nexthdr;

                            // l3hdr += sizeof(struct frag_hdr); // Not needed next header over fragmented data is administratively not parsed

                            break;
                        default: // therefore include NEXTHDR_NONE, NEXTHDR_HOP, NEXTHDR_ESP, NEXTHDR_AUTH and so on
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

                    struct tcphdr *tcph = l3hdr;

                    // __com001
                    if ((void *)tcph + sizeof(*tcph) > data_end)
                        MXDP_V6DROP

                    struct in6_addr *saddr = NULL;
#ifdef IPV6_SSH
                    if ((ip6h->saddr.s6_addr[0] & 0xFE) == 0xFC)
                        MXDP_V6DROP // block all traffic forwarded from link-local addresses because if packet is arrived here, potentially our devices can reach internet (fc00::/7 - RFC 1918)
                            else if (htons(tcph->source) == SERVICE_SSH_CTR)
                        {
                            key = UNTRUSTED_TO_LOP;
                            saddr = bpf_map_lookup_elem(&untrust_v6, &key);

                            if (saddr && addrV6cmp(&ip6h->saddr, saddr) == true)
                            {
                                __u32 _csum = 0;

                                streamV6_t in_id_stream = { 0 };
                                in_id_stream.saddr = (struct in6_addr) { .s6_addr32[0] = ip6h->daddr.s6_addr32[0], .s6_addr32[1] = ip6h->daddr.s6_addr32[1], .s6_addr32[2] = ip6h->daddr.s6_addr32[2], .s6_addr32[3] = ip6h->daddr.s6_addr32[3] };
                                in_id_stream.nexthdr = ip6h->nexthdr;
                                in_id_stream.source = tcph->dest;

                                streamV6_t *out_id_stream = bpf_map_lookup_elem(&dnat_v6map, &in_id_stream);

                                if (out_id_stream)
                                {
                                    // clang-format off
                    			const struct in6_addr saddr = (struct in6_addr) { .s6_addr32[0] = out_id_stream->daddr.s6_addr32[0],
                                			                                      .s6_addr32[1] = out_id_stream->daddr.s6_addr32[1],
                                            			                          .s6_addr32[2] = out_id_stream->daddr.s6_addr32[2],
                                                        			              .s6_addr32[3] = out_id_stream->daddr.s6_addr32[3] };
                                    // clang-format on
                                    // perform a checksum and copy daddr in ip6h->daddr
                                    csumV6nat(&tcph->check, &ip6h->saddr, &saddr);
                                }

                                goto v6redirect;
                            }
                        }
#else
                    if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->daddr)) // Always permit ipv6 ssh monitor replies
                    {
                        if ((ip6h->saddr.s6_addr[0] & 0xFE) == 0xFC)
                            MXDP_V6DROP // block all traffic forwarded from link-local addresses because if packet is arrived here, potentially our devices can reach internet (fc00::/7 - RFC 1918)
                                else
                            {
                                key = UNTRUSTED_TO_LOP;
                                saddr = bpf_map_lookup_elem(&untrust_v6, &key);

                                if (saddr && addrV6cmp(&ip6h->saddr, saddr) == true)
                                    goto v6redirect;
                            }
                    }
#endif
                }
#ifdef IPV6_SSH
                else if (ip6h->nexthdr == IPPROTO_ICMPV6)
                {
                    __u32 key = 0;

                    if (ifinfo)
                    {
                        if (ifinfo->xdp_idx == TxPorts.wan_xdp)
                            l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid
                        else
                            MXDP_V6DROP
                    }
                    else if (fib_params.ifindex != TxPorts.wan)
                        MXDP_V6DROP

                    struct icmp6hdr *icmp6h = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                    // __com001
                    if (icmp6h + 1 > data_end)
                        MXDP_V6DROP

                    // Always do a checksum before make a decision of blacklist an address
                    __sum16 rcvcsum = icmp6h->icmp6_cksum;
                    icmp6h->icmp6_cksum = 0; // check sum must be always reset before recalculate it

                    __be16 icmplen = ntohs(ip6h->payload_len);
                    void *n_off = data + VLAN_ETH_HLEN;
                    __sum16 csum = icmpV6csum(n_off, data_end, icmplen);

                    if (csum == 0)
                        MXDP_V6DROP
                    else if (rcvcsum != csum)
                        MXDP_V6DROP

                    // all icmpv6 neighbor in forwarding are blocked
                    if (icmp6h->icmp6_type >= NDISC_ROUTER_SOLICITATION && icmp6h->icmp6_type <= NDISC_REDIRECT)
                        MXDP_V6DROP

                    // Warning: controller reply only with those messages to cracker because pf.conf contain rule: block return-icmp(3,4) quick from <sshbruteforce> (Dest Unreach (3) port unreach ipv4, (4) port unreach ipv6)
                    if (icmp6h->icmp6_type == ICMPV6_DEST_UNREACH && icmp6h->icmp6_code == ICMPV6_PORT_UNREACH)
                    { // Populate or update (ssh bruteforce) ssh_v4timeo map
                        timeo_t *timeo = bpf_map_lookup_elem(&ssh_v6tmo, &ip6h->daddr);

                        __u64 now = (bpf_ktime_get_ns() / NANOSEC_PER_SEC); // uptime cannot be obtained inside lock's block

                        // Insert or handle remote address in timeout map only if not a monitor addresses
                        if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->daddr) == NULL)
                        {
                            if (timeo)
                            {
                                bpf_spin_lock(&timeo->lock);

                                if (now > timeo->lastuptime + SSH_DENIED_TIME)
                                    timeo->lastuptime = now; // set approximate system uptime

                                bpf_spin_unlock(&timeo->lock);
                            }
                            else
                            {
                                timeo_t timeo;
                                __builtin_memset(&timeo, 0, sizeof(timeo));
                                timeo.creationtime = now; // set approximate system uptime
                                timeo.lastuptime = now; // set approximate system uptime

                                bpf_map_update_elem(&ssh_v6tmo, &ip6h->daddr, &timeo, BPF_NOEXIST);
                            }

                            MXDP_V6DROP
                        }
                    }
                }
#endif
            }

            MXDP_V6DROP

        v6redirectfast:
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);
#ifndef TRUNK_PORT
            // shift on rigth for VLAN_HDR_SIZE bytes, the mac addrs
            __builtin_memmove(data + VLAN_HDR_SIZE, data, (ETH_ALEN * 2)); // Note: LLVM built-in memmove inlining require size to be constant

            // Move on ahead start of packet header seen by Linux kernel stack
            bpf_xdp_adjust_head(ctx, VLAN_HDR_SIZE);
#endif
            if (bpf_redirect_map(&xdp_ctr_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                MXDP_V6REDIRECT
            else
                MXDP_V6ABORTED
        v6redirect:
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);
#ifndef TRUNK_PORT
            // shift on rigth for VLAN_HDR_SIZE bytes, the mac addrs
            __builtin_memmove(data + VLAN_HDR_SIZE, data, (ETH_ALEN * 2)); // Note: LLVM built-in memmove inlining require size to be constant

            // Move on ahead start of packet header seen by Linux kernel stack
            bpf_xdp_adjust_head(ctx, VLAN_HDR_SIZE);
#endif
            if (bpf_redirect_map(&xdp_ctr_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
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

            MXDP_V6DROP;
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
            if (VLAN_DMZ_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                if (iph->protocol == IPPROTO_TCP)
                {
                    if ((ntohs(iph->frag_off) & 0x01FF) == 0x0000) // For not Fragmented or First Fragment of data check always protocol port
                    {
                        struct tcphdr *tcph = data + VLAN_ETH_HLEN + (iph->ihl * 4);

                        // __com001
                        if ((void *)tcph + sizeof(*tcph) > data_end)
                            MXDP_V4DROP

                        if (htons(tcph->source) == SERVICE_BGP || htons(tcph->dest) == SERVICE_BGP)
                        {
                            __u32 key = UNTRUSTED_TO_DMZ;

                            in4_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                            if (dmzaddr == NULL || dmzaddr == 0)
                                MXDP_V6DROP

                            if (*dmzaddr != iph->daddr)
                                MXDP_V4DROP
                            else
                            {
                                __u32 key = 0;

                                amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                                if (_amasks == NULL)
                                    MXDP_V4DROP

                                if (ntohs(_amasks->dmz) > 0 && netV4cmp(dmzaddr, &iph->saddr, ntohs(_amasks->dmz)) == true)
                                    MXDP_V4PASS
                            }
                        }
                    }
                    else
                    {
                        __u32 key = UNTRUSTED_TO_DMZ;

                        in4_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                        if (dmzaddr == NULL || dmzaddr == 0)
                            MXDP_V6DROP

                        if (*dmzaddr != iph->daddr)
                            MXDP_V4DROP
                        else
                        {
                            __u32 key = 0;

                            amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                            if (_amasks == NULL)
                                MXDP_V4DROP

                            if (ntohs(_amasks->dmz) > 0 && netV4cmp(dmzaddr, &iph->saddr, ntohs(_amasks->dmz)) == true)
                                MXDP_V4PASS
                        }
                    }

                    MXDP_V4DROP
                }
                else if (iph->protocol == IPPROTO_UDP && ((ntohs(iph->frag_off) >> 8) & 0x20) == 0x00 && (ntohs(iph->frag_off) & 0x01FF) == 0x0000) // Only not Fragmented data are accepted
                {
                    struct udphdr *udph = data + VLAN_ETH_HLEN + sizeof(iph->ihl * 4);

                    // __com001
                    if ((void *)udph + sizeof(*udph) + 1 > data_end)
                        MXDP_V4DROP

                    // udp traceroute
                    if ((htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                    {
                        if (iph->ttl <= 1)
                        {
                            if (iph->daddr == UnTrustedV4[UNTRUSTED_TO_DMZ])
                                return sendV4icmp(ctx, (in4_addr *)&UnTrustedV4[UNTRUSTED_TO_DMZ], ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0); // to use only when packet forwarding
                            else
                                MXDP_V4DROP // udp packet to this device are dropped
                        }
                        else
                            MXDP_V4DROP // udp packet to this device are dropped
                    }
                    else if ((htons(udph->source) > 33433) && (htons(udph->source) < 33626))
                    {
                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                            MXDP_V4PASS
                    }

                    MXDP_V4DROP
                }
                else if (iph->protocol == IPPROTO_ICMP && ((ntohs(iph->frag_off) >> 8) & 0x20) == 0x00 && (ntohs(iph->frag_off) & 0x01FF) == 0x0000)
                    ; // Only not Fragmented data are accepted;
                else
                    MXDP_V4DROP
#ifdef ICMPSTRICT
                __sum16 csum = 0;
                __sum16 rcvcsum = 0;
#endif
                void *n_off = NULL;
                struct icmphdr *icmph = data + VLAN_ETH_HLEN + sizeof(*iph);

                if (icmph + 1 > data_end)
                    MXDP_V4DROP

                if (icmph->type == ICMP_ECHO)
                {
                    if (icmph->code != 0 || (ntohs(iph->tot_len) - sizeof(*iph)) > ICMPV4_MAX_SIZE)
                        MXDP_V4DROP

                    if (UnTrustedV4[UNTRUSTED_TO_DMZ] > 0)
                    {
                        if (iph->daddr != UnTrustedV4[UNTRUSTED_TO_DMZ])
                            MXDP_V4DROP
                    }
                    else // try to fetch map variable if it is already not set as volatile
                    {
                        __u32 key = UNTRUSTED_TO_DMZ;

                        in4_addr *addrV4dmz = bpf_map_lookup_elem(&untrust_v4, &key);

                        if (addrV4dmz && iph->daddr != *addrV4dmz)
                            MXDP_V4DROP
                    }
                }
                else if (icmph->type == ICMP_INFO_REQUEST)
                    MXDP_V4DROP
                else
                {
                    if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                        MXDP_V4PASS
                    else if (icmph->type == ICMP_ECHOREPLY && icmph->code == 0)
                    {
                        __u32 key = 0;
                        amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                        // __com006
                        if (_amasks)
                        {
                            __u32 key = UNTRUSTED_TO_DMZ;

                            in4_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v4, &key);

                            // __com006
                            if (dmzaddr && netV4cmp(dmzaddr, &iph->saddr, ntohs(_amasks->dmz)) == true)
                            {
                                dgn_reply_timer = bpf_ktime_get_ns();
                                MXDP_V4PASS
                            }
                        }
                    }

                    MXDP_V4DROP
                }
            icmpV4reply:
                icmph = data + VLAN_ETH_HLEN + sizeof(*iph);

                if (icmph->type != ICMP_ECHO)
                    return XDP_ABORTED;

                icmplen = ntohs(iph->tot_len) - sizeof(*iph);

                // __com001
                if (data + VLAN_ETH_HLEN + sizeof(*iph) + icmplen > data_end)
                    MXDP_V4DROP

                // __com001
                if (data + VLAN_ETH_HLEN + sizeof(*iph) + sizeof(*icmph) > data_end)
                    MXDP_V4DROP

                n_off = data + VLAN_ETH_HLEN + sizeof(*iph);

                __u32 raddr = 0;
#ifdef ICMPSTRICT
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
                    if (fib_params.ifindex == TxPorts.dmz)
                        iph->ttl = MIPDEFTTL - 1; // traceroute spoofing
                    else
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
#ifdef ICMPSTRICT
                icmph->checksum = rcvcsum;
#endif
                icmph->checksum += 0x0008;

                MXDP_V4TX
            }
            else if (VLAN_SSH_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                if (iph->protocol == IPPROTO_TCP)
                {
                    if (sizeof(*iph) != (iph->ihl * 4))
                        MXDP_V4DROP

                    struct tcphdr *tcph = data + VLAN_ETH_HLEN + sizeof(*iph);

                    // __com001
                    if ((void *)tcph + sizeof(*tcph) > data_end)
                        MXDP_V4DROP

                    // sanity checks needed by the eBPF verifier
                    if ((void *)tcph + sizeof(*tcph) > data_end)
                        MXDP_V4DROP

                    switch (htons(tcph->dest))
                    {
                    case SERVICE_SSH: // __com005
                    {
                        __u32 key = UNTRUSTED_TO_SSH;
                        in4_addr *daddr = bpf_map_lookup_elem(&untrust_v4, &key);

                        if (daddr && iph->daddr == *daddr)
                            return XDP_PASS;
                    }

                        MXDP_V4DROP
                    default:
                        MXDP_V4DROP
                    }
                }
                else if (iph->protocol == IPPROTO_UDP)
                    MXDP_V4DROP

                MXDP_V4PASS
            }
        }
        else if (h_proto == htons(ETH_P_IPV6))
        {
            __u8 *nexthdr = NULL;
            struct frag_hdr *fraghdr = NULL;
            bool nexthdr_routing = false;
            bool nexthdr_dest = false;

            nexthdr = &ip6h->nexthdr;
            l3hdr = data + VLAN_ETH_HLEN + sizeof(*ip6h);

            // Iterate thrown ipv6 extension headers (RFC 8200 https://datatracker.ietf.org/doc/html/rfc8200)
            // Packet with NEXTHDR_NONE should be ignored by hosts, but passed unaltered by routers (not for MiEnRo)
            // Fragmentation cannot be check by MiEnRo because packet must be riassembled (with too many resource) before forward.
            for (__u8 i = 0; i < IPV6_OPT_MAX; i++)
            {
                switch (*nexthdr)
                {
                case NEXTHDR_ROUTING: // Routing header. // Transparent
                    if (nexthdr_routing == false)
                        nexthdr_routing = true;
                    else
                        MXDP_V6DROP;
                case NEXTHDR_DEST: // Destination options header. // Transparent
                    if (*nexthdr == NEXTHDR_DEST)
                    {
                        if (nexthdr_dest == false)
                            nexthdr_dest = true;
                        else
                            MXDP_V6DROP;
                    }

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

                    l3hdr += sizeof(struct frag_hdr);

                    break;
                case NEXTHDR_TCP: // IPPROTO_TCP
                    i = IPV6_OPT_MAX;

                    break;
                default: // therefore include NEXTHDR_NONE, NEXTHDR_HOP, NEXTHDR_ESP, NEXTHDR_AUTH and so on
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

            if (VLAN_DMZ_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                if (ip6h->nexthdr == IPPROTO_TCP)
                {
                    struct tcphdr *tcph = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                    // __com001
                    if (tcph + 1 > data_end)
                        MXDP_V6DROP

                    __u32 key;

                    if (htons(tcph->source) == SERVICE_BGP || htons(tcph->dest) == SERVICE_BGP)
                    {
                        __u32 key = UNTRUSTED_TO_DMZ;

                        struct in6_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                        if (dmzaddr == NULL || dmzaddr->s6_addr[0] == 0)
                            MXDP_V6DROP

                        if (addrV6cmp(dmzaddr, &ip6h->daddr) == false)
                            MXDP_V6DROP
                        else
                        {
                            __u32 key = 0;

                            amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                            if (_amasks == NULL)
                                MXDP_V6DROP

                            if ((_amasks->dmz & 0x00FF) > 0 && netV6cmp(dmzaddr, &ip6h->saddr, (_amasks->dmz & 0x00FF)) == true)
                                MXDP_V6PASS
                        }
                    }

                    MXDP_V6DROP
                }
                else if (ip6h->nexthdr == IPPROTO_UDP)
                {
                    struct udphdr *udph = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                    // __com001
                    if (udph + 1 > data_end)
                        MXDP_V6DROP

                    // udp traceroute
                    if ((htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                    {
                        if (ip6h->hop_limit <= 1)
                        {
                            if (addrV6cmp(&ip6h->daddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_DMZ]) == true)
                                return sendV6icmp(ctx, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_DMZ], ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0); // to use only when packet forwarding
                            else
                                MXDP_V6DROP
                        }
                        else
                            MXDP_V6DROP
                    }
                    else if ((htons(udph->source) > 33433) && (htons(udph->source) < 33626))
                    {
                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                            MXDP_V6PASS
                    }

                    MXDP_V6DROP
                }
                else if (ip6h->nexthdr == IPPROTO_ICMPV6)
                    ;
                else if (fraghdr && *nexthdr == IPPROTO_TCP && ((bpf_ntohs(fraghdr->frag_off) & IPV6_MORE_F) == IPV6_MORE_F || (bpf_ntohs(fraghdr->frag_off) & IPV6_OFFSET) > 0)) // Fragmented data
                {
                    __u32 key = UNTRUSTED_TO_DMZ;

                    struct in6_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                    if (dmzaddr == NULL || dmzaddr->s6_addr[0] == 0)
                        MXDP_V6DROP

                    if (addrV6cmp(dmzaddr, &ip6h->daddr) == false)
                        MXDP_V6DROP
                    else
                    {
                        __u32 key = 0;

                        amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                        if (_amasks == NULL)
                            MXDP_V6DROP

                        if ((_amasks->dmz & 0x00FF) > 0 && netV6cmp(dmzaddr, &ip6h->saddr, (_amasks->dmz & 0x00FF)) == true)
                            MXDP_V6PASS
                    }

                    MXDP_V6DROP
                }
                else
                    MXDP_V6DROP
#ifdef ICMPSTRICT
                __sum16 csum = 0;
                __sum16 rcvcsum = 0;
#endif
                struct in6_addr raddr;
                void *n_off = NULL;
                struct icmp6hdr *icmp6h = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                // __com001
                if (icmp6h + 1 > data_end)
                    MXDP_V6DROP

                if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST)
                {
                    if (icmp6h->icmp6_code != 0 || ntohs(ip6h->payload_len) > ICMPV6_MAX_SIZE)
                        MXDP_V6DROP

                    if (UnTrustedV6[UNTRUSTED_TO_DMZ].s6_addr[0] > 0)
                    {
                        if (addrV6cmp(&ip6h->daddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_DMZ]) == false)
                            MXDP_V6DROP
                    }
                    else // try to fetch map variable if it is already not set as volatile
                    {
                        __u32 key = UNTRUSTED_TO_DMZ;

                        struct in6_addr *addrV6dmz = bpf_map_lookup_elem(&untrust_v6, &key);

                        if (addrV6dmz && addrV6cmp(&ip6h->daddr, addrV6dmz) == false)
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
                            __u8 dmzipV6mask = (_amasks->dmz & 0x00FF);

                            if (dmzipV6mask > 128)
                                XDP_ABORTED;

                            __u32 key = UNTRUSTED_TO_DMZ;

                            struct in6_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                            // __com006
                            if (dmzaddr && dmzaddr->s6_addr[0] > 0 && netV6cmp(dmzaddr, &ip6h->saddr, dmzipV6mask) == true)
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

                    // always permit all remain icmp messages from bgp servers
                    if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                        MXDP_V6PASS
                    else if (icmp6h->icmp6_type == ICMPV6_ECHO_REPLY && icmp6h->icmp6_code == 0)
                    {
                        __u32 key = 0;
                        amasks_t *_amasks = bpf_map_lookup_elem(&amasks, &key);

                        // __com006
                        if (_amasks)
                        {
                            __u32 key = UNTRUSTED_TO_DMZ;
                            struct in6_addr *dmzaddr = bpf_map_lookup_elem(&untrust_v6, &key);

                            // __com006
                            if (dmzaddr && dmzaddr->s6_addr[0] > 0 && netV6cmp(dmzaddr, &ip6h->saddr, (_amasks->dmz & 0x00FF)) == true)
                            {
                                if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                    dgn_reply_timer = bpf_ktime_get_ns();

                                MXDP_V6PASS
                            }
                        }
                    }

                    MXDP_V6DROP
                }
            icmpV6reply:
                icmp6h = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                if (icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST)
                    return XDP_ABORTED;

                icmplen = ntohs(ip6h->payload_len);
                n_off = data + VLAN_ETH_HLEN;
#ifdef ICMPSTRICT
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

                if (fib_params.ifindex == TxPorts.dmz)
                    ip6h->hop_limit = MIPDEFTTL - 1;
                else
                    ip6h->hop_limit = MIPDEFTTL;

                ip6h->saddr = ip6h->daddr;
                ip6h->daddr = raddr;
                icmp6h->icmp6_type = ICMPV6_ECHO_REPLY;
                icmp6h->icmp6_code = 0;
#ifdef ICMPSTRICT
                icmp6h->icmp6_cksum = rcvcsum;
#endif
                icmp6h->icmp6_cksum -= 0x0001; // it may suffice when few changes are made

                MXDP_V6TX
            }
            else if (VLAN_SSH_VID == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
            {
                if (ip6h->nexthdr == IPPROTO_TCP)
                {
                    struct tcphdr *tcph = data + VLAN_ETH_HLEN + sizeof(*ip6h);

                    // __com001
                    if ((void *)tcph + sizeof(*tcph) > data_end)
                        MXDP_V6DROP

                    switch (htons(tcph->dest))
                    {
#ifdef IPV6_SSH
                    case SERVICE_SSH: // __com005
                    {
                        __u32 key = UNTRUSTED_TO_SSH;
                        struct in6_addr *daddr = bpf_map_lookup_elem(&untrust_v6, &key);

                        if (daddr && addrV6cmp(&ip6h->daddr, daddr) == true)
                            return XDP_PASS;
                    }

                        MXDP_V6DROP
#endif
                    default:
                        MXDP_V6DROP
                    }
                }
                else if (ip6h->nexthdr == IPPROTO_UDP)
                    MXDP_V6DROP;

                MXDP_V6PASS
            }
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

SEC("mienro_ctr")
int mienro_ctr_prog(struct xdp_md *ctx)
{
    return mienro_process_packet(ctx, 0);
}

SEC("mienro_ctr_direct")
int mienro_ctr_direct_prog(struct xdp_md *ctx)
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
    bpf_spin_unlock(&_txports->lock);

    bpf_printk("Initialized XDP on ctr interface (cpu %u)", bpf_get_smp_processor_id());
}

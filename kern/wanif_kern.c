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

#define KBUILD_MODNAME "wanforwarder"
#include "common_kern.h"

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
} xdp_wan_tx_ports SEC(".maps");

static __always_inline void init_variables(void);

static __always_inline int mienro_process_packet(struct xdp_md *ctx, u32 flags)
{
    const __u32 ifingress = ctx->ingress_ifindex;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *l3hdr = NULL;
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
    bool intcp_echo_request = false; // __com002

    /*
    * Only for debugging
    *
    __u32 coreid = 0;
    if ((coreid = bpf_get_smp_processor_id()) != core_id)
    {
            bpf_printk("for wan core changed from %u to %u", core_id, coreid);
            core_id = coreid;
    } */

    nh_off = L2_HLEN;

#ifdef TRUNK_PORT
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

        if (data + nh_off > data_end)
        {
            __u32 key = 0;
            update_stats(bpf_map_lookup_elem(&fail_cnt, &key), (ctx->data_end - ctx->data));

            return XDP_DROP;
        }

        __u16 vlan = (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK);

        xdp_stats_t *stats = bpf_map_lookup_elem(&brvlan_wl, &vlan);

        if (stats && bpf_redirect_map(&xdp_wan_tx_ports, TxPorts.lan, 0) == XDP_REDIRECT)
        {
            stats->packets++;
            stats->bytes += (ctx->data_end - ctx->data);

            return XDP_REDIRECT; // Bridged VLAN
        }

        h_proto = l2hdr->h_vlan_encapsulated_proto;
    }
    else
        MXDP_V4ABORTED
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

        if (iph + 1 > data_end || iph->ihl < 5 || iph->ihl > 15)
            MXDP_V4DROP

        // block all traffic forwarded to local addresses because if packet is arrived here, it can reach lan of nas if configured as private (172.16.0.0/12 - RFC 1918)
        if ((iph->daddr & 0x0000F0FF) == 0x000010AC)
            MXDP_V4DROP

        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        //		fib_params.sport		= 0; // see __builtin_memset above
        //		fib_params.dport		= 0; // see __builtin_memset above
        fib_params.tot_len = ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
        fib_params.h_vlan_proto = 0;
        fib_params.h_vlan_TCI = 0;

        // bpf_printk("WAN IF: source %pI4 dest %pI4", &iph->saddr, &iph->daddr); // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
    }
    else if (h_proto == htons(ETH_P_IPV6))
    {
        ip6h = data + nh_off;

        if (ip6h + 1 > data_end)
            MXDP_V6DROP

        // block all traffic forwarded to link-local addresses because if packet is arrived here, it can reach lan of nas if configured as private (fc00::/7 - RFC 1918)
        if ((ip6h->daddr.s6_addr[0] & 0xFE) == 0xFC)
            MXDP_V6DROP

        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.ifindex = ctx->ingress_ifindex;
        fib_params.family = AF_INET6;
        fib_params.flowinfo = *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol = ip6h->nexthdr;
        //		fib_params.sport		= 0; // see __builtin_memset above
        //		fib_params.dport		= 0; // see __builtin_memset above
        fib_params.tot_len = ntohs(ip6h->payload_len);
        *((struct in6_addr *)fib_params.ipv6_src) = ip6h->saddr;
        *((struct in6_addr *)fib_params.ipv6_dst) = ip6h->daddr;
        fib_params.h_vlan_proto = 0;
        fib_params.h_vlan_TCI = 0;

        // bpf_printk("WAN IF: source %pI6 dest %pI6", &ip6h->saddr, &ip6h->daddr); // https://www.kernel.org/doc/html/v4.20/core-api/printk-formats.html
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
            //	if (! bpf_map_lookup_elem(&xdp_wan_tx_ports, &fib_params.ifindex))
            //		MXDP_V4DROP

            // No decrease ttl is needed for simulate single stage router
            // Traffic destined for customers is a lot and the one relating to the nas's private services (e.g. radius) passes through the MiEnRo Controller.
#ifdef TRUNK_PORT
            if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
            else
#else
            if (fib_params.ifindex == TxPorts.lan)
#endif
            {
#ifdef TRUNK_PORT
                if (fib_params.ifindex == TxPorts.lan_xdp)
                    MXDP_V4DROP
                else
                {
                    ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                    if (ifinfo && ifinfo->xdp_idx == TxPorts.lan_xdp)
                    {
                        fib_params.ifindex = ifinfo->xdp_idx;
                        l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid

                        fib_params_urpf4.ipv4_dst = iph->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                            MXDP_V4DROP

                        memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
                        memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

                        if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                            MXDP_V4REDIRECT
                        else
                            MXDP_V4ABORTED
                    }
                }
#else
                fib_params_urpf4.ipv4_dst = iph->saddr;

                if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                    MXDP_V4DROP

                memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
                memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

                if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                    MXDP_V4REDIRECT
                else
                    MXDP_V4ABORTED
#endif
            }
#ifndef TRUNK_PORT
            else if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
#endif
            __u8 icmp4_type = ICMP_DEST_UNREACH;
            __u8 icmp4_code = ICMP_PORT_UNREACH;
            __u8 deltattl = 0;
            in4_addr saddr = 0;
            xdp_stats_t *stats = NULL;
            struct tcphdr *tcph = NULL;
            struct udphdr *udph = NULL;
            __be16 *sport = NULL;
            __be16 *dport = NULL;
            // clang-format off
                                                             /*************
                                                             *FIREWALL ACL*
                                                             *************/
            // clang-format on
            if (iph->protocol == IPPROTO_TCP && (bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Not fragmented data
                tcph = data + L2_HLEN + (iph->ihl * 4);
            else if (iph->protocol == IPPROTO_UDP && (bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Not fragmented data
                udph = data + L2_HLEN + (iph->ihl * 4);
            else if (iph->protocol == IPPROTO_ICMP)
            {
                if ((bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Not fragmented data
                {
                    struct icmphdr *icmph = data + L2_HLEN + sizeof(struct iphdr);

                    if (icmph + 1 > data_end)
                        MXDP_V4DROP

                    if (fib_params.ifindex == TxPorts.dmz)
                    { // handle time exceeded simulating single stage router spoofing traceroute reply.
                        if (iph->ttl < 2)
                        {
                            fib_params_urpf4.ipv4_dst = iph->saddr;

                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                                MXDP_V4DROP

                            icmp4_type = ICMP_TIME_EXCEEDED;
                            icmp4_code = ICMP_EXC_TTL;
                            saddr = UnTrustedV4[UNTRUSTED_TO_LOP];
                            goto v4traceroutereply;
                        }

                        if (icmph->type == ICMP_ECHO)
                        {
                            if (icmph->code != 0 || (ntohs(iph->tot_len) - sizeof(*iph)) > ICMPV4_MAX_SIZE)
                                MXDP_V4DROP

                            if (bpf_map_lookup_elem(&icmp_v4wl, &iph->saddr))
                            {
                                ip_decrease__ttl(iph); // decrease ttl only for dmz interface
                                goto v4redirectfast;
                            }

                            fib_params_urpf4.ipv4_dst = iph->saddr;

                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                                MXDP_V4DROP

                            goto icmpV4reply;
                        }
                        else if (icmph->type == ICMP_INFO_REQUEST)
                            MXDP_V4DROP
                        else
                        {
                            ip_decrease__ttl(iph); // decrease ttl only for dmz interface

                            // forwards all remaining icmp messages from our remote servers
                            if (bpf_map_lookup_elem(&icmp_v4wl, &iph->saddr))
                            { // forwards all remaining icmp messages from monitor servers
                                if (bpf_map_lookup_elem(&mon_v4wl, &iph->saddr) && icmph->type == ICMP_ECHOREPLY && icmph->code == 0 && ((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                    dgn_reply_timer = bpf_ktime_get_ns();

                                goto v4redirectfast;
                            } // forwards all remaining icmp messages only if they are within range ICMP_REPLY_GRANT_TIME
                            else if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                            {
                                fib_params_urpf4.ipv4_dst = iph->saddr;

                                if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                                    MXDP_V4DROP

                                goto v4redirectfast;
                            }
                        }
                    }
                    else if (fib_params.ifindex == TxPorts.ssh && icmph->type == ICMP_ECHO)
                    {
                        // Warning: Only ping reply on echo request can work for Mienro virtual loopback address
                        if (iph->daddr == UnTrustedV4[UNTRUSTED_TO_LOP])
                        {
                            fib_params_urpf4.ipv4_dst = iph->saddr;

                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                                MXDP_V4DROP

                            goto icmpV4reply;
                        }
                    }
                }
                else if (((bpf_ntohs(iph->frag_off) & IPV4_MORE_F) == IPV4_MORE_F || (bpf_ntohs(iph->frag_off) & IPV4_OFFSET) > 0) && // Fragmented data
                    fib_params.ifindex == TxPorts.dmz && bpf_map_lookup_elem(&icmp_v4wl, &iph->saddr))
                { // Fragmented icmp protocol can be forward on to dmz interface only if is coming from trusted servers
                    ip_decrease__ttl(iph); // decrease ttl only for dmz interface
                    goto v4redirectfast;
                }

                MXDP_V4DROP
            }

            if (tcph)
            { // __com001
                if (tcph + 1 > data_end)
                    MXDP_V4DROP

                sport = &tcph->source;
                dport = &tcph->dest;
            }
            else if (udph)
            { // __com001
                if (udph + 1 > data_end)
                    MXDP_V4DROP

                sport = &udph->source;
                dport = &udph->dest;
            }

            if (sport && dport)
            { // handle time exceeded simulating single stage router spoofing traceroute reply.
                if (iph->ttl < 3)
                {
                    fib_params_urpf4.ipv4_dst = iph->saddr;

                    if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                        MXDP_V4DROP

                    if (iph->ttl < 2)
                    {
                        if (fib_params.ifindex == TxPorts.ssh && udph && (htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                        {
                            icmp4_type = ICMP_DEST_UNREACH;
                            icmp4_code = ICMP_PORT_UNREACH;
                            saddr = UnTrustedV4[UNTRUSTED_TO_LOP];
                            goto v4traceroutereply;
                        }
                        else if (fib_params.ifindex == TxPorts.dmz)
                        {
                            icmp4_type = ICMP_TIME_EXCEEDED;
                            icmp4_code = ICMP_EXC_TTL;
                            saddr = UnTrustedV4[UNTRUSTED_TO_LOP];
                            goto v4traceroutereply;
                        }
                    }
                    else if (fib_params.ifindex == TxPorts.dmz)
                    {
                        if (udph && (htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                        {
                            icmp4_type = ICMP_DEST_UNREACH;
                            icmp4_code = ICMP_PORT_UNREACH;
                            saddr = iph->daddr;
                            deltattl = 1;
                            goto v4traceroutereply;
                        }
                    }
                }

                if (fib_params.ifindex == TxPorts.dmz)
                {
                    ip_decrease__ttl(iph); // decrease ttl only for dmz interface

                    // traceroute replies permitted to dmz zone
                    if (udph && (htons(udph->source) > 33433) && (htons(udph->source) < 33626))
                    {
                        fib_params_urpf4.ipv4_dst = iph->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                            MXDP_V4DROP

                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                            goto v4redirectfast;
                    }

                    switch (htons(*sport))
                    {
                    case SERVICE_RADIUS:
                    case SERVICE_RADIUS_ACCT:
                        if ((stats = bpf_map_lookup_elem(&rad_v4wl, &iph->saddr)))
                            goto v4redirect;

                    case SERVICE_DNS:
                    case SERVICE_DNS_S:
                        if ((stats = bpf_map_lookup_elem(&dns_v4wl, &iph->saddr)))
                            goto v4redirect;

                        break;
                    case SERVICE_NTP:
                        if (udph && (stats = bpf_map_lookup_elem(&ntp_v4wl, &iph->saddr)))
                            goto v4redirect;

                        break;
                    case SERVICE_SMTP:
                        if (tcph && (stats = bpf_map_lookup_elem(&mxx_v4wl, &iph->saddr)))
                            goto v4redirect;

                        break;
                    case SERVICE_LOG:
                        if (udph && (stats = bpf_map_lookup_elem(&log_v4wl, &iph->saddr)))
                            goto v4redirect;

                        break;
                    default:
                        if ((stats = bpf_map_lookup_elem(&mon_v4wl, &iph->saddr)))
                            goto v4redirect;

                        break;
                    }
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    if (tcph && htons(*dport) == SERVICE_SSH_CTR && iph->daddr == UnTrustedV4[UNTRUSTED_TO_LOP]) // check if traffic is destinated to controller node loopback address
                    {
                        fib_params_urpf4.ipv4_dst = iph->saddr;
#ifndef TRUNK_PORT
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf4, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS)
                        {
                            if (fib_params_urpf4.ifindex != ifingress)
                                MXDP_V4DROP
                        }
                        else
                            MXDP_V4DROP
#else
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf4, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS) // && fib_params_urpf4.ifindex != ifingress)
                        {
                            ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, (const void *)&fib_params_urpf4.ifindex);

                            if (ifinfo)
                            {
                                if (ifinfo->xdp_idx != TxPorts.wan_xdp || ifinfo->vlan_id != (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
                                    MXDP_V4DROP
                            }
                            else
                                MXDP_V4DROP
                        }
                        else
                            MXDP_V4DROP
#endif
                        if (bpf_map_lookup_elem(&mon_v4wl, &iph->saddr) == NULL) // If ip ssh traffic do not come from a monitor server check if it is blacklisted (timers)
                        {
                            timeo_t *timeo = bpf_map_lookup_elem(&ssh_v4tmo, &iph->saddr);

                            if (timeo && (bpf_ktime_get_ns() / NANOSEC_PER_SEC) < timeo->lastuptime + SSH_DENIED_TIME)
                                MXDP_V4DROP;
                        }

                        goto v4redirectfast;
                    }
                }
            }
            else if ((bpf_ntohs(iph->frag_off) & IPV4_MORE_F) == IPV4_MORE_F || (bpf_ntohs(iph->frag_off) & IPV4_OFFSET) > 0) // Fragmented data
            { // to get the numbers of the ports involved, MiEnRo would have to reassemble the packets first but resources are needed and it is more useful to filter the traffic only by type and trusted ip address.
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    ip_decrease__ttl(iph); // decrease ttl only for dmz interface

                    switch (iph->protocol)
                    {
                    case IPPROTO_TCP:
                        if ((stats = bpf_map_lookup_elem(&tcp_v4wl, &iph->saddr)) && (stats = bpf_map_lookup_elem(&mon_v4wl, &iph->saddr)))
                            goto v4redirect;
                    case IPPROTO_UDP:
                        if ((stats = bpf_map_lookup_elem(&udp_v4wl, &iph->saddr)) && // check if source address is found in map of remote servers
                            (stats = bpf_map_lookup_elem(&mon_v4wl, &iph->saddr)))
                            goto v4redirect;
                    }
                }
                else if (fib_params.ifindex == TxPorts.ssh && iph->protocol == IPPROTO_TCP && iph->daddr == UnTrustedV4[UNTRUSTED_TO_LOP] && // check if traffic is destinated to controller node loopback address
                    bpf_map_lookup_elem(&mon_v4wl, &iph->saddr)) // Only ssh traffic coming from the monitor servers can send to ssh port of controller tcp fragmented data
                    goto v4redirectfast;
            }

            MXDP_V4DROP

        v4redirectfast:
#ifdef TRUNK_PORT
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh)
            {
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }
            }
#else
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh) // incapsulate vlan header on ethernet protocol
            {
                // encapsulate traffic inside vlan
                __s32 headroom = (__s32)sizeof(struct vlan_hdr);

                if (bpf_xdp_adjust_head(ctx, 0 - headroom))
                    MXDP_V4DROP

                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                if (data + VLAN_HDR_SIZE + (ETH_ALEN * 2) + sizeof(u16) + 1 > data_end)
                    MXDP_V4DROP

                // shift on left for VLAN_HDR_SIZE bytes, the mac addrs plus ethertype
                __builtin_memmove(data, data + VLAN_HDR_SIZE, (ETH_ALEN * 2) + sizeof(u16)); // Note: LLVM built-in memmove inlining require size to be constant

                struct vlan_hdr vhdr = { 0 };
                vhdr.h_vlan_TCI = htons((uint16_t)VLAN_SSH_PRIO << VLAN_PRIO_SHIFT);

                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }

                vhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);

                __builtin_memcpy(data + (ETH_ALEN * 2) + sizeof(u16), &vhdr, VLAN_HDR_SIZE);

                l2hdr = data;

                // __com001
                if (l2hdr + 1 > data_end)
                    MXDP_V4DROP

                l2hdr->h_proto = htons(ETH_P_8021Q);
            }
#endif
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

            if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                MXDP_V4REDIRECT
            else
                MXDP_V4ABORTED
        v4redirect:
#ifdef TRUNK_PORT
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh)
            {
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }
            }
#else
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh) // incapsulate vlan header on ethernet protocol
            {
                // encapsulate traffic inside vlan
                __s32 headroom = (__s32)sizeof(struct vlan_hdr);

                if (bpf_xdp_adjust_head(ctx, 0 - headroom))
                    MXDP_V4DROP

                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                if (data + VLAN_HDR_SIZE + (ETH_ALEN * 2) + sizeof(u16) + 1 > data_end)
                    MXDP_V4DROP

                // shift on left for VLAN_HDR_SIZE bytes, the mac addrs plus ethertype
                __builtin_memmove(data, data + VLAN_HDR_SIZE, (ETH_ALEN * 2) + sizeof(u16)); // Note: LLVM built-in memmove inlining require size to be constant

                struct vlan_hdr vhdr = { 0 };
                vhdr.h_vlan_TCI = htons((uint16_t)VLAN_SSH_PRIO << VLAN_PRIO_SHIFT);

                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }

                vhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);

                __builtin_memcpy(data + (ETH_ALEN * 2) + sizeof(u16), &vhdr, VLAN_HDR_SIZE);

                l2hdr = data;

                // __com001
                if (l2hdr + 1 > data_end)
                    MXDP_V4DROP

                l2hdr->h_proto = htons(ETH_P_8021Q);
            }
#endif
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

            if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
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
        v4traceroutereply:

            return sendV4icmp(ctx, &saddr, icmp4_type, icmp4_code, deltattl); // to use only when packet forwarding

            MXDP_V4DROP;
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
            //	if (! bpf_map_lookup_elem(&xdp_wan_tx_ports, &fib_params.ifindex))
            //		MXDP_V6DROP

            // No decrease ttl is needed for simulate single stage router
            // Traffic destined for customers is a lot and the one relating to the nas's private services (e.g. radius) passes through the MiEnRo Controller.
#ifdef TRUNK_PORT
            if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
            else
#else
            if (fib_params.ifindex == TxPorts.lan)
#endif
            {
#ifdef TRUNK_PORT // and mienromonnet up
                if (fib_params.ifindex == TxPorts.lan_xdp)
                    MXDP_V6DROP
                else
                {
                    ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, &fib_params.ifindex);

                    if (ifinfo && ifinfo->xdp_idx == TxPorts.lan_xdp)
                    {
                        fib_params.ifindex = ifinfo->xdp_idx;
                        l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | ifinfo->vlan_id); // alter only vlanid

                        *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                            MXDP_V6DROP

                        memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
                        memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

                        if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                            MXDP_V6REDIRECT
                        else
                            MXDP_V6ABORTED
                    }
                }
#else
                *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                    MXDP_V6DROP

                memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
                memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

                if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                    MXDP_V6REDIRECT
                else
                    MXDP_V6ABORTED
#endif
            }
#ifndef TRUNK_PORT
            else if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                init_variables();
#endif

            __u8 icmp6_type = ICMPV6_DEST_UNREACH;
            __u8 icmp6_code = ICMPV6_PORT_UNREACH;
            __u8 deltattl = 0;
            __u8 *nexthdr = NULL;
            struct frag_hdr *fraghdr = NULL;
            struct in6_addr saddr;
            xdp_stats_t *stats = NULL;
            struct tcphdr *tcph = NULL;
            struct udphdr *udph = NULL;
            bool nexthdr_routing = false;
            bool nexthdr_dest = false;
            __be16 *sport = NULL;
            __be16 *dport = NULL;

            nexthdr = &ip6h->nexthdr;
            l3hdr = data + L2_HLEN + sizeof(*ip6h);

            // Iterate thrown ipv6 extension headers (RFC 8200 https://datatracker.ietf.org/doc/html/rfc8200)
            // Packet with NEXTHDR_NONE should be ignored by hosts, but passed unaltered by routers (not for MiEnRo)
            // Fragmentation cannot be check by MiEnRo because packet must be riassembled (with too many resource) before forward.
            for (__u8 i = 0; i < IPV6_OPT_MAX; i++)
            {
                switch (*nexthdr)
                {
                case NEXTHDR_ESP:
                case NEXTHDR_AUTH:
                    if (fib_params.ifindex == TxPorts.dmz)
                    {
                        nexthdr = l3hdr; // Note: the nexthdr indicator in the Ipv6 Extention header is the first byte

                        // __com001
                        if (nexthdr + 1 > data_end || *nexthdr == NEXTHDR_NONE)
                            MXDP_V6DROP

                        if ((stats = bpf_map_lookup_elem(&vpn_v6wl, &ip6h->saddr))) // forward to ctr also any type of ping
                        {
                            ip6h->hop_limit--; // decrease ttl only for dmz interface

                            goto v6redirect;
                        }
                        else
                            MXDP_V6DROP
                    }
                    else
                        MXDP_V6DROP

                    break;
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

                    l3hdr += sizeof(struct frag_hdr);

                    break;
                case NEXTHDR_TCP: // IPPROTO_TCP
                case NEXTHDR_UDP: // IPPROTO_UDP
                case NEXTHDR_ICMP: // IPPROTO_ICMPV6
                    i = IPV6_OPT_MAX;

                    break;
                default: // therefore include NEXTHDR_NONE, NEXTHDR_HOP
                    MXDP_V6DROP
                }
            }

            // __com001
            if (l3hdr + 1 > data_end)
                MXDP_V6DROP

            // handle time exceeded and no decrease ttl is needed for simulate single stage router
            if (fraghdr == NULL && ip6h->hop_limit < 2)
            {
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                    if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                        MXDP_V6DROP

                    icmp6_type = ICMPV6_TIME_EXCEED;
                    icmp6_code = ICMPV6_EXC_HOPLIMIT;
                    saddr = UnTrustedV6[UNTRUSTED_TO_LOP];
                    goto v6traceroutereply;
                }
            }
            // clang-format off
                                                             /*************
                                                             *FIREWALL ACL*
                                                             *************/
            // clang-format on
            if (fraghdr == NULL && *nexthdr == IPPROTO_TCP)
                tcph = l3hdr;
            else if (fraghdr == NULL && *nexthdr == IPPROTO_UDP)
                udph = l3hdr;
            else if (ip6h->nexthdr == IPPROTO_ICMPV6)
            {
                struct icmp6hdr *icmp6h = l3hdr;

                // __com001
                if (icmp6h + 1 > data_end)
                    MXDP_V6DROP

                if (fib_params.ifindex == TxPorts.dmz)
                {
                    if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST)
                    {
                        if (icmp6h->icmp6_code != 0 || ntohs(ip6h->payload_len) > ICMPV6_MAX_SIZE)
                            MXDP_V6DROP

                        if (bpf_map_lookup_elem(&icmp_v6wl, &ip6h->saddr))
                        {
                            ip6h->hop_limit--; // decrease ttl only for dmz interface
                            goto v6redirectfast;
                        }

                        *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                            MXDP_V6DROP

                        goto icmpV6reply;
                    }
                    else
                    {
                        // all icmpv6 neighbor in forwarding are blocked
                        if (icmp6h->icmp6_type >= NDISC_ROUTER_SOLICITATION && icmp6h->icmp6_type <= NDISC_REDIRECT)
                            ip6h->hop_limit--; // decrease ttl only for dmz interface

                        // forwards all remaining icmp messages from our remote servers
                        if (bpf_map_lookup_elem(&icmp_v6wl, &ip6h->saddr))
                        {
                            if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr) && icmp6h->icmp6_type == ICMPV6_ECHO_REPLY && icmp6h->icmp6_code == 0 && ((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) > ICMP_REPLY_GRANT_TIME)
                                dgn_reply_timer = bpf_ktime_get_ns();

                            goto v6redirectfast;
                        }
                        else if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                        {
                            *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                                MXDP_V6DROP

                            goto v6redirectfast;
                        }
                    }
                }
                else if (fib_params.ifindex == TxPorts.ssh && icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST)
                { // Warning: Only ping reply on echo request can work for Mienro virtual loopback address
                    if (addrV6cmp(&ip6h->daddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP]) == true)
                    {
                        *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                            MXDP_V6DROP

                        goto icmpV6reply;
                    }
                }
            }
            else if (fraghdr && *nexthdr == IPPROTO_ICMPV6 && ((bpf_ntohs(fraghdr->frag_off) & IPV6_MORE_F) == IPV6_MORE_F || (bpf_ntohs(fraghdr->frag_off) & IPV6_OFFSET) > 0)) // Fragmented data
            {
                if (fib_params.ifindex == TxPorts.dmz && bpf_map_lookup_elem(&icmp_v6wl, &ip6h->saddr))
                { // Can be forward to dmz interface only if is coming from trusted servers
                    ip6h->hop_limit--; // decrease ttl only for dmz interface
                    goto v6redirectfast;
                }
            }
            else if (*nexthdr == IPPROTO_ICMPV6 && fraghdr == NULL) // Ipv6 option header without fragmented data
            {
                if (fib_params.ifindex == TxPorts.dmz && bpf_map_lookup_elem(&icmp_v6wl, &ip6h->saddr))
                { // Can be forward to dmz interface only if is coming from trusted servers
                    ip6h->hop_limit--; // decrease ttl only for dmz interface
                    goto v6redirectfast;
                }
            }

            if (tcph)
            { // __com001
                if (tcph + 1 > data_end)
                    MXDP_V6DROP

                sport = &tcph->source;
                dport = &tcph->dest;
            }
            else if (udph)
            { // __com001
                if (udph + 1 > data_end)
                    MXDP_V6DROP

                sport = &udph->source;
                dport = &udph->dest;
            }

            if (sport && dport)
            {
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    // udp traceroute reply
                    if (ip6h->hop_limit < 3)
                    {
                        if (udph && (htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                        {
                            *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                                MXDP_V6DROP

                            saddr = ip6h->daddr;
                            deltattl = 1;
                            goto v6traceroutereply;
                        }
                    }

                    ip6h->hop_limit--; // decrease ttl only for dmz interface

                    switch (htons(*sport))
                    {
                    case SERVICE_RADIUS:
                    case SERVICE_RADIUS_ACCT:
                        if ((stats = bpf_map_lookup_elem(&rad_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    case SERVICE_DNS:
                    case SERVICE_DNS_S:
                        if ((stats = bpf_map_lookup_elem(&dns_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    case SERVICE_NTP:
                        if (udph && (stats = bpf_map_lookup_elem(&ntp_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    case SERVICE_SMTP:
                        if (tcph && (stats = bpf_map_lookup_elem(&mxx_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    case SERVICE_LOG:
                        if (udph && (stats = bpf_map_lookup_elem(&log_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    default:
                        if ((stats = bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    }

                    // traceroute replies permitted to dmz zone
                    if (udph && (htons(udph->source) > 33433) && (htons(udph->source) < 33626))
                    {
                        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                        {
                            *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                                MXDP_V6DROP

                            goto v6redirectfast;
                        }
                    }
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                    // udp traceroute reply
                    if (ip6h->hop_limit < 2)
                    {
                        if (udph && (htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                        {
                            if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                                MXDP_V6DROP

                            saddr = UnTrustedV6[UNTRUSTED_TO_LOP];
                            goto v6traceroutereply;
                        }
                    }
#ifdef IPV6_SSH
                    if (tcph && htons(*dport) == SERVICE_SSH_CTR && addrV6cmp(&ip6h->daddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP]) == true)
                    {
#ifndef TRUNK_PORT
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf6, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS)
                        {
                            if (fib_params_urpf6.ifindex != ifingress)
                                MXDP_V6DROP
                        }
                        else
                            MXDP_V6DROP
#else
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf6, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS) // && fib_params_urpf6.ifindex != ifingress)
                        {
                            ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, (const void *)&fib_params_urpf6.ifindex);

                            if (ifinfo)
                            {
                                if (ifinfo->xdp_idx != TxPorts.wan_xdp || ifinfo->vlan_id != (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
                                    MXDP_V6DROP
                            }
                            else
                                MXDP_V6DROP
                        }
                        else
                            MXDP_V6DROP
#endif
                        if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr) == NULL) // If ipv6 ssh traffic do not come from a monitor server check if it is blacklisted (timers)
                        {
                            timeo_t *timeo = bpf_map_lookup_elem(&ssh_v6tmo, &ip6h->saddr);

                            if (timeo && (bpf_ktime_get_ns() / NANOSEC_PER_SEC) < timeo->lastuptime + SSH_DENIED_TIME)
                                MXDP_V6DROP;
                        }

                        goto v6redirectfast;
                    }
#else
                    if (tcph && htons(*dport) == SERVICE_SSH_CTR && addrV6cmp(&ip6h->daddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP]) == true)
                    {
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf6, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS)
                        {
                            if (fib_params_urpf6.ifindex != ifingress)
                                MXDP_V6DROP
                        }
                        else
                            MXDP_V6DROP

                        if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr) == NULL) // Always permit ipv6 ssh traffic only from a monitor server
                            MXDP_V6DROP;

                        goto v6redirectfast;
                    }
#endif
                }

                MXDP_V6DROP
            }
            else if (fraghdr && ((bpf_ntohs(fraghdr->frag_off) & IPV6_MORE_F) == IPV6_MORE_F || (bpf_ntohs(fraghdr->frag_off) & IPV6_OFFSET) > 0)) // Fragmented data
            { // to get the numbers of the ports involved, MiEnRo would have to reassemble the packets first but resources are needed and it is more useful to filter the traffic only by type and trusted ip address.
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    ip6h->hop_limit--; // decrease ttl only for dmz interface

                    switch (*nexthdr)
                    {
                    case IPPROTO_TCP:
                        if ((stats = bpf_map_lookup_elem(&tcp_v6wl, &ip6h->saddr)) && (stats = bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    case IPPROTO_UDP:
                        if ((stats = bpf_map_lookup_elem(&udp_v6wl, &ip6h->saddr)) && (stats = bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr)))
                            goto v6redirect;

                        MXDP_V6DROP
                    }
                }
                else if (fib_params.ifindex == TxPorts.ssh && *nexthdr == IPPROTO_TCP && addrV6cmp(&ip6h->daddr, (struct in6_addr *)&UnTrustedV6[UNTRUSTED_TO_LOP]) == true && bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr)) // Only monitor servers can send to ssh interface of controller tcp fragmented data
                    goto v6redirectfast;

                MXDP_V6DROP
            }

            MXDP_V6DROP

        v6redirectfast:
#ifdef TRUNK_PORT
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh)
            {
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }
            }
#else
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh) // incapsulate vlan header on ethernet protocol
            {
                // encapsulate traffic inside vlan
                __s32 headroom = (__s32)sizeof(struct vlan_hdr);

                if (bpf_xdp_adjust_head(ctx, 0 - headroom))
                    MXDP_V6DROP

                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                if (data + VLAN_HDR_SIZE + (ETH_ALEN * 2) + sizeof(u16) + 1 > data_end)
                    MXDP_V6DROP

                // shift on left for VLAN_HDR_SIZE bytes, the mac addrs plus ethertype
                __builtin_memmove(data, data + VLAN_HDR_SIZE, (ETH_ALEN * 2) + sizeof(u16)); // Note: LLVM built-in memmove inlining require size to be constant

                struct vlan_hdr vhdr = { 0 };
                vhdr.h_vlan_TCI = htons((uint16_t)VLAN_SSH_PRIO << VLAN_PRIO_SHIFT);

                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }

                vhdr.h_vlan_encapsulated_proto = htons(ETH_P_IPV6);

                __builtin_memcpy(data + (ETH_ALEN * 2) + sizeof(u16), &vhdr, VLAN_HDR_SIZE);

                l2hdr = data;

                // __com001
                if (l2hdr + 1 > data_end)
                    MXDP_V6DROP

                l2hdr->h_proto = htons(ETH_P_8021Q);
            }
#endif
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

            if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
                MXDP_V6REDIRECT
            else
                MXDP_V6ABORTED
        v6redirect:
#ifdef TRUNK_PORT
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh)
            {
                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    l2hdr->h_vlan_TCI = htons((ntohs(l2hdr->h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }
            }
#else
            if (fib_params.ifindex == TxPorts.dmz || fib_params.ifindex == TxPorts.ssh) // incapsulate vlan header on ethernet protocol
            {
                // encapsulate traffic inside vlan
                __s32 headroom = (__s32)sizeof(struct vlan_hdr);

                if (bpf_xdp_adjust_head(ctx, 0 - headroom))
                    MXDP_V6DROP

                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                if (data + VLAN_HDR_SIZE + (ETH_ALEN * 2) + sizeof(u16) + 1 > data_end)
                    MXDP_V6DROP

                // shift on left for VLAN_HDR_SIZE bytes, the mac addrs plus ethertype
                __builtin_memmove(data, data + VLAN_HDR_SIZE, (ETH_ALEN * 2) + sizeof(u16)); // Note: LLVM built-in memmove inlining require size to be constant

                struct vlan_hdr vhdr = { 0 };
                vhdr.h_vlan_TCI = htons((uint16_t)VLAN_SSH_PRIO << VLAN_PRIO_SHIFT);

                if (fib_params.ifindex == TxPorts.dmz)
                {
                    fib_params.ifindex = TxPorts.dmz_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_DMZ_VID); // alter only vlanid
                }
                else if (fib_params.ifindex == TxPorts.ssh)
                {
                    fib_params.ifindex = TxPorts.ssh_xdp;
                    vhdr.h_vlan_TCI = htons((ntohs(vhdr.h_vlan_TCI) & ~VLAN_VID_MASK) | VLAN_SSH_VID); // alter only vlanid
                }

                vhdr.h_vlan_encapsulated_proto = htons(ETH_P_IPV6);

                __builtin_memcpy(data + (ETH_ALEN * 2) + sizeof(u16), &vhdr, VLAN_HDR_SIZE);

                l2hdr = data;

                // __com001
                if (l2hdr + 1 > data_end)
                    MXDP_V6DROP

                l2hdr->h_proto = htons(ETH_P_8021Q);
            }
#endif
            memcpy(l2hdr->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(l2hdr->h_source, fib_params.smac, ETH_ALEN);

            if (bpf_redirect_map(&xdp_wan_tx_ports, fib_params.ifindex, 0) == XDP_REDIRECT)
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
        v6traceroutereply:

            return sendV6icmp(ctx, &saddr, icmp6_type, icmp6_code, deltattl); // to use only when packet forwarding

            MXDP_V6DROP;
        }
    }
    else if (rc == BPF_FIB_LKUP_RET_BLACKHOLE)
        return XDP_DROP; // fast drop and no stats when destination address/network is blackholed
    else if (rc == BPF_FIB_LKUP_RET_UNREACHABLE || // dest is unreachable and can be dropped from OS
        rc == BPF_FIB_LKUP_RET_PROHIBIT) // dest not allowed and can be dropped from OS
    {
        if (h_proto == htons(ETH_P_IP))
        {
            if (update_stats(bpf_map_lookup_elem(&ddos_v4bl, &iph->saddr), (ctx->data_end - ctx->data)) == true)
                ; // __com010
            else
            {
                xdp_stats_t stats;
                stats.packets = 1;
                stats.bytes = (ctx->data_end - ctx->data);
                bpf_map_update_elem(&ddos_v4bl, &iph->saddr, &stats, BPF_EXIST);
            }
        }
        else if (h_proto == htons(ETH_P_IPV6))
        {
            if (update_stats(bpf_map_lookup_elem(&ddos_v6bl, &ip6h->saddr), (ctx->data_end - ctx->data)) == true)
                ; // __com010
            else
            {
                xdp_stats_t stats;
                stats.packets = 1;
                stats.bytes = (ctx->data_end - ctx->data);
                bpf_map_update_elem(&ddos_v6bl, &ip6h->saddr, &stats, BPF_EXIST);
            }
        }

        return XDP_DROP;
    }
    else if (rc == BPF_FIB_LKUP_RET_UNSUPP_LWT || // fwd requires encapsulation
        rc == BPF_FIB_LKUP_RET_FRAG_NEEDED) // fragmentation required to fwd
    {
        if (h_proto == htons(ETH_P_IP))
            MXDP_V4PASS
        else if (h_proto == htons(ETH_P_IPV6))
            MXDP_V6PASS
    }
    else if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) // INPUT_SECTION Note: Only for TCP protocol Fragmented Data is handled
    {
        __be16 icmplen;

        if (h_proto == htons(ETH_P_IP))
        {
            if (iph->protocol == IPPROTO_TCP)
            {
                if ((bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Not fragmented data
                {
                    struct tcphdr *tcph = data + L2_HLEN + (iph->ihl * 4);

                    // __com001
                    if ((void *)tcph + sizeof(*tcph) > data_end)
                        MXDP_V4DROP

                    // Dnat
                    if (htons(tcph->dest) == SERVICE_SSH_CTR)
                    {
                        if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                            init_variables();

                        fib_params_urpf4.ipv4_dst = iph->saddr;
#ifndef TRUNK_PORT
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf4, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS)
                        {
                            if (fib_params_urpf4.ifindex != ifingress)
                                MXDP_V4DROP
                        }
                        else
                            MXDP_V4DROP
#else
                        if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf4, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS) // && fib_params_urpf4.ifindex != ifingress)
                        {
                            ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, (const void *)&fib_params_urpf4.ifindex);

                            if (ifinfo)
                            {
                                if (TxPorts.wan == 0) // INITIALIZATION VOLATILE VARIABLES FOR FORWARDING PACKETS
                                    init_variables();

                                if (ifinfo->xdp_idx != TxPorts.wan_xdp || ifinfo->vlan_id != (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
                                    MXDP_V4DROP
                            }
                            else
                                MXDP_V4DROP
                        }
                        else
                            MXDP_V4DROP
#endif
                        if (bpf_map_lookup_elem(&mon_v4wl, &iph->saddr) == NULL) // If ip ssh traffic do not come from a monitor server check if it is blacklisted (timers)
                        {
                            timeo_t *timeo = bpf_map_lookup_elem(&ssh_v4tmo, &iph->saddr);

                            if (timeo && (bpf_ktime_get_ns() / NANOSEC_PER_SEC) < timeo->lastuptime + SSH_DENIED_TIME)
                                MXDP_V4DROP;
                        }

                        __u32 _csum = 0;

                        streamV4_t in_id_stream = { 0 };
                        in_id_stream.saddr = iph->saddr;
                        in_id_stream.protocol = iph->protocol;
                        in_id_stream.source = tcph->source;

                        streamV4_t *out_id_stream = bpf_map_lookup_elem(&dnat_v4map, &in_id_stream);

                        if (out_id_stream)
                        {
                            if (tcph->syn && (tcph->fin | tcph->rst | tcph->psh | tcph->ack | tcph->urg | tcph->ece | tcph->cwr) == 0) // tcp syn must always received for store the stream id
                            {
                                __u32 key = 0; // 0 -> ipv4 and 1 -> ipv6
                                lock_t *dnatlock = bpf_map_lookup_elem(&dnat_locks, &key);

                                if (dnatlock)
                                { // The LRU maps doesn't support locks, so we use (sparingly) an external lock
                                    bpf_spin_lock(&dnatlock->lock);
                                    out_id_stream->daddr = iph->daddr;
                                    bpf_spin_unlock(&dnatlock->lock);
                                }
                                else
                                    MXDP_V4ABORTED
                            }
                            else if (out_id_stream->daddr != iph->daddr) // look is (statistically) not needed here
                                MXDP_V4DROP
                        }
                        else if (tcph->syn && (tcph->fin | tcph->rst | tcph->psh | tcph->ack | tcph->urg | tcph->ece | tcph->cwr) == 0)
                        {
                            streamV4_t value = { 0 };
                            value.daddr = iph->daddr;
                            bpf_map_update_elem(&dnat_v4map, &in_id_stream, &value, BPF_NOEXIST);
                        }
                        else
                            MXDP_V4DROP

                        const in4_addr daddr = UnTrustedV4[DNAT_TO_LOP];
                        csumV4nat(&iph->check, &iph->daddr, &daddr);
                        csumV4nat(&tcph->check, &iph->daddr, &daddr);
                        iph->daddr = daddr;

                        fib_params.ipv4_dst = iph->daddr;

                        if (bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags) == BPF_FIB_LKUP_RET_SUCCESS) // FORWARD
                            goto v4redirectfast;

                        MXDP_V4DROP
                    }
                    else if (htons(tcph->dest) == SERVICE_SSH)
                    {
                        if (bpf_map_lookup_elem(&mon_v4wl, &iph->saddr))
                            MXDP_V4PASS
                    }
                    else if (htons(tcph->source) == SERVICE_BGP || htons(tcph->dest) == SERVICE_BGP)
                    {
                        ingress_vlan_t *vlaninfo = bpf_map_lookup_elem(&bgpn_v4wl, &iph->saddr); // check if source address is found in map of bgp neighbors

                        if (vlaninfo && vlaninfo->vlan_id == 0x0FFF) // traffic coming from a trusted bgp blacklist server and can pass always
                            MXDP_V4PASS
#ifdef TRUNK_PORT
                        if (vlaninfo && vlaninfo->vlan_id == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK)) // pass only if ingress vlan match
#else
                        if (vlaninfo && vlaninfo->vlan_id == 0)
#endif
                            MXDP_V4PASS
                    }
                }
                else if ((bpf_ntohs(iph->frag_off) & IPV4_MORE_F) == IPV4_MORE_F || (bpf_ntohs(iph->frag_off) & IPV4_OFFSET) > 0) // Fragmented data
                {
                    ingress_vlan_t *vlaninfo = bpf_map_lookup_elem(&bgpn_v4wl, &iph->saddr); // check if source address is found in map of bgp neighbors

                    if (vlaninfo && vlaninfo->vlan_id == 0x0FFF) // traffic coming from a trusted bgp blacklist server and can pass always
                        MXDP_V4PASS
#ifdef TRUNK_PORT
                    if (vlaninfo && vlaninfo->vlan_id == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK)) // pass only if ingress vlan match
#else
                    if (vlaninfo && vlaninfo->vlan_id == 0)
#endif
                        MXDP_V4PASS
                    else if (bpf_map_lookup_elem(&mon_v4wl, &iph->saddr))
                        MXDP_V4PASS
                }

                MXDP_V4DROP
            }
            else if (iph->protocol == IPPROTO_UDP && (bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0) // Only not Fragmented data are accepted
            {
                struct udphdr *udph = data + L2_HLEN + sizeof(struct iphdr);

                // __com001
                if ((void *)udph + sizeof(*udph) + 1 > data_end)
                    MXDP_V4DROP

                // udp traceroute
                if ((htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                {
                    if (iph->ttl <= 1)
                    {
                        fib_params_urpf4.ipv4_dst = iph->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                            MXDP_V4DROP

                        return sendV4icmp(ctx, (in4_addr *)&fib_params.ipv4_dst, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0); // to use only when packet forwarding
                    }
                    else
                        MXDP_V4DROP // udp packet to this device are dropped
                }
                else if ((htons(udph->source) > 33433) && (htons(udph->source) < 33626))
                {
                    if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                    {
                        fib_params_urpf4.ipv4_dst = iph->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                            MXDP_V4DROP

                        MXDP_V4PASS
                    }
                }

                MXDP_V4DROP
            }
            else if (iph->protocol == IPPROTO_ICMP && (bpf_ntohs(iph->frag_off) & (IPV4_MORE_F | IPV4_OFFSET)) == 0x0)
                ; // Only not Fragmented data are accepted
            else
                MXDP_V4DROP
#ifdef ICMPSTRICT
            __sum16 csum = 0;
            __sum16 rcvcsum = 0;
#endif
            void *n_off = NULL;
            struct icmphdr *icmph = data + L2_HLEN + sizeof(*iph);

            if (icmph + 1 > data_end)
                MXDP_V4DROP

            if (icmph->type == ICMP_ECHO)
            {
                if (icmph->code != 0 || (ntohs(iph->tot_len) - sizeof(*iph)) > ICMPV4_MAX_SIZE)
                    MXDP_V4DROP

                fib_params_urpf4.ipv4_dst = iph->saddr;

                if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                    MXDP_V4DROP
            }
            else if (icmph->type == ICMP_INFO_REQUEST)
                MXDP_V4DROP
            else
            { // always permit all remain icmp messages from bgp servers
                if (bpf_map_lookup_elem(&bgpn_v4wl, &iph->saddr))
                    MXDP_V4PASS

                if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                {
                    fib_params_urpf4.ipv4_dst = iph->saddr;

                    if (check_urpf_wan(ctx, (void *)&fib_params_urpf4, flags, ifingress, h_proto) == true)
                        MXDP_V4DROP

                    MXDP_V4PASS
                }

                MXDP_V4DROP
            }
        icmpV4reply:
            icmph = data + L2_HLEN + sizeof(*iph);

            if (icmph->type != ICMP_ECHO)
                return XDP_ABORTED;

            icmplen = ntohs(iph->tot_len) - sizeof(*iph);

            // __com001
            //		if (data + L2_HLEN + sizeof(*iph) + icmplen > data_end)
            //			MXDP_V4DROP

            // __com001
            //		if (data + L2_HLEN + sizeof(*iph) + sizeof(*icmph) > data_end)
            //			MXDP_V4DROP

            n_off = data + L2_HLEN + sizeof(*iph);

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

            if (iph->ttl != MIPDEFTTL || iph->ttl != (MIPDEFTTL - 1))
            {
                if (iph->ttl != (MIPDEFTTL - 1))
                {
                    if (fib_params.ifindex == TxPorts.dmz)
                        iph->ttl = MIPDEFTTL - 1; // traceroute spoofing
                }
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
        else if (h_proto == htons(ETH_P_IPV6))
        {
            __u8 *nexthdr = &ip6h->nexthdr;
            struct frag_hdr *fraghdr = NULL;
            bool nexthdr_routing = false;
            bool nexthdr_dest = false;

            l3hdr = data + L2_HLEN + sizeof(*ip6h);

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

            if (ip6h->nexthdr == IPPROTO_TCP)
            {
                struct tcphdr *tcph = l3hdr;

                // __com001
                if (tcph + 1 > data_end)
                    MXDP_V6DROP

                // Dnat
                if (htons(tcph->dest) == SERVICE_SSH_CTR)
                {
                    if (TxPorts.wan == 0)
                        init_variables();

                    *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;
#ifdef IPV6_SSH
#ifndef TRUNK_PORT
                    if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf6, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS)
                    {
                        if (fib_params_urpf6.ifindex != ifingress)
                            MXDP_V6DROP
                    }
                    else
                        MXDP_V6DROP
#else
                    if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf6, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS) // && fib_params_urpf6.ifindex != ifingress)
                    {
                        ifidx_t *ifinfo = bpf_map_lookup_elem(&ifidx_map, (const void *)&fib_params_urpf6.ifindex);

                        if (ifinfo)
                        {
                            if (ifinfo->xdp_idx != TxPorts.wan_xdp || ifinfo->vlan_id != (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK))
                                MXDP_V6DROP
                        }
                        else
                            MXDP_V6DROP
                    }
                    else
                        MXDP_V6DROP
#endif
                    if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr) == NULL) // If ipv6 ssh traffic do not come from a monitor server check if it is blacklisted (timers)
                    {
                        timeo_t *timeo = bpf_map_lookup_elem(&ssh_v6tmo, &ip6h->saddr);

                        if (timeo && (bpf_ktime_get_ns() / NANOSEC_PER_SEC) < timeo->lastuptime + SSH_DENIED_TIME)
                            MXDP_V6DROP;
                    }
#else
                    if (bpf_fib_lookup(ctx, (struct bpf_fib_lookup *)&fib_params_urpf6, sizeof(struct bpf_fib_lookup), flags) == BPF_FIB_LKUP_RET_SUCCESS)
                    {
                        if (fib_params_urpf6.ifindex != ifingress)
                            MXDP_V6DROP
                    }
                    else
                        MXDP_V6DROP

                    if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr) == NULL) // Always permit ipv6 ssh traffic only from a monitor server
                        MXDP_V6DROP;
#endif
                    __u32 _csum = 0;

                    streamV6_t in_id_stream = { 0 };
                    in_id_stream.saddr = (struct in6_addr) { .s6_addr32[0] = ip6h->saddr.s6_addr32[0], .s6_addr32[1] = ip6h->saddr.s6_addr32[1], .s6_addr32[2] = ip6h->saddr.s6_addr32[2], .s6_addr32[3] = ip6h->saddr.s6_addr32[3] };
                    in_id_stream.nexthdr = ip6h->nexthdr;
                    in_id_stream.source = tcph->source;

                    streamV6_t *out_id_stream = bpf_map_lookup_elem(&dnat_v6map, &in_id_stream);

                    if (out_id_stream)
                    {
                        if (tcph->syn && (tcph->fin | tcph->rst | tcph->psh | tcph->ack | tcph->urg | tcph->ece | tcph->cwr) == 0) // tcp syn must always received for store the stream id
                        {
                            __u32 key = 0; // 0 -> ipv4 and 1 -> ipv6
                            lock_t *dnatlock = bpf_map_lookup_elem(&dnat_locks, &key);

                            if (dnatlock)
                            { // The LRU maps doesn't support locks, so we use (sparingly) an external lock
                                bpf_spin_lock(&dnatlock->lock);
                                // clang-format off
                                out_id_stream->daddr = (struct in6_addr) { .s6_addr32[0] = ip6h->daddr.s6_addr32[0],
                                                                           .s6_addr32[1] = ip6h->daddr.s6_addr32[1],
                                                                           .s6_addr32[2] = ip6h->daddr.s6_addr32[2],
                                                                           .s6_addr32[3] = ip6h->daddr.s6_addr32[3] };
                                // clang-format on
                                bpf_spin_unlock(&dnatlock->lock);
                            }
                            else
                                MXDP_V6ABORTED
                        }
                        else if (!addrV6cmp(&ip6h->daddr, (struct in6_addr *)&out_id_stream->daddr)) // look is (statistically) not needed here
                            MXDP_V4DROP
                    }
                    else if (tcph->syn && (tcph->fin | tcph->rst | tcph->psh | tcph->ack | tcph->urg | tcph->ece | tcph->cwr) == 0)
                    {
                        streamV6_t value = { 0 };
                        value.daddr = (struct in6_addr) { .s6_addr32[0] = ip6h->daddr.s6_addr32[0], .s6_addr32[1] = ip6h->daddr.s6_addr32[1], .s6_addr32[2] = ip6h->daddr.s6_addr32[2], .s6_addr32[3] = ip6h->daddr.s6_addr32[3] };
                        bpf_map_update_elem(&dnat_v6map, &in_id_stream, &value, BPF_NOEXIST);
                    }
                    else
                        MXDP_V6DROP

                    // clang-format off
                    const struct in6_addr daddr = (struct in6_addr) { .s6_addr32[0] = UnTrustedV6[DNAT_TO_LOP].s6_addr32[0],
                                                                      .s6_addr32[1] = UnTrustedV6[DNAT_TO_LOP].s6_addr32[1],
                                                                      .s6_addr32[2] = UnTrustedV6[DNAT_TO_LOP].s6_addr32[2],
                                                                      .s6_addr32[3] = UnTrustedV6[DNAT_TO_LOP].s6_addr32[3] };
                    // clang-format on
                    // perform a checksum and copy daddr in ip6h->daddr
                    csumV6nat(&tcph->check, &ip6h->daddr, &daddr);

                    *((struct in6_addr *)fib_params.ipv6_dst) = ip6h->daddr;

                    if (bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags) == BPF_FIB_LKUP_RET_SUCCESS) // FORWARD
                        goto v6redirectfast;
                }
                else if (htons(tcph->dest) == SERVICE_SSH)
                { // dnat
                    if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr))
                        MXDP_V6PASS
                }
                else if (htons(tcph->source) == SERVICE_BGP || htons(tcph->dest) == SERVICE_BGP)
                {
                    ingress_vlan_t *vlaninfo = bpf_map_lookup_elem(&bgpn_v6wl, &ip6h->saddr); // check if source address is found in map of bgp neighbors

                    if (vlaninfo && vlaninfo->vlan_id == 0x0FFF) // traffic coming from a trusted bgp blacklist server and can pass always
                        MXDP_V6PASS
#ifdef TRUNK_PORT
                    if (vlaninfo && vlaninfo->vlan_id == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK)) // pass only if ingress vlan match
#else
                    if (vlaninfo && vlaninfo->vlan_id == 0)
#endif
                        MXDP_V6PASS
                }
            }
            else if (ip6h->nexthdr == IPPROTO_UDP)
            {
                struct udphdr *udph = data + L2_HLEN + sizeof(*ip6h);

                // __com001
                if (udph + 1 > data_end)
                    MXDP_V6DROP

                // udp traceroute
                if ((htons(udph->dest) > 33433) && (htons(udph->dest) < 33626))
                {
                    if (ip6h->hop_limit <= 1)
                    {
                        *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                            MXDP_V6DROP

                        return sendV6icmp(ctx, (struct in6_addr *)&fib_params.ipv6_dst, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0); // to use only when packet forwarding
                    }
                    else
                        MXDP_V6DROP
                }
                else if ((htons(udph->source) > 33433) && (htons(udph->source) < 33626))
                {
                    if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                    {
                        *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                        if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                            MXDP_V6DROP

                        MXDP_V6PASS
                    }
                }

                MXDP_V6DROP
            }
            else if (ip6h->nexthdr == IPPROTO_ICMPV6)
                ;
            else if (fraghdr && *nexthdr == IPPROTO_TCP && ((bpf_ntohs(fraghdr->frag_off) & IPV6_MORE_F) == IPV6_MORE_F || (bpf_ntohs(fraghdr->frag_off) & IPV6_OFFSET) > 0)) // Fragmented data
            {
                ingress_vlan_t *vlaninfo = bpf_map_lookup_elem(&bgpn_v6wl, &ip6h->saddr); // check if source address is found in map of bgp neighbors

                if (vlaninfo && vlaninfo->vlan_id == 0x0FFF) // traffic coming from a trusted bgp blacklist server and can pass always
                    MXDP_V6PASS
#ifdef TRUNK_PORT
                if (vlaninfo && vlaninfo->vlan_id == (ntohs(l2hdr->h_vlan_TCI) & VLAN_VID_MASK)) // pass only if ingress vlan match
#else
                if (vlaninfo && vlaninfo->vlan_id == 0)
#endif
                    MXDP_V6PASS
                else if (bpf_map_lookup_elem(&mon_v6wl, &ip6h->saddr)) // monitor traffic to ssh can pass if only come from remote monitor server address
                    MXDP_V6PASS
            }
            else
                MXDP_V6DROP
#ifdef ICMPSTRICT
            __sum16 csum = 0;
            __sum16 rcvcsum = 0;
#endif
            struct in6_addr raddr;
            void *n_off = NULL;
            struct icmp6hdr *icmp6h = data + L2_HLEN + sizeof(*ip6h);

            // __com001
            if (icmp6h + 1 > data_end)
                MXDP_V6DROP

            if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST)
            {
                if (icmp6h->icmp6_code != 0 || ntohs(ip6h->payload_len) > ICMPV6_MAX_SIZE)
                    MXDP_V6DROP

                *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                    MXDP_V6DROP
            }
            else
            {
                switch (icmp6h->icmp6_type)
                {
                case NDISC_NEIGHBOUR_SOLICITATION:
                case NDISC_NEIGHBOUR_ADVERTISEMENT:
                    return XDP_PASS; // __com004
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
                if (bpf_map_lookup_elem(&bgpn_v6wl, &ip6h->saddr))
                    MXDP_V6PASS

                // always permit all remain icmp messages only if enabled via controller
                if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
                {
                    *((struct in6_addr *)fib_params_urpf6.ipv6_dst) = ip6h->saddr;

                    if (check_urpf_wan(ctx, (void *)&fib_params_urpf6, flags, ifingress, h_proto) == true)
                        MXDP_V6DROP

                    MXDP_V6PASS
                }

                MXDP_V6DROP
            }
        icmpV6reply:
            icmp6h = data + L2_HLEN + sizeof(*ip6h);

            if (icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST)
                return XDP_ABORTED;

            // __com001
            // if (icmp6h + 1 > data_end)
            //	MXDP_V6DROP

            icmplen = ntohs(ip6h->payload_len);
            n_off = data + L2_HLEN;
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

SEC("mienro_wan")
int mienro_wan_prog(struct xdp_md *ctx)
{
    return mienro_process_packet(ctx, 0);
}

SEC("mienro_wan_direct")
int mienro_wan_direct_prog(struct xdp_md *ctx)
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

    struct in6_addr *addrV6lop = bpf_map_lookup_elem(&untrust_v6, &key);

    if (addrV6lop == NULL)
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
    UnTrustedV6[UNTRUSTED_TO_LOP] = (struct in6_addr) { .s6_addr32[0] = addrV6lop->s6_addr32[0], .s6_addr32[1] = addrV6lop->s6_addr32[1], .s6_addr32[2] = addrV6lop->s6_addr32[2], .s6_addr32[3] = addrV6lop->s6_addr32[3] };

    TxPorts.wan = _txports->wan;
    TxPorts.wan_xdp = _txports->wan_xdp;
    TxPorts.ssh = _txports->ssh;
    TxPorts.ssh_xdp = _txports->ssh_xdp;
    TxPorts.dmz = _txports->dmz;
    TxPorts.dmz_xdp = _txports->dmz_xdp;
    TxPorts.lan = _txports->lan;
    TxPorts.lan_xdp = _txports->lan_xdp;

    __builtin_memset((void *)&fib_params_urpf4, 0, sizeof(struct bpf_fib_lookup));
    fib_params_urpf4.ifindex = _txports->wan;
    fib_params_urpf4.family = AF_INET;

    __builtin_memset((void *)&fib_params_urpf6, 0, sizeof(struct bpf_fib_lookup));
    fib_params_urpf6.ifindex = _txports->wan;
    fib_params_urpf6.family = AF_INET6;
    bpf_spin_unlock(&_txports->lock);

    bpf_printk("Initialized XDP on wan interface (cpu %u)", bpf_get_smp_processor_id());
}

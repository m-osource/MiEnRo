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

/* Warning: Only pure C language is supported in this header */
#ifndef __COMMON_KERN_INCLUDED_H
#define __COMMON_KERN_INCLUDED_H
#include <uapi/linux/bpf.h>
#include <uapi/linux/icmp.h>
// #include <uapi/linux/if_vlan.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/ip.h>
#include <net/ipv6.h> // struct frag_hdr
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "common_maps.h"

#define IPV6_FLOWINFO_MASK cpu_to_be32(0x0FFFFFFF)
#define VLAN_HDR_SIZE 4
#define VLAN_PRIO_MASK 0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT 13
#define VLAN_CFI_MASK 0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT VLAN_CFI_MASK
#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
#define VLAN_N_VID 4096
#define VLAN_SSH_VID 4094
#define VLAN_DMZ_VID 4093

#ifndef TRUNK_PORT
#define VLAN_SSH_PRIO 3
#endif

#define STRICT
// #define MIPDEFTTL IPDEFTTL
#define MIPDEFTTL 255
#define ICMPSTRICT // it activate icmp integrity verification. Keep in mind that it also increase bpf complexity code (see BPF_COMPLEXITY_LIMIT_INSNS patch if needed) though.
#define ICMP_DEFAULT_SIZE 64 // standard size of icmp
#define ICMPV4_MAX_SIZE 1480 // DON'T TOUCH THIS VALUE (size of icmpv4 header plus data) for OpenBSD Emulation
// #define ICMPV4_MAX_SIZE 1480 // DON'T TOUCH THIS VALUE (size of icmpv4 header plus data)
#define ICMPV4_DSTUNREACH_SIZE 98
#define ICMPV4_DSTUNREACH_PAYLOAD_SIZE 92
#define ICMPV6_MAX_SIZE 1240 // DON'T TOUCH THIS VALUE (size of icmpv6 header plus data) for OpenBSD Emulation
// #define ICMPV6_MAX_SIZE 1460 // DON'T TOUCH THIS VALUE (size of icmpv6 header plus data)
#define ICMPV6_TIMEX_SIZE 98
#define ICMPV6_TIMEX_PAYLOAD_SIZE 92
#define ICMP_REPLY_GRANT_TIME 3600
#define SSH_SERVER_V4ADDR 4278167744 // 192.168.255.254
#define SSH_SERVER_V6ADDR                             \
    {                                                 \
        429496729, 4294967295, 4294967295, 4278189855 \
    } // fcff:ffff:ffff:ffff:ffff:ffff:1fff:fffe
#define SSH_DENIED_TIME 30 // TODO must be changed with thougth setup (array MAP)

#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
            ##__VA_ARGS__);                        \
    })
#else
#define bpf_debug(fmt, ...) \
    {                       \
    }                       \
    while (0)
#endif

// diagnostic reply timer: enable reply for diagnostic protocol (eg: icmp or traceroute)
static volatile u64 dgn_reply_timer = 0;

static __always_inline int ip_decrease__ttl(struct iphdr *);
static __always_inline void swap_src_dst_mac(void *);
static __always_inline __u16 csum_fold_helper(__u32);
static __always_inline void ipv4_csum(void *, int, __u32 *);
static __always_inline bool addrV6cmp(struct in6_addr *, struct in6_addr *);
static __always_inline bool update_stats(xdp_stats_t *, size_t);
static __always_inline int icmpV4parse(struct xdp_md *, void *, void *);
static __always_inline int icmpV6parse(struct xdp_md *, void *, void *);
static __always_inline __sum16 fold_csum(__u32);
static __always_inline __sum16 recalc_csum16(__u16, __u16, __u16);
static __always_inline void csumV4nat(__u16 *, in4_addr *, const in4_addr *);
static __always_inline void csumV6nat(__u16 *, struct in6_addr *, const struct in6_addr *);
static __always_inline __sum16 icmpV4csum(void *, void *, __be16);
static __always_inline __sum16 icmpV6csum(void *, void *, const __be16);
static __always_inline int send_icmp4(struct xdp_md *, in4_addr *, const __u8, const __u8);
static __always_inline int sendV4icmp(struct xdp_md *, in4_addr *, const __u8, const __u8, __u8);
static __always_inline int send_icmp6(struct xdp_md *, struct in6_addr *, const __u8, const __u8);
static __always_inline int sendV6icmp(struct xdp_md *, struct in6_addr *, const __u8, const __u8, __u8);
// Firewall Functions Layer 4 - nostate -
// static __always_inline bool bgppeer_ck(void *, u16 *, void *);
static __always_inline bool check__urpf(struct xdp_md *, struct bpf_fib_lookup *, u32, const __u32);
// static __always_inline bool check_v4acl(struct xdp_md *, void *, void *, void *, void *, void *); // deprecated
// static __always_inline bool check_v6acl(struct xdp_md *, void *, void *, void *, void *, void *); // deprecated
// static __always_inline bool ipv4_acl(__u32 *);
static __always_inline bool netV4cmp(in4_addr *, in4_addr *, __u8);
static __always_inline bool netV6cmp(struct in6_addr *, struct in6_addr *, __u8);
static __always_inline __u8 bitcomposer(__u8);

/* from include/net/ip.h */
static __always_inline int ip_decrease__ttl(struct iphdr *iph)
{
    u32 check = (__force u32)iph->check;

    check += (__force u32)htons(0x0100);
    iph->check = (__force __sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

static __always_inline void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void ipv4_csum(void *data_start, int data_size, __u32 *csum)
{
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);

    // *csum = csum_fold_helper(*csum); // unstable because it return random BAD ip checksum
    for (__u16 i = 0; i < 2048 && (*csum >> 16) > 0; i++)
        *csum = (*csum & 0xffff) + (*csum >> 16);
}

//
// Name: addrV6cmp
//
// Description: compare two ipv6 addr
//
// Input:
//  A - the address to compare
//  B - the address to compare
//
// Output:
//
// Return: true if both are equals
//
static __always_inline bool addrV6cmp(struct in6_addr *A, struct in6_addr *B)
{
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++)
        if (A->s6_addr32[i] != B->s6_addr32[i])
            return false;

    return true;
}

/*
// Name: bgppeer_ck
//
// Description: check bgp servers (provider and blacklist sharing) can communicate with this router
//
// Input:
//
// Output:
//
// Return: true if whitelist rule exists and they are in the same
//
static __always_inline bool bgppeer_ck(void *bgpn_wl, u16 *h_proto, void *hdr)
{
        if (*h_proto == htons(ETH_P_IP))
        {
                struct iphdr *iph = (struct iphdr *)hdr;

                in4_addr *daddr = bpf_map_lookup_elem(bgpn_wl, &iph->saddr);

                if (daddr && iph->daddr == *daddr) // it is a bgp peer's provider
                        return true;
        }
        else if (*h_proto == htons(ETH_P_IPV6))
        {
                struct ipv6hdr *ip6h = (struct ipv6hdr *)hdr;

                struct in6_addr *daddr = bpf_map_lookup_elem(bgpn_wl, &ip6h->saddr);

                if (daddr && (addrV6cmp(daddr, &ip6h->daddr) == true)) // if found and target address concide with interface local address, then pass
                        return true;
        }

        return true;
} */

//
// Name: update_stats
//
// Description: update stats counters in maps
//
// Input:
//  stats - the data to update
//  pktsize - the size of full packet
//
// Output:
//
// Return: true if key exists
//
static __always_inline bool update_stats(xdp_stats_t *stats, size_t pktsize)
{
    if (stats)
    { // Don't need __sync_fetch_and_add(); as percpu map
        stats->packets++;
        stats->bytes += pktsize;

        return true;
    }

    return false;
}

//
// Name: icmpV4parse
//
// Description: parse packet for icmp protocols and do some __com001
//
// Input:
//  ctx - the pointer to context
//  untrust_V4 - map of ipv4 local addresses
//  amasks - mop of cidr of addresses
//
// Output:
//
// Return: XDP_TX if echo request
//
static __always_inline int icmpV4parse(struct xdp_md *ctx, void *untrust_V4, void *amasks)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct vlan_ethhdr *l2hdr = data;

    // __com001
    if (data + sizeof(*l2hdr) > data_end)
        return XDP_DROP; // __com011

    struct icmphdr *icmph;
    struct iphdr *iph;

    iph = data + sizeof(*l2hdr);

    if (data + sizeof(*l2hdr) + sizeof(*iph) > data_end)
        MXDP_V4DROP

    if (iph->protocol != IPPROTO_ICMP)
        MXDP_V4DROP

    icmph = data + sizeof(*l2hdr) + sizeof(*iph);

    if (icmph + 1 > data_end)
        MXDP_V4DROP

    // unsupported icmp request with fragmented data
    if (icmph->type == ICMP_ECHO && icmph->code == 0)
        return XDP_TX; // handle at the exit function
    else if (icmph->type == ICMP_ECHOREPLY && icmph->code == 0)
    {
        //		if ... // TODO
        //			MXDP_V6PASS
        //		else
        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
            MXDP_V4PASS

        __u32 key = 0;
        amasks_t *_amasks = bpf_map_lookup_elem(amasks, &key);

        // __com006
        if (_amasks)
        {
            __u32 key = UNTRUSTED_TO_WAN;

            in4_addr *wanaddr = bpf_map_lookup_elem(untrust_V4, &key);

            // __com006
            if (wanaddr && netV4cmp(wanaddr, &iph->saddr, ntohs(_amasks->wan)) == true)
                MXDP_V4PASS
        }
    }

    MXDP_V4DROP
}

//
// Name: icmpV6parse
//
// Description: parse packet for icmp protocols and do some __com001
//
// Input:
//  ctx - the pointer to context
//  untrust_V6 - map of ipv6 local addresses
//  amasks - mop of cidr of addresses
//
// Output:
//
// Return: XDP_TX if echo request
//
static __always_inline int icmpV6parse(struct xdp_md *ctx, void *untrust_V6, void *amasks)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct vlan_ethhdr *l2hdr = data;

    // __com001
    if (data + sizeof(*l2hdr) > data_end)
        return XDP_DROP; // __com011

    struct icmp6hdr *icmp6h;
    struct ipv6hdr *ip6h;

    ip6h = data + sizeof(*l2hdr);

    if (data + sizeof(*l2hdr) + sizeof(*ip6h) > data_end)
        MXDP_V6DROP

    if (ip6h->nexthdr != IPPROTO_ICMPV6)
        MXDP_V6DROP

    icmp6h = data + sizeof(*l2hdr) + sizeof(*ip6h);

    if (icmp6h + 1 > data_end)
        MXDP_V6DROP

    if (icmp6h->icmp6_type == ICMPV6_ECHO_REQUEST && icmp6h->icmp6_code == 0) // __com009
        return XDP_TX; // handle at the exit function
    else if (icmp6h->icmp6_type == ICMPV6_ECHO_REPLY && icmp6h->icmp6_code == 0)
    {
        //		if ... // TODO
        //			MXDP_V6PASS
        //		else
        if (((bpf_ktime_get_ns() - dgn_reply_timer) / NANOSEC_PER_SEC) <= ICMP_REPLY_GRANT_TIME)
            MXDP_V6PASS

        __u32 key = 0;
        amasks_t *_amasks = bpf_map_lookup_elem(amasks, &key);

        // __com006
        if (_amasks)
        {
            __u32 key = UNTRUSTED_TO_WAN;

            struct in6_addr *wanaddr = bpf_map_lookup_elem(untrust_V6, &key);

            // __com006
            if (wanaddr && wanaddr->s6_addr[0] > 0 && netV6cmp(wanaddr, &ip6h->saddr, (_amasks->wan & 0x00FF)) == true)
                MXDP_V6PASS
        }

        MXDP_V6DROP
    }
    else if (icmp6h->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION || icmp6h->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT)
    {
        if (icmp6h->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION && l2hdr->h_dest[0] == 0x33 && l2hdr->h_dest[1] == 0x33 && ip6h->daddr.s6_addr32[0] == 0x000002FF && ip6h->daddr.s6_addr32[1] == 0x00000000 && ip6h->daddr.s6_addr32[2] == 0x01000000 && ip6h->daddr.s6_addr32[3] >= 0x000000FF && ip6h->daddr.s6_addr32[3] <= 0xFFFFFFFF) // __com007
            MXDP_V6PASS
        else if ((ip6h->saddr.s6_addr16[0] & 0xC0FF) == 0x80FE || (ip6h->daddr.s6_addr16[0] & 0xC0FF) == 0x80FE) // icmpv6 neighbour messages must be received also via link-local addresses
            MXDP_V6PASS
        else
        {
            __u32 key = 0;
            amasks_t *_amasks = bpf_map_lookup_elem(amasks, &key);

            // __com006
            if (_amasks)
            {
                __u8 wanipV6mask = (_amasks->wan & 0x00FF);

                if (wanipV6mask > 128)
                    MXDP_V6ABORTED;

                __u32 key = UNTRUSTED_TO_WAN;

                struct in6_addr *wanaddr = bpf_map_lookup_elem(untrust_V6, &key);

                // __com006
                if (wanaddr && wanaddr->s6_addr[0] > 0 && netV6cmp(wanaddr, &ip6h->saddr, wanipV6mask) == true)
                    MXDP_V6PASS
            }
        }
    }
    else if (icmp6h->icmp6_type == NDISC_ROUTER_SOLICITATION || icmp6h->icmp6_type == NDISC_ROUTER_ADVERTISEMENT || icmp6h->icmp6_type == NDISC_REDIRECT)
        MXDP_V6PASS

    MXDP_V6DROP
}

//
// Name: recalc_csum16
//
// Description: do a checksum corresponding to 'partial', which is a value updated
//
// Input:
//  partial_csum
//
// Output:
//
// Return: the new checksum
//
static __always_inline __sum16 fold_csum(__u32 partial_csum)
{
    static const __u8 max_fold = 4;

    // #pragma clang loop unroll(full)
    for (__u8 i = 0; i < max_fold; i++)
        if (partial_csum >> 16)
            partial_csum = (partial_csum & 0xffff) + (partial_csum >> 16);
        else
            break;

    return ~partial_csum;
}

//
// Name: recalc_csum16
//
// Description: do a checksum for a packet in which the checksum field previously contained 'old_csum' and in which a field that contained 'old_u16' was changed to contain 'new_u16'.
//
// Input:
//
// Output:
//
// Return: the new checksum
//
static __always_inline __u16 recalc_csum16(__u16 old_csum, __u16 old_u16, __u16 new_u16)
{
    // Ones-complement arithmetic is endian-independent, so this code does not
    // use htons() or ntohs().

    // See RFC 1624 for formula and explanation.
    __u16 hc_complement = ~old_csum;
    __u16 m_complement = ~old_u16;
    __u16 m_prime = new_u16;
    __u32 sum = hc_complement + m_complement + m_prime;
    return fold_csum(sum);
}

//
// Name: recalc_csum16
//
// Description: do a checksum for a packet in which the checksum field previously contained 'old_csum' and in which a field that contained 'old_u16' was changed to contain 'new_u16'.
//
// Input:
//
// Output:
//
// Return: the new checksum
//
static __always_inline void csumV4nat(__u16 *csum, in4_addr *addr, const in4_addr *natto)
{
    __u16 *pold = (__u16 *)addr;
    __u16 *pnew = (__u16 *)natto;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 2; i++)
        *csum = recalc_csum16(*csum, *(pold++), *(pnew++));
}

//
// Name: recalc_csum16
//
// Description: do a checksum for a packet in which the checksum field previously contained 'old_csum' and in which a field that contained 'old_u16' was changed to contain 'new_u16'.
//
// Input:
//
// Output:
//
// Return: the new checksum
//
static __always_inline void csumV6nat(__u16 *csum, struct in6_addr *addr, const struct in6_addr *natto)
{
#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 8; i++)
    {
        *csum = recalc_csum16(*csum, addr->s6_addr16[i], natto->s6_addr16[i]);
        addr->s6_addr16[i] = natto->s6_addr16[i];
    }
}

//
// Name: icmpV4csum
//
// Description: perform a icmp fast checksum (64 bits) icmp packet
//
// Input:
//  n_off - pointer to icmp4 header start
//  data_end - pointer to end of buffer
//  icmplen - icmp length as declared inside ip header
//
// Output:
//
// Return: the checksum value or set to 0 if error occurred
//
static __always_inline __sum16 icmpV4csum(void *n_off, void *data_end, __be16 icmplen)
{ // __com001
    if (n_off + 1 > data_end)
        return 0;

    __u64 *n_off_u64 = (__u64 *)n_off;
    __u64 sum_u64 = 0;
    __u32 t1, t2;
    __u16 t3, t4;

    // __com001
    if (icmplen > ICMPV4_MAX_SIZE)
        return 0;

    if (icmplen == ICMP_DEFAULT_SIZE) // csum 64 bits
    { // __com001
        if (n_off_u64 + (icmplen / sizeof(__u64)) > data_end)
            return 0;

#pragma clang loop unroll_count(ICMP_DEFAULT_SIZE / sizeof(__u64))
        for (__u32 i = 0; i < icmplen; i += sizeof(__u64))
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }
    }
    else if (icmplen == sizeof(struct icmphdr)) // for zero payload data perform a csum conventional 16 bits (RFC 1071)
    {
        __u16 *n_off_u16 = (__u16 *)n_off;
        __u32 sum_u32 = 0;

#pragma clang loop unroll(full)
        for (__s32 i = 0; i < sizeof(struct icmphdr); i += sizeof(__u16))
            sum_u32 += *n_off_u16++;

        /* this code is valid but length of icmp header is a even value and can be skipped
        __u8 *n_off_u8 = (__u8 *)n_off_u16;

        if (icmplen & 1)
        {
                if (n_off_u8 + 1 <= data_end) // __com001
                        sum_32 += *n_off_u8;
                else
                        return 0;
        } */

        return fold_csum(sum_u32);
    }
    else // csum 64 bits
    {
        for (__u32 i = 0; i < icmplen; i += sizeof(__u64))
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;

            // __com001
            if (n_off_u64 + 1 > data_end)
                break;
        }

        __u32 *n_off_u32 = (__u32 *)n_off_u64;

        if (icmplen & 4)
        {
            if (n_off_u32 + 1 > data_end) // __com001
                return 0;
            else
            {
                __u64 s = *n_off_u32++;

                sum_u64 += s;

                if (sum_u64 < s)
                    sum_u64++;
            }
        }

        __u16 *n_off_u16 = (__u16 *)n_off_u32;

        if (icmplen & 2)
        {
            if (n_off_u16 + 1 > data_end) // __com001
                return 0;
            else
            {
                __u64 s = *n_off_u16++;

                sum_u64 += s;

                if (sum_u64 < s)
                    sum_u64++;
            }
        }

        __u8 *n_off_u8 = (__u8 *)n_off_u16;

        if (icmplen & 1)
        {
            if (n_off_u8 + 1 > data_end) // __com001
                return 0;
            else
            {
                __u64 s = *n_off_u8;

                sum_u64 += s;

                if (sum_u64 < s)
                    sum_u64++;
            }
        }
    }

    // Fold down to 16 bits
    t1 = sum_u64;
    t2 = sum_u64 >> 32;
    t1 += t2;
    if (t1 < t2)
        t1++;
    t3 = t1;
    t4 = t1 >> 16;
    t3 += t4;
    if (t3 < t4)
        t3++;

    return ~t3;
}

//
// Name: icmpV6csum
//
// Description: Build IPv6 ICMP pseudo-header and execute checksum (Section 8.1 of RFC 2460).
//
// Input:
//  n_off - pointer to ipv6 header start
//  data_end - pointer to end of buffer
//  icmplen - icmpv6 total length as declared inside ipv6 header
//
// Output:
//
// Return: the checksum value value or set to 0 if error occur
//
static __always_inline __sum16 icmpV6csum(void *n_off, void *data_end, const __be16 icmplen)
{
    struct ipv6hdr *ip6h = NULL;
    struct icmp6hdr *icmp6h = NULL;

    // __com001
    if (icmplen > ICMPV6_MAX_SIZE)
        return 0;

    // __com001
    //	if (n_off + 1 > data_end)
    //		return 0;

    ip6h = n_off;

    if (n_off + sizeof(*ip6h) > data_end)
        return 0;

    icmp6h = n_off + sizeof(*ip6h);

    //	if (sizeof(*icmp6h) > icmplen)
    //		return 0;

    //	if (n_off + sizeof(*ip6h) + sizeof(*icmp6h) > data_end)
    //		return 0;

    __u64 *n_off_u64 = NULL; // warning: bpf reject code if this declaration is after next condition check

    if (icmplen == sizeof(struct icmp6hdr)) // for zero payload data perform a csum conventional 16 bits (RFC 1071)
    {
        __u32 sum_u32 = 0;

#pragma clang loop unroll(full)
        for (__u8 i = 0; i < 8; i++)
            sum_u32 += ip6h->saddr.s6_addr16[i];

#pragma clang loop unroll(full)
        for (__u8 i = 0; i < 8; i++)
            sum_u32 += ip6h->daddr.s6_addr16[i];

        sum_u32 += ntohs(icmplen);
        sum_u32 += ntohs(ip6h->nexthdr);
        sum_u32 += icmp6h->icmp6_type;
        sum_u32 += htons(icmp6h->icmp6_code);
        sum_u32 += icmp6h->icmp6_identifier;
        sum_u32 += icmp6h->icmp6_sequence;

        return fold_csum(sum_u32);
    }

    n_off_u64 = n_off + sizeof(*ip6h) + sizeof(*icmp6h); // + sizeof(*icmp6h);
    __u64 sum_u64 = 0;
    __u32 t1, t2;
    __u16 t3, t4;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++)
        sum_u64 += ip6h->saddr.s6_addr32[i];

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++)
        sum_u64 += ip6h->daddr.s6_addr32[i];

    sum_u64 += ntohs(icmplen);
    sum_u64 += ntohs(ip6h->nexthdr);
    sum_u64 += icmp6h->icmp6_type;
    sum_u64 += htons(icmp6h->icmp6_code);
    sum_u64 += icmp6h->icmp6_identifier;
    sum_u64 += icmp6h->icmp6_sequence;

    if (icmplen == ICMP_DEFAULT_SIZE) // csum 64 bits
    {
        __u64 *n_off_u64 = n_off + sizeof(*ip6h) + sizeof(*icmp6h); // + sizeof(*icmp6h);

        // __com001
        if (n_off_u64 + (icmplen / sizeof(__u64)) - (sizeof(*icmp6h) / sizeof(__u64)) > data_end)
            return 0;

#pragma clang loop unroll_count((ICMP_DEFAULT_SIZE - sizeof(*icmp6h)) / sizeof(__u64))
        for (__u32 i = sizeof(*icmp6h); i < icmplen; i += sizeof(__u64))
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        goto icmpV6checksum_fold;
    }

    if (n_off_u64 + 1 > data_end) // __com001
        return 0;

    for (__u32 i = sizeof(*icmp6h); i < icmplen; i += sizeof(__u64))
    {
        __u64 s = *n_off_u64++;

        sum_u64 += s;

        if (sum_u64 < s)
            sum_u64++;

        // __com001
        if (n_off_u64 + 1 > data_end)
            break;
    }

    __u32 *n_off_u32 = (__u32 *)n_off_u64;

    if (icmplen & 4)
    {
        if (n_off_u32 + 1 > data_end) // __com001
            return 0;
        else
        {
            __u64 s = *n_off_u32++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }
    }

    __u16 *n_off_u16 = (__u16 *)n_off_u32;

    if (icmplen & 2)
    {
        if (n_off_u16 + 1 > data_end) // __com001
            return 0;
        else
        {
            __u64 s = *n_off_u16++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }
    }

    __u8 *n_off_u8 = (__u8 *)n_off_u16;

    if (icmplen & 1)
    {
        if (n_off_u8 + 1 > data_end) // __com001
            return 0;
        else
        {
            __u64 s = *n_off_u8;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }
    }

icmpV6checksum_fold:
    // Fold down to 16 bits
    t1 = sum_u64;
    t2 = sum_u64 >> 32;
    t1 += t2;
    if (t1 < t2)
        t1++;
    t3 = t1;
    t4 = t1 >> 16;
    t3 += t4;
    if (t3 < t4)
        t3++;

    return ~t3;

nocheck:
    return 0;
}
/*
{
        struct ipv6hdr *ip6h;
        struct icmp6hdr *icmp6h;

        // __com001
        if (icmplen > ICMPV6_MAX_SIZE)
                return 0;

        ip6h = n_off;

        if (n_off + sizeof(*ip6h) > data_end)
                return 0;

        icmp6h = n_off + sizeof(*ip6h);

        if (sizeof(*icmp6h) > icmplen)
                return 0;

//	if (n_off + sizeof(*ip6h) + sizeof(*icmp6h) > data_end)
//		return 0;

        if (icmplen == sizeof(struct icmp6hdr)) // for zero payload data perform a csum conventional 16 bits (RFC 1071)
        {
                __u32 sum_u32 = 0;

#pragma clang loop unroll(full)
                for (__u8 i = 0; i < 8; i++)
                        sum_u32 += ip6h->saddr.s6_addr16[i];

#pragma clang loop unroll(full)
                for (__u8 i = 0; i < 8; i++)
                sum_u32 += ip6h->daddr.s6_addr16[i];

                sum_u32 += ntohs(icmplen);
                sum_u32 += ntohs(ip6h->nexthdr);
                sum_u32 += icmp6h->icmp6_type;
                sum_u32 += icmp6h->icmp6_code * 256;
                sum_u32 += icmp6h->icmp6_identifier;
                sum_u32 += icmp6h->icmp6_sequence;

                return fold_csum(sum_u32);
        }

        __u64 sum_u64 = 0;
        __u32 t1, t2;
        __u16 t3, t4;

#pragma clang loop unroll(full)
        for (__u8 i = 0; i < 4; i++)
                sum_u64 += ip6h->saddr.s6_addr32[i];

#pragma clang loop unroll(full)
        for (__u8 i = 0; i < 4; i++)
        sum_u64 += ip6h->daddr.s6_addr32[i];

        sum_u64 += ntohs(icmplen);
        sum_u64 += ntohs(ip6h->nexthdr);
        sum_u64 += icmp6h->icmp6_type;
        sum_u64 += icmp6h->icmp6_code * 256;
        sum_u64 += icmp6h->icmp6_identifier;
        sum_u64 += icmp6h->icmp6_sequence;

        if (icmplen == ICMP_DEFAULT_SIZE) // csum 64 bits
        {
                __u64 *n_off_u64 = n_off + sizeof(*ip6h) + sizeof(*icmp6h); // + sizeof(*icmp6h);

                // __com001
                if (n_off_u64 + (icmplen / sizeof(__u64)) - (sizeof(*icmp6h) / sizeof(__u64)) > data_end)
                                return 0;

#pragma clang loop unroll(full)
                for (__u32 i = sizeof(*icmp6h); i < icmplen; i += sizeof(__u64))
                {
                        __u64 s = *n_off_u64++;

                        sum_u64 += s;

                        if (sum_u64 < s)
                                sum_u64++;
                }
        }
        else // csum 64 bits
        {
                __u64 *n_off_u64 = n_off + sizeof(*ip6h) + sizeof(*icmp6h); // + sizeof(*icmp6h);

                if (n_off_u64 + 1 > data_end)
                                return 0;

// TODO NOT load with this code
                for (__u32 i = sizeof(*icmp6h); i < icmplen; i += sizeof(__u64))
                {
                        __u64 s = *n_off_u64++;

                        sum_u64 += s;

                        if (sum_u64 < s)
                                sum_u64++;

                        // __com001
                        if (n_off_u64 + 1 > data_end)
                                break;
                }


// TODO NOT load with this code
                __u32 *n_off_u32 = (__u32 *)n_off_u64;

                if (icmplen & 4)
                {
                        if (n_off_u32 + 1 <= data_end) // __com001
                        {
                                __u64 s = *n_off_u32++;

                                sum_u64 += s;

                                if (sum_u64 < s)
                                        sum_u64++;
                        }
                        else
                                return 0;
                }

                __u16 *n_off_u16 = (__u16 *)n_off_u32;

                if (payloadlen & 2)
                {
                        if (n_off_u16 + 1 <= data_end) // __com001
                        {
                                __u64 s = *n_off_u16++;

                                sum_u64 += s;

                                if (sum_u64 < s)
                                        sum_u64++;
                        }
                        else
                                return 0;
                }

                __u8 *n_off_u8 = (__u8 *)n_off_u16;

                if (payloadlen & 1)
                {
                        if (n_off_u8 + 1 <= data_end) // __com001
                        {
                                __u64 s = *n_off_u8;

                                sum_u64 += s;

                                if (sum_u64 < s)
                                        sum_u64++;
                        }
                        else
                                return 0;
                }
        }

        // Fold down to 16 bits
        t1 = sum_u64;
        t2 = sum_u64 >> 32;
        t1 += t2;
        if (t1 < t2) t1++;
        t3 = t1;
        t4 = t1 >> 16;
        t3 += t4;
        if (t3 < t4) t3++;

        return ~t3;
} */

//
// Name: send_icmp4
//
// Description: trasmit a custom icmp packet
//
// Input:
//  ctx - the xdp context
//  icmp4_type - the icmp type to trasmit
//  icmp4_code - the icmp code to trasmit
//  saddr - the source address for the new packet
//
// Output:
//
// Return: XDP_TX if ok, else XDP_DROP
//
static __always_inline int send_icmp4(struct xdp_md *ctx, in4_addr *saddr, const __u8 icmp4_type, const __u8 icmp4_code)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct vlan_ethhdr *l2hdr = NULL;
    struct iphdr *iph = NULL;
    struct iphdr *orig_iph = NULL;
    struct icmphdr *icmph = NULL;

    // __com006
    if (saddr == NULL)
        MXDP_V4DROP

    __s32 headroom = (__s32)sizeof(struct iphdr) + (__s32)sizeof(struct icmphdr);

    // check for respect MTU size of outgoing packet
    if ((ETH_HLEN + sizeof(struct iphdr) + ICMPV4_MAX_SIZE) < ((data_end - data) + headroom))
        MXDP_V4DROP

    // create headroom at the begin of data
    if (bpf_xdp_adjust_head(ctx, 0 - headroom))
        MXDP_V4DROP

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    l2hdr = data;

    // __com001
    if (l2hdr + 1 > data_end)
        MXDP_V4DROP

    iph = data + sizeof(*l2hdr);

    // __com001
    if (iph + 1 > data_end)
        MXDP_V4DROP

    icmph = data + sizeof(*l2hdr) + sizeof(*iph);

    // __com001
    if (icmph + 1 > data_end)
        MXDP_V4DROP

    orig_iph = data + sizeof(*l2hdr) + sizeof(*iph) + sizeof(*icmph);

    // __com001
    if (orig_iph + 1 > data_end)
        MXDP_V4DROP

    memcpy(data, data + headroom, VLAN_ETH_HLEN);
    iph->version = orig_iph->version;
    iph->ihl = 5;
    iph->id = orig_iph->id;
    iph->tot_len = *((__be16 *)(data + ETH_HLEN + headroom + offsetof(struct iphdr, tot_len)));
    iph->tot_len = htons(ntohs(iph->tot_len) + headroom);
    iph->protocol = IPPROTO_ICMP;
    iph->frag_off = 0;
    iph->ttl = MIPDEFTTL;
    iph->saddr = *saddr;
    iph->daddr = orig_iph->saddr;
    iph->check = 0;
    __u32 _csum = 0;
    ipv4_csum(iph, sizeof(struct iphdr), &_csum);
    iph->check = (__sum16)~_csum;
    icmph->type = icmp4_type;
    icmph->code = icmp4_code;
    icmph->checksum = 0;
    icmph->un.gateway = 0;

#ifdef STRICT
    __be16 icmplen = ntohs(iph->tot_len) - sizeof(*iph);

    void *n_off = data + sizeof(*l2hdr) + sizeof(*iph);

    // __com001
    if (n_off + icmplen > data_end)
        MXDP_V4DROP

    __sum16 csum = icmpV4csum(n_off, data_end, icmplen);

    if (csum == 0)
        MXDP_V4DROP

    icmph->checksum = csum;
#endif

    // bpf_printk("reply %u %u", (data_end - data), ntohs(ip6h->payload_len));

    MXDP_V4TX
}

//
// Name: sendV4icmp
//
// Description: trasmit a custom icmp packet emulating OpenBSD OS
//
// Input:
//  ctx - the xdp context
//  icmp4_type - the icmp type to trasmit
//  icmp4_code - the icmp code to trasmit
//  saddr - the source address for the new packet
//  deltattl - value to subtract from ttl of sending packet
//
// Output:
//
// Return: XDP_TX if ok, else XDP_DROP
//
static __always_inline int sendV4icmp(struct xdp_md *ctx, in4_addr *saddr, const __u8 icmp4_type, const __u8 icmp4_code, __u8 deltattl)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct vlan_ethhdr *in_l2hdr = NULL;
    struct vlan_ethhdr *l2hdr = NULL;
    struct iphdr *iph = NULL;
    struct iphdr *orig_iph = NULL;
    struct icmphdr *icmph = NULL;

    if (saddr == NULL)
        MXDP_V4DROP

    iph = data + sizeof(struct vlan_ethhdr);

    if (iph + 1 > data_end)
        MXDP_V4DROP

    __s32 headroom = (__s32)sizeof(struct iphdr) + (__s32)sizeof(struct icmphdr);
    __s32 msgroom = (__s32)sizeof(struct iphdr);

    switch (iph->protocol)
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

    // truncate all payload data like openbsd
    if (bpf_xdp_adjust_tail(ctx, 0 - ((data_end - data) - (ETH_HLEN + msgroom))))
        MXDP_V4DROP

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // create headroom at the begin of data
    if (bpf_xdp_adjust_head(ctx, 0 - headroom))
        MXDP_V4DROP

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    l2hdr = data;

    // __com001
    if (l2hdr + 1 > data_end)
        MXDP_V4DROP

    iph = data + sizeof(*l2hdr);

    // __com001
    if (iph + 1 > data_end)
        MXDP_V4DROP

    icmph = data + sizeof(*l2hdr) + sizeof(*iph);

    // __com001
    if (icmph + 1 > data_end)
        MXDP_V4DROP

    orig_iph = data + sizeof(*l2hdr) + headroom;

    // __com001
    if (orig_iph + 1 > data_end)
        MXDP_V4DROP

    memcpy(data, data + headroom, VLAN_ETH_HLEN);
    iph->version = orig_iph->version;
    iph->ihl = 5;
    iph->id = orig_iph->id;
    iph->tot_len = htons(ntohs(orig_iph->tot_len) + headroom - (ntohs(orig_iph->tot_len) - msgroom));

    if (icmp4_type == ICMP_TIME_EXCEEDED)
        iph->tos = 0xc0; // clone openbsd reply

    iph->protocol = IPPROTO_ICMP;
    iph->frag_off = 0;
    iph->ttl = MIPDEFTTL - deltattl;
    iph->saddr = *saddr;
    iph->daddr = orig_iph->saddr;
    iph->check = 0;
    __u32 _csum = 0;
    ipv4_csum(iph, sizeof(struct iphdr), &_csum);
    iph->check = (__sum16)~_csum;
    icmph->type = icmp4_type;
    icmph->code = icmp4_code;
    icmph->checksum = 0;
    icmph->un.gateway = 0;

    // Checksum 64 bits calculation section
    __be16 icmplen = ntohs(iph->tot_len) - sizeof(*iph);

    void *n_off = data + sizeof(*l2hdr) + sizeof(*iph);

    // __com001
    if (n_off + icmplen > data_end)
        MXDP_V4DROP

    __u64 *n_off_u64 = (__u64 *)n_off;
    __u32 *n_off_u32 = NULL;
    __u64 sum_u64 = 0;
    __u32 t1, t2;
    __u16 t3, t4;

#define V4TCP64 6 // (sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) / 8 = 6
#define V4VAR64 4 // (sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct udphdr/icmphdr)) / 8 = 4.5

    switch (icmplen / 8)
    {
    case V4TCP64:
        if (n_off_u64 + V4TCP64 > data_end)
            MXDP_V4DROP

#pragma clang loop unroll(full)
        for (__u32 i = 0; i < V4TCP64; i++)
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        break;
    case V4VAR64:
        if (n_off_u64 + V4VAR64 > data_end)
            MXDP_V4DROP

#pragma clang loop unroll(full)
        for (__u32 i = 0; i < V4VAR64; i++)
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        n_off_u32 = (__u32 *)n_off_u64;

        if (n_off_u32 + 1 > data_end) // __com001
            return 0;
        else
        {
            __u64 s = *n_off_u32++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        break;
    default:
        MXDP_V4DROP
    }

    // Fold down to 16 bits
    t1 = sum_u64;
    t2 = sum_u64 >> 32;
    t1 += t2;
    if (t1 < t2)
        t1++;
    t3 = t1;
    t4 = t1 >> 16;
    t3 += t4;
    if (t3 < t4)
        t3++;

    icmph->checksum = ~t3;

    MXDP_V4TX
}

//
// Name: send_icmp6
//
// Description: trasmit a custom icmp packet
//
// Input:
//  ctx - the xdp context
//  icmp4_type - the icmp type to trasmit
//  icmp4_code - the icmp code to trasmit
//  saddr - the source address for the new packet
//
// Output:
//
// Return: XDP_TX if ok, else XDP_DROP
//
static __always_inline int send_icmp6(struct xdp_md *ctx, struct in6_addr *saddr, const __u8 icmp6_type, const __u8 icmp6_code)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct vlan_ethhdr *l2hdr = NULL;
    struct ipv6hdr *ip6h = NULL;
    struct ipv6hdr *orig_ip6h = NULL;
    struct icmp6hdr *icmp6h = NULL;

    if (saddr == NULL)
        MXDP_V6DROP

    __u16 headroom = (__u16)sizeof(struct ipv6hdr) + (__u16)sizeof(struct icmp6hdr);

    // check for respect MTU size of outgoing packet
    if ((sizeof(struct vlan_ethhdr) + sizeof(struct ipv6hdr) + ICMPV6_MAX_SIZE) < ((data_end - data) + headroom))
        MXDP_V6DROP

    // create headroom at the begin of data
    if (bpf_xdp_adjust_head(ctx, 0 - headroom))
        MXDP_V6DROP

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    l2hdr = data;

    // __com001
    if (l2hdr + 1 > data_end)
        MXDP_V6DROP

    ip6h = data + sizeof(*l2hdr);

    // __com001
    if (ip6h + 1 > data_end)
        MXDP_V6DROP

    icmp6h = data + sizeof(*l2hdr) + sizeof(*ip6h);

    // __com001
    if (icmp6h + 1 > data_end)
        MXDP_V6DROP

    orig_ip6h = data + sizeof(*l2hdr) + sizeof(*ip6h) + sizeof(*icmp6h);

    // __com001
    if (orig_ip6h + 1 > data_end)
        MXDP_V6DROP

    memcpy(data, data + headroom, VLAN_ETH_HLEN);
    ip6h->version = orig_ip6h->version;
    memcpy(&ip6h->flow_lbl, &orig_ip6h->flow_lbl, 3);
    ip6h->payload_len = htons((data_end - data) - sizeof(*l2hdr) - sizeof(*ip6h));
    ip6h->nexthdr = IPPROTO_ICMPV6;
    ip6h->hop_limit = MIPDEFTTL;
    ip6h->saddr = *saddr;
    ip6h->daddr = orig_ip6h->saddr;
    icmp6h->icmp6_type = icmp6_type;
    icmp6h->icmp6_code = icmp6_code;
    icmp6h->icmp6_cksum = 0;
    icmp6h->icmp6_pointer = 0;

#ifdef STRICT
    __be16 icmplen = ntohs(ip6h->payload_len);

    void *n_off = data + sizeof(*l2hdr);

    __sum16 csum = icmpV6csum(n_off, data_end, icmplen);

    if (csum == 0)
        MXDP_V6DROP

    icmp6h->icmp6_cksum = csum;
#endif

    // bpf_printk("reply %u %u", (data_end - data), ntohs(ip6h->payload_len));

    MXDP_V6TX
}

//
// Name: sendV6icmp
//
// Description: trasmit a custom icmp packet emulating OpenBSD OS
//
// Input:
//  ctx - the xdp context
//  icmp4_type - the icmp type to trasmit
//  icmp4_code - the icmp code to trasmit
//  saddr - the source address for the new packet
//  deltattl - value to subtract from ttl of sending packet
//
// Output:
//
// Return: XDP_TX if ok, else XDP_DROP
//
static __always_inline int sendV6icmp(struct xdp_md *ctx, struct in6_addr *saddr, const __u8 icmp6_type, const __u8 icmp6_code, __u8 deltattl)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct vlan_ethhdr *l2hdr = NULL;
    struct ipv6hdr *ip6h = NULL;
    struct ipv6hdr *orig_ip6h = NULL;
    struct icmp6hdr *icmp6h = NULL;

    if (saddr == NULL)
        MXDP_V6DROP

    ip6h = data + sizeof(struct vlan_ethhdr);

    if (ip6h + 1 > data_end)
        MXDP_V6DROP

    __s32 headroom = (__s32)sizeof(struct ipv6hdr) + (__s32)sizeof(struct icmp6hdr);
    __s32 msgroom = (__s32)sizeof(struct ipv6hdr);

    switch (ip6h->nexthdr)
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

    // truncate all payload data like openbsd
    if (bpf_xdp_adjust_tail(ctx, 0 - ((data_end - data) - (ETH_HLEN + msgroom))))
        MXDP_V6DROP

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // create headroom at the begin of data
    if (bpf_xdp_adjust_head(ctx, 0 - headroom))
        MXDP_V6DROP

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    l2hdr = data;

    // __com001
    if (l2hdr + 1 > data_end)
        MXDP_V6DROP

    ip6h = data + sizeof(*l2hdr);

    // __com001
    if (ip6h + 1 > data_end)
        MXDP_V6DROP

    icmp6h = data + sizeof(*l2hdr) + sizeof(*ip6h);

    // __com001
    if (icmp6h + 1 > data_end)
        MXDP_V6DROP

    orig_ip6h = data + sizeof(*l2hdr) + headroom;

    // __com001
    if (orig_ip6h + 1 > data_end)
        MXDP_V6DROP

    memcpy(data, data + headroom, VLAN_ETH_HLEN);
    ip6h->version = orig_ip6h->version;
    memcpy(&ip6h->flow_lbl, &orig_ip6h->flow_lbl, 3);
    ip6h->payload_len = htons(ntohs(orig_ip6h->payload_len) + headroom - (ntohs(orig_ip6h->payload_len) - (msgroom - sizeof(struct ipv6hdr))));
    ;

    //	if (icmp6_type == ICMPV6_TIME_EXCEED)
    //		ip6h->tos = 0xc0; // clone openbsd reply TODO testing for now

    ip6h->nexthdr = IPPROTO_ICMPV6;
    ip6h->hop_limit = MIPDEFTTL - deltattl;
    icmp6h->icmp6_type = icmp6_type;
    icmp6h->icmp6_code = icmp6_code;
    icmp6h->icmp6_cksum = 0;
    icmp6h->icmp6_pointer = 0;

    // Checksum 64 bits calculation section
    __be16 icmplen = ntohs(ip6h->payload_len);

    void *n_off = data + sizeof(*l2hdr) + sizeof(*ip6h) + sizeof(*icmp6h);

    // __com001
    if (n_off + 1 > data_end)
        MXDP_V6DROP

    __u64 *n_off_u64 = (__u64 *)n_off;
    __u32 *n_off_u32 = NULL;
    __u64 sum_u64 = 0;
    __u32 t1, t2;
    __u16 t3, t4;

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++)
    {
        ip6h->saddr.s6_addr32[i] = saddr->s6_addr32[i];
        sum_u64 += ip6h->saddr.s6_addr32[i];
    }

#pragma clang loop unroll(full)
    for (__u8 i = 0; i < 4; i++)
    {
        ip6h->daddr.s6_addr32[i] = orig_ip6h->saddr.s6_addr32[i];
        sum_u64 += ip6h->daddr.s6_addr32[i];
    }

    sum_u64 += ntohs(icmplen);
    sum_u64 += ntohs(ip6h->nexthdr);
    sum_u64 += icmp6h->icmp6_type;
    sum_u64 += htons(icmp6h->icmp6_code);
    sum_u64 += icmp6h->icmp6_identifier;
    sum_u64 += icmp6h->icmp6_sequence;

#define V6TCP64 7 // (sizeof(struct ipv6hdr) + sizeof(struct tcphdr)) / 8 = 7.5
#define V6VAR64 6 // (sizeof(struct ipv6hdr) + sizeof(struct udphdr/icmp6hdr)) / 8 = 6

    switch ((icmplen - sizeof(struct icmp6hdr)) / 8)
    {
    case V6TCP64:
        if (n_off_u64 + V6TCP64 > data_end)
            MXDP_V6DROP

#pragma clang loop unroll(full)
        for (__u32 i = 0; i < V6TCP64; i++)
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        n_off_u32 = (__u32 *)n_off_u64;

        if (n_off_u32 + 1 > data_end) // __com001
            return 0;
        else
        {
            __u64 s = *n_off_u32++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        break;
    case V6VAR64:
        if (n_off_u64 + V6VAR64 > data_end)
            MXDP_V6DROP

#pragma clang loop unroll(full)
        for (__u32 i = 0; i < V6VAR64; i++)
        {
            __u64 s = *n_off_u64++;

            sum_u64 += s;

            if (sum_u64 < s)
                sum_u64++;
        }

        break;
    default:
        MXDP_V6DROP
    }

    // Fold down to 16 bits
    t1 = sum_u64;
    t2 = sum_u64 >> 32;
    t1 += t2;
    if (t1 < t2)
        t1++;
    t3 = t1;
    t4 = t1 >> 16;
    t3 += t4;
    if (t3 < t4)
        t3++;

    icmp6h->icmp6_cksum = ~t3;

    MXDP_V6TX
}

//
// Name: check__urpf
//
// Description: perform a Unicast Reverse Path Forwarding (RFC 3704) and check if source address must be ignored/reject because part of Special Address Block (this static tables must be inserted from bird)
//
// Input:
//  ctx - the xdp_md context
//  fib_params - the bpf_fib_lookup params
//  flags - flags for bpf_fib_lookup function
//  ifingress - the interface where program is running
//
// Output:
//
// Return: true if address is found with Unicast Reverse Path Forwarding search or forwarding disable
//
static __always_inline bool check__urpf(struct xdp_md *ctx, struct bpf_fib_lookup *fib_params, u32 flags, const __u32 ifingress)
{
    switch (bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params), flags))
    {
    case BPF_FIB_LKUP_RET_SUCCESS:
        if (fib_params->ifindex != ifingress) // If source address is not part of default route it must be dropped.
            return true;

        break;
    case BPF_FIB_LKUP_RET_BLACKHOLE: // Source network is blackholed
    case BPF_FIB_LKUP_RET_UNREACHABLE: // Source network is unreachable and can be dropped from OS
    case BPF_FIB_LKUP_RET_PROHIBIT: // Source network not allowed and can be dropped from OS
        return true;
    default:
        break;
    }

    return false;
}

/*
// Name: check_v4acl
//
// Description: create - nostate - L4 firewall rules for nas devices loppback with host fields minor than 8. Warning: source address in whitelist cannot found also in blacklist.
//
// Input:
//  ctx - the context
//
// Output:
//
// Return: false if packet must be dropped
//
static __always_inline bool check_v4acl(struct xdp_md *ctx, void *ntp_wl, void *dns_wl, void *log_wl, void *rad_wl, void *untrust)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct vlan_ethhdr *l2hdr = data;
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
        struct tcphdr *tcph;
        struct udphdr *udph;
        __u32 key = 0;
        u16 h_proto;

        // __com001
        if (data + sizeof(*l2hdr) > data_end)
                return XDP_DROP;

        h_proto = l2hdr->h_vlan_encapsulated_proto;

        iph = data + sizeof(*l2hdr);

        if (data + sizeof(*l2hdr) + sizeof(*iph) > data_end)
                return false;

        // __com003
        if ((iph->daddr & 0xF8000000) > 0)
                return true; // of sure, possible traffic destined to generic hosts of our AS

        if (sizeof(*iph) != (iph->ihl * 4))
                return false;

        if (iph->protocol == IPPROTO_TCP)
                tcph = data + sizeof(*l2hdr) + sizeof(*iph);
        else if (iph->protocol == IPPROTO_UDP)
                udph = data + sizeof(*l2hdr) + sizeof(*iph);
        else if (iph->protocol == IPPROTO_ICMP)
        {
                if (data + sizeof(*l2hdr) + sizeof(*iph) + sizeof(struct icmphdr) > data_end)
                        return false;

                return true;
        }

        in4_addr *daddr = NULL;

        if (tcph)
        {	// __com001
                if ((void *)tcph + sizeof(*tcph) > data_end)
                        return false;

                switch (htons(tcph->source))
                {
                        case SERVICE_NTP:
                                daddr = bpf_map_lookup_elem(ntp_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_DNS:
                                daddr = bpf_map_lookup_elem(dns_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_LOG:
                                daddr = bpf_map_lookup_elem(log_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_RADIUS:
                        case SERVICE_RADIUS_ACCT:
                                daddr = bpf_map_lookup_elem(rad_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        default:
                                key = UNTRUSTED_TO_LOP;
                                goto untrusted;
                }
        }
        else if (udph)
        {	// __com001
                if ((void *)udph + sizeof(*udph) > data_end)
                        return false;

                switch (htons(udph->source))
                {
                        case SERVICE_NTP:
                                daddr = bpf_map_lookup_elem(ntp_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_DNS:
                                daddr = bpf_map_lookup_elem(dns_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_LOG:
                                daddr = bpf_map_lookup_elem(log_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_RADIUS:
                        case SERVICE_RADIUS_ACCT:
                                daddr = bpf_map_lookup_elem(rad_wl, &iph->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        default:
                                key = UNTRUSTED_TO_LOP;
                                goto untrusted;
                }
        }

        return false;

candidate:

        if (daddr && (netV4cmp(&iph->daddr, daddr, IPV4LOOP_MASK) == true)) // if found and target address is inside network mask of loopback nas address, then pass
                return true;

        return false;

untrusted:
        {
                in4_addr *daddr = bpf_map_lookup_elem(untrust, &key);

                if (daddr && (netV4cmp(&iph->daddr, daddr, IPV4LOOP_MASK) == true)) // unwanted traffic destinated to network mask of loopback nas address
                        return false;
        }

        return true;
}

//
//static __always_inline bool netV4cmp(in4_addr *, in4_addr *, __u8);
//static __always_inline bool netV6cmp(struct in6_addr *, struct in6_addr *, __u8);
// Name: check_v6acl
//
// Description: create - nostate - L4 firewall rules for nas devices loppback with host fields minor than 8. Warning: source address in whitelist cannot found also in blacklist.
//
// Input:
//  ctx - the context
//
// Output:
//
// Return: false if packet must be dropped
//
static __always_inline bool check_v6acl(struct xdp_md *ctx, void *ntp_wl, void *dns_wl, void *log_wl, void *rad_wl, void *untrust)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct vlan_ethhdr *l2hdr = data;
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
        struct tcphdr *tcph;
        struct udphdr *udph;
        __u32 key = 0;
        u16 h_proto;

        // __com001
        if (data + sizeof(*l2hdr) > data_end)
                return XDP_DROP;

        h_proto = l2hdr->h_vlan_encapsulated_proto;

        ip6h = data + sizeof(*l2hdr);

        if (data + sizeof(*l2hdr) + sizeof(*ip6h) > data_end)
                return false;

        // __com003
        if (ip6h->daddr.s6_addr16[3] > 0 || // 2345:6789:abcd:................::
                ip6h->daddr.s6_addr32[2] > 0 || // 2345:6789:abcd:0:................:................::
                (ip6h->daddr.s6_addr32[3] & 0xF8FFFFFF) > 0) // 2345:6789:abcd::................:.....xxx........
                return true; // of sure, possible traffic destined to generic hosts of our AS

        if (ip6h->nexthdr == IPPROTO_TCP)
                tcph = data + sizeof(*l2hdr) + sizeof(*ip6h);
        else if (ip6h->nexthdr == IPPROTO_UDP)
                udph = data + sizeof(*l2hdr) + sizeof(*ip6h);
        else if (ip6h->nexthdr == IPPROTO_ICMPV6)
        {
                if (data + sizeof(*l2hdr) + sizeof(*ip6h) + sizeof(struct icmp6hdr) > data_end)
                        return false;

                return true;
        }

        struct in6_addr *daddr = NULL;

        if (tcph)
        {	// __com001
                if ((void *)tcph + sizeof(*tcph) > data_end)
                        return false;

                switch (htons(tcph->source))
                {
                        case SERVICE_NTP:
                                daddr = bpf_map_lookup_elem(ntp_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_DNS:
                                daddr = bpf_map_lookup_elem(dns_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_LOG:
                                daddr = bpf_map_lookup_elem(log_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_RADIUS:
                        case SERVICE_RADIUS_ACCT:
                                daddr = bpf_map_lookup_elem(rad_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        default:
                                key = UNTRUSTED_TO_LOP;
                                goto untrusted;
                }
        }
        else if (udph)
        {	// __com001
                if ((void *)udph + sizeof(*udph) > data_end)
                        return false;

                switch (htons(udph->source))
                {
                        case SERVICE_NTP:
                                daddr = bpf_map_lookup_elem(ntp_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_DNS:
                                daddr = bpf_map_lookup_elem(dns_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_LOG:
                                daddr = bpf_map_lookup_elem(log_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        case SERVICE_RADIUS:
                        case SERVICE_RADIUS_ACCT:
                                daddr = bpf_map_lookup_elem(rad_wl, &ip6h->saddr); // check if source address is found in map of remote servers
                                goto candidate;
                        default:
                                key = UNTRUSTED_TO_LOP;
                                goto untrusted;
                }
        }

        return false;

candidate:

        if (daddr && (netV6cmp(&ip6h->daddr, daddr, IPV6LOOP_MASK) == true)) // if found and target address is inside network mask of loopback nas address, then pass
                return true;

        return false;

untrusted:
        {
                struct in6_addr *daddr = bpf_map_lookup_elem(untrust, &key);

                if (daddr && (netV6cmp(&ip6h->daddr, daddr, IPV6LOOP_MASK) == true)) // unwanted traffic destinated to network mask of loopback nas address
                        return false;
        }

        return true;
} */

//
// Name: netV4cmp
//
// Description: checks if addresses both belong to the same network
//
// Input:
//  addrA - the address to check
//  addrB - the address to check
//  cidr - the cidr
//
// Output:
//
// Return: true if both address are in the same network
//
static __always_inline bool netV4cmp(in4_addr *addrA, in4_addr *addrB, __u8 cidr)
{
    if (cidr > 32)
        return false;
    else if (cidr == 32 && *addrA != *addrB)
        return false;

    if (cidr >= 24)
    {
        if ((*addrA & 0x00FFFFFF) != (*addrB & 0x00FFFFFF))
            return false;

        if (cidr == 24)
            return true;

        if (((*addrA >> 24) & bitcomposer(cidr % 8)) == ((*addrB >> 24) & bitcomposer(cidr % 8)))
            return true;
    }
    else if (cidr >= 16)
    {
        if ((*addrA & 0x0000FFFF) != (*addrB & 0x0000FFFF))
            return false;

        if (cidr == 16)
            return true;

        if (((*addrA >> 16) & bitcomposer(cidr % 8)) == ((*addrB >> 16) & bitcomposer(cidr % 8)))
            return true;
    }
    else if (cidr >= 8)
    {
        if ((*addrA & 0x000000FF) != (*addrB & 0x000000FF))
            return false;

        if (cidr == 8)
            return true;

        if (((*addrA >> 8) & bitcomposer(cidr % 8)) == ((*addrB >> 8) & bitcomposer(cidr % 8)))
            return true;
    }
    else if ((*addrA & bitcomposer(cidr % 8)) == (*addrB & bitcomposer(cidr % 8)))
        return true;

    return false;
}

//
// Name: netV6cmp
//
// Description: checks if addresses both belong to the same network
//
// Input:
//  addrA - the address to check
//  addrB - the address to check
//  cidr - the cidr
//
// Output:
//
// Return: true if both address are in the same network
//
static __always_inline bool netV6cmp(struct in6_addr *addrA, struct in6_addr *addrB, __u8 cidr)
{
    if (cidr > 128)
        return false;

    __u8 o = 0;

    // heuristic method for fast processing for ipv6 network/48
    if (1 < (cidr / 32))
    {
        if (addrA->s6_addr32[1] != addrB->s6_addr32[1]) // check if both address are administrative or not (high comparison rate, requisite for both: (...s6_addr32[1] & 0x000F8000 == 0))
            return false;

        o = 2;

        if (3 < (cidr / 32))
        {
            if ((__u64 *)&addrA->s6_addr32[2] != (__u64 *)&addrB->s6_addr32[2])
                return false;

            o += 2;
        }
        else if (2 < (cidr / 32))
        {
            if (addrA->s6_addr32[2] != addrB->s6_addr32[2])
                return false;

            o++;
        }

        if (addrA->s6_addr32[0] != addrB->s6_addr32[0]) // if the addresses are different, it will hardly be necessary to compare the first 16 bits
            return false;
    }
    else if (0 < (cidr / 32))
    {
        if (addrA->s6_addr32[0] != addrB->s6_addr32[0])
            return false;

        o = 1;
    }

    // basic method
    // #pragma clang loop unroll(full)
    //	for (o = 0; o < 4 && o < (cidr / 32); o++)
    //		if (addrA->s6_addr32[o] != addrB->s6_addr32[o])
    //			return false;

    o *= 2;

    if ((cidr / 16) > ((cidr / 32) * 2) && o < 7)
    {
        if (addrA->s6_addr16[o] != addrB->s6_addr16[o])
            return false;

        if ((cidr % 16) == 0)
            return true;

        o++;
    }

    o *= 2;

    if (o < (cidr / 8) && o < 15)
    {
        if (addrA->s6_addr[o] != addrB->s6_addr[o])
            return false;

        if ((cidr % 8) == 0)
            return true;

        o++;
    }

    if ((cidr % 32) == 0 || ((o < 16) && (cidr % 8) && (addrA->s6_addr[o] & bitcomposer(cidr % 8)) == (addrB->s6_addr[o] & bitcomposer(cidr % 8))))
        return true;

    return false;
}

//
// Name: bitcomposer
//
// Description: convert 1 byte cidr in bits
//
// Input:
//  cidr - the cidr
//
// Output:
//
// Return: the bitset
//
static __always_inline __u8 bitcomposer(__u8 bits)
{
    switch (bits % 8)
    {
    case 1:
        return 0x80;
    case 2:
        return 0xC0;
    case 3:
        return 0xE0;
    case 4:
        return 0xF0;
    case 5:
        return 0xF8;
    case 6:
        return 0xFC;
    case 7:
        return 0xFE;
    default:
        return 0xFF;
    }
}

// LEGENDA COMMENTS:

// __com001 : sanity check/checks needed by the eBPF verifier
// __com002 : true if xdp program intercept an echo request destined to servers loopback
// __com003 : check if the host field is greater than seven, otherwise it could be a loopback address of our nas devices (firewall->host=0) canonical loopback address (ipv4net/24, ipv6net/48 and 0 < host < 8)
// __com004 : required for the address resolution protocol to work
// __com005 : accept ssh access from controller node																			// global variables must be reinitialized inside master function
// __com006 : before go aHead, check if destination address is assigned at wan interface
// __com007 : Checking for icmpv6 Neighbor Solicitation packets (FF02:0:0:0:0:1:FF00::/104) RFC 2641
// __com008 : before go aHead, check if source address is in whitelist
// __com009 : unsupported icmp request with fragmented data
// __com010 : drop forwarded packets if source address is inside black list. Warning: blacklist cannot contain trusted server found in whitelist
// __com011 : this condition cannot happen
// __com012 : translate local destination address to interface address of ssh server
// __com013 : translate local source address of ssh server to interface address of wan

#endif // __COMMON_KERN_INCLUDED_H

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
#ifndef __COMMON_INCLUDED_H
#define __COMMON_INCLUDED_H

#include <linux/types.h>
#include <linux/ipv6.h> // needed for defining ingressV6_t
#include <bpf/bpf_endian.h>

#define PIN_NONE 0
#define PIN_OBJECT_NS 1
#define PIN_GLOBAL_NS 2

// ICMP types for neighbour discovery messages
#define NDISC_ROUTER_SOLICITATION 133
#define NDISC_ROUTER_ADVERTISEMENT 134
#define NDISC_NEIGHBOUR_SOLICITATION 135
#define NDISC_NEIGHBOUR_ADVERTISEMENT 136
#define NDISC_REDIRECT 137

// Max ipv6 option headers accepted
#define IPV6_OPT_MAX 4

#define NANOSEC_PER_SEC 1000000000 // 10^9 nanoseconds

#define XDP_UNKNOWN XDP_REDIRECT + 1
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)

#define STATS                                        \
    if (stats)                                       \
    {                                                \
        stats->packets++;                            \
        stats->bytes += (ctx->data_end - ctx->data); \
    }

#define MXDP_V4ABORTED                                              \
    {                                                               \
        __u32 key = XDP_ABORTED;                                    \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v4cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V4DROP                                                 \
    {                                                               \
        __u32 key = XDP_DROP;                                       \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v4cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V4PASS                                                 \
    {                                                               \
        __u32 key = XDP_PASS;                                       \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v4cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V4TX                                                   \
    {                                                               \
        __u32 key = XDP_TX;                                         \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v4cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V4REDIRECT                                             \
    {                                                               \
        __u32 key = XDP_REDIRECT;                                   \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v4cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V6ABORTED                                              \
    {                                                               \
        __u32 key = XDP_ABORTED;                                    \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v6cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V6DROP                                                 \
    {                                                               \
        __u32 key = XDP_DROP;                                       \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v6cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V6PASS                                                 \
    {                                                               \
        __u32 key = XDP_PASS;                                       \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v6cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V6TX                                                   \
    {                                                               \
        __u32 key = XDP_TX;                                         \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v6cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_V6REDIRECT                                             \
    {                                                               \
        __u32 key = XDP_REDIRECT;                                   \
        xdp_stats_t *stats = bpf_map_lookup_elem(&act_v6cnt, &key); \
        STATS;                                                      \
        return key;                                                 \
    }
#define MXDP_MAXPEERS 256
#define FRAG_MAXPEERS 4096
#define SNAT_TO_WAN UNTRUSTED_TO_WAN
#define SNAT_TO_LOP UNTRUSTED_TO_LOP
#define DNAT_TO_LOP UNTRUSTED_TO_LOP

// #define IPV4_DONT_F 0x4000 /* Dont fragment flag */
#define IPV4_MORE_F 0x2000 /* Flag: "More Fragments" */
#define IPV4_OFFSET 0x1FFF /* "Fragment Offset" part */
#define IPV6_MORE_F 0x0001 /* Flag: "More Fragments" */
#define IPV6_OFFSET 0xFFF8 /* "Fragment Offset" part */

// clang-format off
#define PROGRAM_STR(x) (                            \
          x == 0                   ? "mienroload"   \
        : x == 1                   ? "mienromon4"   \
        : x == 2                   ? "mienromon6"   \
        : x == 3                   ? "mienromonnet" \
                                   : "(invalid program)")
// clang-format on

enum program_t : __u8
{
    MIENROLOAD = 0,
    MIENROMON4,
    MIENROMON6,
    MIENROMONNET,
    INVALIDPROG // Must be ignored
};

// for untrusted traffic destined to wan interface or to the servers loopbacks main network
enum untrusted_t : __u32
{
    UNTRUSTED_TO_WAN = 0, // for router
    UNTRUSTED_TO_SSH, // to controller ssh lan
    UNTRUSTED_TO_DMZ, // to controller demilitarized zone
    UNTRUSTED_TO_LAN, // to nas lan
    UNTRUSTED_TO_LOP, // to virtual loopback
    UNTRUSTED_MAX
};

enum service_t : __u16
{
    SERVICE_SMTP = 25,
    SERVICE_DNS = 53,
    SERVICE_DNS_S = 853,
    SERVICE_NTP = 123,
    SERVICE_BGP = 179,
    SERVICE_SSH = 22,
    SERVICE_SSH_CTR = 343,
    SERVICE_LOG = 514,
    SERVICE_RADIUS = 1812,
    SERVICE_RADIUS_ACCT = 1813
};

typedef __be32 in4_addr;

typedef struct
{
    __u64 creationtime; // as seconds uptime
    __u64 lastuptime; // last tcp rst-ack received from controller node
    struct bpf_spin_lock lock;
} timeo_t;

typedef struct
{
    __u8 wan;
    __u8 wan_xdp;
    __u8 ssh;
    __u8 ssh_xdp;
    __u8 dmz;
    __u8 dmz_xdp;
    __u8 lan;
    __u8 lan_xdp;
    struct bpf_spin_lock lock; // a struct bpf_spin_lock must be used also for cuncurrency userspace bpf map function that use BPF_F_LOCK flag
} txports_t;

typedef struct
{
    __u16 wan;
    __u16 dmz;
    __u16 lan;
    __u16 lop; // network masks dedicated at servers (eg: nas or (ex: bgw)) loopback interfaces
} amasks_t; // address masks pairs (one byte at left ipv4 and one byte at right ipv6)

typedef struct
{
    __u64 packets;
    __u64 bytes;
} xdp_stats_t;

typedef struct
{
    __u32 vlan_id;
    struct bpf_spin_lock lock; // a struct bpf_spin_lock must be used also for cuncurrency userspace bpf map function that use BPF_F_LOCK flag
} ingress_vlan_t;

typedef struct
{
    __u32 xdp_idx; // parent interface index
    __u32 vlan_id; // vlan id
    struct bpf_spin_lock lock; // a struct bpf_spin_lock must be used also for cuncurrency userspace bpf map function that use BPF_F_LOCK flag
} ifidx_t;

struct ipv6_opt_brief
{
    __u8 nexthdr;
    __u8 hdrelen; // Hdr Ext Len
};

typedef struct
{
    in4_addr saddr;
    in4_addr daddr;
    __u8 protocol;
    __be16 source;
    __be16 dest;
} streamV4_t;

typedef struct
{
    struct in6_addr saddr;
    struct in6_addr daddr;
    __u8 nexthdr;
    __be16 source;
    __be16 dest;
} streamV6_t;

typedef struct
{
    struct bpf_spin_lock lock; // a struct bpf_spin_lock must be used also for cuncurrency userspace bpf map function that use BPF_F_LOCK flag
} lock_t;

#endif // __COMMON_INCLUDED_H

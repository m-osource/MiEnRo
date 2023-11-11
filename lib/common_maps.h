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
#ifndef __COMMON_MAPS_INCLUDED_H
#define __COMMON_MAPS_INCLUDED_H

#include "/tmp/.mienro_kern_volatile.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); // map type BPF declaration is required for lock
    __type(value, txports_t); // idem
    __uint(max_entries, 1);
} txports SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, in4_addr); // map type BPF declaration is required for lock
    __type(value, timeo_t); // idem
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} ssh_v4tmo SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr); // map type BPF declaration is required for lock
    __type(value, timeo_t); // idem
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} ssh_v6tmo SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, amasks_t);
    __uint(max_entries, 1);
    __uint(pinning, PIN_OBJECT_NS);
} amasks SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, UNTRUSTED_MAX);
    __uint(pinning, PIN_OBJECT_NS);
} untrust_v4 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct in6_addr);
    __uint(max_entries, UNTRUSTED_MAX);
    __uint(pinning, PIN_OBJECT_NS);
} untrust_v6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} events SEC(".maps");

#ifdef TRUNK_PORT
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u16);
    __type(value, xdp_stats_t);
    __uint(max_entries, 64);
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
    //	__uint(pinning, PIN_OBJECT_NS);
} brvlan_wl SEC(".maps");
#endif

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, ifidx_t);
    __uint(max_entries, 264);
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} ifidx_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, xdp_stats_t);
    __uint(max_entries, 1);
} fail_cnt SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, xdp_stats_t);
    __uint(max_entries, XDP_ACTION_MAX);
} act_v4cnt SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, xdp_stats_t);
    __uint(max_entries, XDP_ACTION_MAX);
} act_v6cnt SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, streamV4_t);
    __type(value, streamV4_t);
    __uint(max_entries, 64); // max 64 ssh dnat sessions to controller
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} dnat_v4map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, streamV6_t);
    __type(value, streamV6_t);
    __uint(max_entries, 64); // max 64 ssh dnat sessions to controller
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} dnat_v6map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, lock_t);
    __uint(max_entries, 2);
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
    //	__uint(pinning, PIN_OBJECT_NS);
} dnat_locks SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, in4_addr);
    __type(value, ingress_vlan_t);
    __uint(max_entries, MXDP_MAXPEERS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} bgpn_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, ingress_vlan_t);
    __uint(max_entries, MXDP_MAXPEERS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, PIN_OBJECT_NS);
} bgpn_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS * 32); // 32 == max port services supported
} tcp_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS * 32); // 32 == max port services supported
} tcp_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS * 32); // 32 == max port services supported
} udp_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS * 32); // 32 == max port services supported
} udp_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS * 32); // 32 == max port services supported
} icmp_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS * 32); // 32 == max port services supported
} icmp_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} rad_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} rad_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} dns_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} dns_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} ntp_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} ntp_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} vpn_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} vpn_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} mxx_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} mxx_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} mon_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} mon_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} log_v4wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, MXDP_MAXPEERS);
} log_v6wl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, in4_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, 65536);
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
} ddos_v4bl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct in6_addr);
    __type(value, xdp_stats_t);
    __uint(max_entries, 65536);
    //	__uint(map_flags, BPF_F_NO_PREALLOC);
} ddos_v6bl SEC(".maps");

#endif // __COMMON_MAPS_INCLUDED_H

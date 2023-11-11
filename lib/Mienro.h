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

// Local libraries

// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#ifndef __MIENRO_INCLUDED_H
#define __MIENRO_INCLUDED_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"

// Local Library
#include "const.h"
#include "common.h"
#include "mcommon.h"
#include "Setup.h"

// #include <bitmask.h>

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

/* Exit return codes */
#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 3
#define EXIT_FAIL_MAP 20
#define EXIT_FAIL_MAP_KEY 21
#define EXIT_FAIL_MAP_FILE 22
#define EXIT_FAIL_MAP_FS 23
#define EXIT_FAIL_IP 30
#define EXIT_FAIL_PORT 31
#define EXIT_FAIL_BPF 40
#define EXIT_FAIL_BPF_ELF 41
#define EXIT_FAIL_BPF_RELOCATE 42

/* Blacklist operations */
#define ACTION_ADD (1 << 0)
#define ACTION_DEL (1 << 1)

// Netlink buffer
#define IFLIST_REPLY_BUFFER 8192

typedef enum : __u8
{
    WAN_PLS = 0,
    CTR_PLS,
    LAN_PLS,
    XDP_PLS_MAX
} xdp_pls_t;

typedef enum : __u8
{
    PROG_FWD_WAN = 0,
    PROG_FWD_CTR,
    PROG_FWD_LAN,
    PROG_FWD_WAN_DIRECT,
    PROG_FWD_CTR_DIRECT,
    PROG_FWD_LAN_DIRECT,
    PROG_OPT_MAX
} prog_opt_t;

typedef enum : __u8
{
    PROG_MAP_IDX = 0,
    EVENTS_MAP_IDX,
    TXPORTS_MAP_IDX,
    SSHV4TIMEO_MAP_IDX, // Warning: this table take precedence to MON_V4WL_MAP_IDX
    SSHV6TIMEO_MAP_IDX, // Warning: this table take precedence to MON_V4WL_MAP_IDX
    AMASKS_MAP_IDX, // address masks
    UNTRUST_V4_MAP_IDX,
    UNTRUST_V6_MAP_IDX,
#ifdef TRUNK_PORT
    BRIDGED_WAN_VLAN_MAP_IDX, // active bridged vlans for wan interface
#endif
    MNET_MAP_IDX, // active vlans for wan interface
    FAILURE_CNT_MAP_IDX, // Process interrupted cause XDP_ABORT or XDP_DROP
    ACTION_V4CNT_MAP_IDX, //
    ACTION_V6CNT_MAP_IDX, //
    DNAT_V4MAP_MAP_IDX, //
    DNAT_V6MAP_MAP_IDX, //
    DNAT_LOCKS_MAP_IDX, //
    BGPNEIGH_V4WL_MAP_IDX,
    BGPNEIGH_V6WL_MAP_IDX,
    TCP_V4WL_MAP_IDX, // Only used for wan and dmz interface as sum of trusted servers that can work with fragmented data
    TCP_V6WL_MAP_IDX, // Only used for wan and dmz interface as sum of trusted servers that can work with fragmented data
    UDP_V4WL_MAP_IDX, // Only used for wan and dmz interface as sum of trusted servers that can work with fragmented data
    UDP_V6WL_MAP_IDX, // Only used for wan and dmz interface as sum of trusted servers that can work with fragmented data
    ICMP_V4WL_MAP_IDX, // Only used for wan and dmz interface as sum of trusted servers (eg. dns, ntp and so on)
    ICMP_V6WL_MAP_IDX, // Only used for wan and dmz interface as sum of trusted servers (eg. dns, ntp and so on)
    RADIUS_V4WL_MAP_IDX, // Maintained for convention
    RADIUS_V6WL_MAP_IDX, // Only used for lan interfaces (nas)
    DNS_V4WL_MAP_IDX,
    DNS_V6WL_MAP_IDX,
    NTP_V4WL_MAP_IDX,
    NTP_V6WL_MAP_IDX,
    VPN_V4WL_MAP_IDX,
    VPN_V6WL_MAP_IDX,
    MXX_V4WL_MAP_IDX,
    MXX_V6WL_MAP_IDX,
    MON_V4WL_MAP_IDX,
    MON_V6WL_MAP_IDX,
    LOG_V4WL_MAP_IDX,
    LOG_V6WL_MAP_IDX,
    DDOS_V4BL_MAP_IDX, // Accept in blacklist only routable Unicast Global address and reject bgp neighbour address and wan neighbour address
    DDOS_V6BL_MAP_IDX, // Accept in blacklist only routable Unicast Global address and reject bgp neighbour address and wan neighbour address
    MAX_MAPS
} idx_t;

typedef struct
{
    struct nlmsghdr header;
    struct ifinfomsg msg;
} nl_req_t;

typedef struct
{
    struct
    {
        struct nlmsghdr hdr;
        struct ifinfomsg msg;
        //	struct rtmsg rtm;
    } req = { 0 };

    int nlfd = EOF;
    struct sockaddr_nl sa_us = { 0 }; /* our local (user space) side of the communication */
    struct msghdr msg = { 0 }; /* generic msghdr struct for use with sendmsg */
    struct nlmsghdr *nh = nullptr; // pointer to current message part
    struct iovec io = { 0 }; /* IO vector for sendmsg */
    char reply_buffer[IFLIST_REPLY_BUFFER]; /* a large buffer to receive lots of link information */
} nl_conn_t;

typedef struct
{
    program_t cld;
    pid_t pid;
    bool rkl;
} cld_stat_t;

/* Export eBPF map for IPv4 blacklist as a file
 * Gotcha need to mount:
 *   mount -t bpf bpf /sys/fs/bpf/
 */

static const char prog_names[PROG_OPT_MAX][MAX_STR_LEN] = { "mienro_wan",
    "mienro_ctr",
    "mienro_lan",
    "mienro_wan_direct",
    "mienro_ctr_direct",
    "mienro_lan_direct" };

static const char file_map[MAX_MAPS][MAX_STR_LEN] = { "",
    "%s%sevents",
    "%s%stxports",
    "%s%sssh_v4tmo",
    "%s%sssh_v6tmo",
    "%s%samasks",
    "%s%suntrust_v4",
    "%s%suntrust_v6",
#ifdef TRUNK_PORT
    "%s%sbrvlan_wl",
#endif
    "%s%sifidx_map",
    "%s%sfail_cnt",
    "%s%sact_v4cnt",
    "%s%sact_v6cnt",
    "%s%sdnat_v4map",
    "%s%sdnat_v6map",
    "%s%sdnat_locks",
    "%s%sbgpn_v4wl",
    "%s%sbgpn_v6wl",
    "%s%stcp_v4wl",
    "%s%stcp_v6wl",
    "%s%sudp_v4wl",
    "%s%sudp_v6wl",
    "%s%sicmp_v4wl",
    "%s%sicmp_v6wl",
    "%s%srad_v4wl",
    "%s%srad_v6wl",
    "%s%sdns_v4wl",
    "%s%sdns_v6wl",
    "%s%sntp_v4wl",
    "%s%sntp_v6wl",
    "%s%svpn_v4wl",
    "%s%svpn_v6wl",
    "%s%smxx_v4wl",
    "%s%smxx_v6wl",
    "%s%smon_v4wl",
    "%s%smon_v6wl",
    "%s%slog_v4wl",
    "%s%slog_v6wl",
    "%s%sddos_v4bl",
    "%s%sddos_v6bl" };

#ifdef TRUNK_PORT
#define MAP_NAMES_COMMON "events",     \
                         "txports",    \
                         "ssh_v4tmo",  \
                         "ssh_v6tmo",  \
                         "amasks",     \
                         "untrust_v4", \
                         "untrust_v6", \
                         "brvlan_wl",  \
                         "ifidx_map",  \
                         "fail_cnt",   \
                         "act_v4cnt",  \
                         "act_v6cnt",  \
                         "dnat_v4map", \
                         "dnat_v6map", \
                         "dnat_locks", \
                         "bgpn_v4wl",  \
                         "bgpn_v6wl",  \
                         "tcp_v4wl",   \
                         "tcp_v6wl",   \
                         "udp_v4wl",   \
                         "udp_v6wl",   \
                         "icmp_v4wl",  \
                         "icmp_v6wl",  \
                         "rad_v4wl",   \
                         "rad_v6wl",   \
                         "dns_v4wl",   \
                         "dns_v6wl",   \
                         "ntp_v4wl",   \
                         "ntp_v6wl",   \
                         "vpn_v4wl",   \
                         "vpn_v6wl",   \
                         "mxx_v4wl",   \
                         "mxx_v6wl",   \
                         "mon_v4wl",   \
                         "mon_v6wl",   \
                         "log_v4wl",   \
                         "log_v6wl",   \
                         "ddos_v4bl",  \
                         "ddos_v6bl"
#else
#define MAP_NAMES_COMMON "events",     \
                         "txports",    \
                         "ssh_v4tmo",  \
                         "ssh_v6tmo",  \
                         "amasks",     \
                         "untrust_v4", \
                         "untrust_v6", \
                         "ifidx_map",  \
                         "fail_cnt",   \
                         "act_v4cnt",  \
                         "act_v6cnt",  \
                         "dnat_v4map", \
                         "dnat_v6map", \
                         "dnat_locks", \
                         "bgpn_v4wl",  \
                         "bgpn_v6wl",  \
                         "tcp_v4wl",   \
                         "tcp_v6wl",   \
                         "udp_v4wl",   \
                         "udp_v6wl",   \
                         "icmp_v4wl",  \
                         "icmp_v6wl",  \
                         "rad_v4wl",   \
                         "rad_v6wl",   \
                         "dns_v4wl",   \
                         "dns_v6wl",   \
                         "ntp_v4wl",   \
                         "ntp_v6wl",   \
                         "vpn_v4wl",   \
                         "vpn_v6wl",   \
                         "mxx_v4wl",   \
                         "mxx_v6wl",   \
                         "mon_v4wl",   \
                         "mon_v6wl",   \
                         "log_v4wl",   \
                         "log_v6wl",   \
                         "ddos_v4bl",  \
                         "ddos_v6bl"
#endif

static const char map_wan_names[MAX_MAPS][MAX_STR_LEN] = { "xdp_wan_tx_ports", MAP_NAMES_COMMON };
static const char map_ctr_names[MAX_MAPS][MAX_STR_LEN] = { "xdp_ctr_tx_ports", MAP_NAMES_COMMON };
static const char map_lan_names[MAX_MAPS][MAX_STR_LEN] = { "xdp_lan_tx_ports", MAP_NAMES_COMMON };
static const char map_pinned_names[MAX_MAPS][MAX_STR_LEN] = { "xdp_lan_tx_ports", MAP_NAMES_COMMON };

static const char xdp_action_names[XDP_ACTION_MAX][MAX_STR_LEN] = { "XDP_ABORTED",
    "XDP_DROP",
    "XDP_PASS",
    "XDP_TX",
    "XDP_REDIRECT",
    "XDP_UNKNOWN" };

class Mienro
{
    const char *classname;
    const Setup *setup;
    const __u32 xdp_flags;
    std::string bpfpath;
    std::string mappath;
    std::string loadpath;
    amasks_t amasks;

    typedef struct
    {
        __u32 txport;
        __u32 xdpport;
        txports_t TxPorts;
    } tx_ports_list_t;

    tx_ports_list_t *tx_ports_list;

    // Verify BPF-filesystem is mounted on given file path
    void bpf_fs_check(void);

	// Verify if path is part of BPF-filesystem
	int bpf_fs_check_path(const char *path);

    // Handle the netlink messages
    void nl_handle_msg(nl_conn_t *, bool *);

public:
    Mienro(class Setup *, const __u32); // ctor

    ~Mienro(); // dtor

    // Attach XDP program to nic device
    void attach(int *) const;

    // Adding ifname as a possible egress TX port
    void set_txports(void);

    // Detach bpf program to nic device
    void detach(void) const;

    // Get the /sys/fs/bpf path
    std::string get_bpfpath(void) const;

    // Get the mapdir in the /sys/fs/bpf filesystem
    std::string get_mappath(void) const;

    // Get the path to the file indicating that mienro is loaded
    std::string get_loadpath(void) const;

    // Close filemap descriptors and remove relatives files
    void map_cleanup(void);

    // Creating a hierarchy of directories into bpf filesystem
    void bpf_fs_prepare(void);

    // Prepare and process netlink request
    void nl_process_req(nl_conn_t *, __u16, pid_t);

    // Handle the netlink messages
    void nl_handle_msg(nl_conn_t *, map<__u32, int> &);

    // Load wan address in array map for kernel program
    void configure_network_interfaces(void);

    // Populate acl maps
    void acl_maps_fill(void);

    // Clear the ssh map used to prevent brute force attacks, from keys that have not been used for a long time
    void ssh_clr_map(void);

    // TODO not needed at moment
    // int export_bpfmap_by_fd( idx_t, enum bpf_map_type, int, int, int, __u32, const char *, uid_t, gid_t );
};

#endif // __XDP_FWD_FER_INCLUDED_H

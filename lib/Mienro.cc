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
#include "Mienro.h"

// Inherited from common.cc
extern const char *projectname;
extern char *progname;
extern program_t progid;
extern FILE *logstream;
extern bool leavelogs;
extern bool disclog;
extern sig_atomic_t _signal;
extern sig_atomic_t _signal_quit;
extern const char *_color;
extern bool _debug;

#define DISPLAYONSUCCESS                                                \
    {                                                                   \
        if (setup->param()[Setup::verbose].cnfdata.vdata.boval == true) \
            LOG(buffer);                                                \
    }

bool _verbose = true;
extern sig_atomic_t _signal;
extern sig_atomic_t _signal_quit;
extern bool disclog;
extern const char *_color;
int map_wan_fd[MAX_MAPS];
int map_ctr_fd[MAX_MAPS];
int map_lan_fd[MAX_MAPS];
int map_pinned_fd[MAX_MAPS]; // warning: this array is used only for compilation code

//
// Name: Mienro
//
// Description: Costructor for Mienro class
//
Mienro::Mienro(class Setup *_S, const __u32 _X) // ctor
    : classname("Mienro")
    , setup(_S)
    , xdp_flags(_X)
    , bpfpath("/sys/fs/bpf/")
    , loadpath("/tmp/.mienroloaded")
{
    if (setup == nullptr)
        THROW("%s: Missing setup configuration.", classname);

    std::string xdpdir = bpfpath + "xdp/";

    std::string bpf_fs_progdir = xdpdir + classname + "/";

    //	mappath = bpf_fs_progdir.append("maps/");
    mappath.append(bpf_fs_progdir);
    mappath.append("maps/");

    memset(&amasks, 0, sizeof(amasks_t));

    // Detect Mienro Interfaces
    tx_ports_list = FCALLOC(tx_ports_list_t, NEW, XDP_PLS_MAX);

    char buf[16192] = { 0 };
    __u16 failcounter = 0;
    __u32 target_idx = 0;
    __u32 parent_idx = 0;
    __u32 master_idx = 0;
    int devtype_id = 0;
    int fd = EOF;
    size_t seq_num = 0;
    struct sockaddr_nl sa = { 0 };
    struct iovec iov = { 0 };
    struct msghdr msg = { 0 };
    struct nlmsghdr *nh;
    nl_req_t req = { 0 };
    std::string kinddevname;
    // These are needed to detect if the controller is on KVM
    std::multimap<__u32, __u32> brmmap;
    std::multimap<__u32, __u32>::iterator it_brmmap;
    std::vector<__u32> tuns;
    std::vector<__u32>::iterator it_tuns;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (fd < 0)
        THROW("Failed to open netlink socket: %s", handle_err());

    req.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.header.nlmsg_type = RTM_GETLINK;
    req.header.nlmsg_seq = ++seq_num;
    req.msg.ifi_family = AF_UNSPEC;
    req.msg.ifi_change = 0xFFFFFFFF;

    sa.nl_family = AF_NETLINK;
    iov.iov_base = &req;
    iov.iov_len = req.header.nlmsg_len;
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof sa;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(fd, &msg, 0) < 0)
        THROW("Failed to sendmsg to netlink socket: %s", handle_err());

    iov.iov_base = buf;
    iov.iov_len = sizeof buf;

    memset(tx_ports_list, 0, (sizeof(tx_ports_list_t) * XDP_PLS_MAX));

    auto lambda_vlan_throw = [&](const bool B)
    {
        if (parent_idx == 0)
            THROW("There is something wrong with the setup of the interface %s", setup->conf_getval((B == true) ? Setup::sshifindex : Setup::dmzifindex).strval);

        if (parent_idx == target_idx)
            THROW("Wrong %s interface: %s. %s", ((B == true) ? "ssh" : "dmz"), setup->conf_getval((B == true) ? Setup::sshifindex : Setup::dmzifindex).strval, "However is not a vlan 802.1Q");

        if (tx_ports_list[CTR_PLS].xdpport == 0)
        {
            tx_ports_list[CTR_PLS].txport = parent_idx;
            tx_ports_list[CTR_PLS].xdpport = parent_idx;
        }
        else if (tx_ports_list[CTR_PLS].xdpport != parent_idx)
            THROW("The %s interface %s%smust be on same physic interface of the controller interface.", ((B == true) ? "ssh" : "dmz"), setup->conf_getval((B == true) ? Setup::sshifindex : Setup::dmzifindex).strval, ((devtype_id == 0) ? " is not a vlan 802.1Q. However " : " "), setup->conf_getval((B == true) ? Setup::sshifindex : Setup::dmzifindex).strval);
    };

    auto lambda_setup = [&]() -> void
    {
        if (target_idx == 0)
            return;

        if (kinddevname.compare("tun") == 0)
            it_tuns = tuns.insert(it_tuns, target_idx);

        if (target_idx == if_nametoindex(setup->conf_getval(Setup::wanifindex).strval))
        {
            tx_ports_list[WAN_PLS].TxPorts.wan = target_idx;
            tx_ports_list[CTR_PLS].TxPorts.wan = target_idx;
            tx_ports_list[LAN_PLS].TxPorts.wan = target_idx;

            if (parent_idx == 0)
            {
                if (tx_ports_list[WAN_PLS].txport > 0)
                    THROW("%s seem duplicated", setup->conf_getval(Setup::wanifindex).strval);

                tx_ports_list[WAN_PLS].txport = target_idx;
                tx_ports_list[WAN_PLS].xdpport = target_idx;
                tx_ports_list[WAN_PLS].TxPorts.wan_xdp = target_idx;
                tx_ports_list[CTR_PLS].TxPorts.wan_xdp = target_idx;
                tx_ports_list[LAN_PLS].TxPorts.wan_xdp = target_idx;
            }
            else if (parent_idx > 0 && (xdp_flags & XDP_FLAGS_SKB_MODE) == XDP_FLAGS_SKB_MODE)
            {
                tx_ports_list[WAN_PLS].txport = target_idx;
                tx_ports_list[WAN_PLS].xdpport = target_idx;

                if (kinddevname.compare("veth") == 0)
                {
                    tx_ports_list[WAN_PLS].TxPorts.wan_xdp = target_idx;
                    tx_ports_list[CTR_PLS].TxPorts.wan_xdp = target_idx;
                    tx_ports_list[LAN_PLS].TxPorts.wan_xdp = target_idx;
                }
                else
                    THROW("Wrong wan interface: %s", setup->conf_getval(Setup::wanifindex).strval);
            }
            else
                THROW("Wrong wan interface: %s", setup->conf_getval(Setup::wanifindex).strval);
        }
        else if (target_idx == if_nametoindex(setup->conf_getval(Setup::sshifindex).strval) && kinddevname.compare("vlan") == 0)
        {
            lambda_vlan_throw(true);

            tx_ports_list[WAN_PLS].TxPorts.ssh = target_idx;
            tx_ports_list[CTR_PLS].TxPorts.ssh = target_idx;
            tx_ports_list[WAN_PLS].TxPorts.ssh_xdp = parent_idx;
            tx_ports_list[CTR_PLS].TxPorts.ssh_xdp = parent_idx;
        }
        else if (target_idx == if_nametoindex(setup->conf_getval(Setup::dmzifindex).strval) && kinddevname.compare("vlan") == 0)
        {
            lambda_vlan_throw(false);

            tx_ports_list[WAN_PLS].TxPorts.dmz = target_idx;
            tx_ports_list[CTR_PLS].TxPorts.dmz = target_idx;
            tx_ports_list[WAN_PLS].TxPorts.dmz_xdp = parent_idx;
            tx_ports_list[CTR_PLS].TxPorts.dmz_xdp = parent_idx;
        }
        else if (target_idx == if_nametoindex(setup->conf_getval(Setup::lanifindex).strval))
        {
            tx_ports_list[WAN_PLS].TxPorts.lan = target_idx;
            tx_ports_list[LAN_PLS].TxPorts.lan = target_idx;

            if (parent_idx == 0)
            {
                if (tx_ports_list[LAN_PLS].txport > 0)
                    THROW("%s seem duplicated", setup->conf_getval(Setup::lanifindex).strval);

                tx_ports_list[LAN_PLS].txport = target_idx;
                tx_ports_list[LAN_PLS].xdpport = target_idx;

                tx_ports_list[WAN_PLS].TxPorts.lan_xdp = target_idx;
                tx_ports_list[LAN_PLS].TxPorts.lan_xdp = target_idx;
            }
            else if (parent_idx > 0)
            {
                if (kinddevname.compare("veth") == 0 && (xdp_flags & XDP_FLAGS_SKB_MODE) == XDP_FLAGS_SKB_MODE)
                {
                    tx_ports_list[LAN_PLS].txport = target_idx;
                    tx_ports_list[LAN_PLS].xdpport = target_idx;

                    tx_ports_list[WAN_PLS].TxPorts.lan_xdp = target_idx;
                    tx_ports_list[LAN_PLS].TxPorts.lan_xdp = target_idx;
                }
#ifdef TRUNK_PORT
                else if (kinddevname.compare("vlan") == 0)
                {
                    tx_ports_list[LAN_PLS].txport = parent_idx;
                    tx_ports_list[LAN_PLS].xdpport = parent_idx;

                    tx_ports_list[WAN_PLS].TxPorts.lan_xdp = parent_idx;
                    tx_ports_list[LAN_PLS].TxPorts.lan_xdp = parent_idx;
                }
#endif
                else
                    THROW("Wrong lan interface: %s", setup->conf_getval(Setup::lanifindex).strval);
            }
            else
                THROW("Wrong lan interface: %s", setup->conf_getval(Setup::lanifindex).strval);
        }
    };

    auto lambda_bridge_slave = [&](const __u32 bridge_master_idx, __u32 &bridge_slave_idx)
    {
        std::vector<__u32> bridge_slaves;
        std::vector<__u32>::iterator it_bridge_slaves;

        std::pair<std::multimap<__u32, __u32>::iterator, std::multimap<__u32, __u32>::iterator> ret = brmmap.equal_range(bridge_master_idx);

        for (std::multimap<__u32, __u32>::iterator it = ret.first; it != ret.second; ++it)
            it_bridge_slaves = bridge_slaves.insert(it_bridge_slaves, it->second);

        if (bridge_slaves.size() > 0)
        {
            std::sort(bridge_slaves.begin(), bridge_slaves.end());
            bridge_slave_idx = bridge_slaves[0];
            bridge_slaves.clear();
        }
        else
            bridge_slave_idx = 0; // setting it to 0 means that bridge_master_idx actually is not a bridge interface
    };

    it_tuns = tuns.begin();

    while (true)
    {
        if (_signal == SIGINT)
            THROW("Interrupted...");

        if (failcounter > 64)
            THROW("Failed to rcvmsg to netlink socket: %s", handle_err());

        ssize_t len = recvmsg(fd, &msg, MSG_DONTWAIT);

        if (len < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                usleep(250000);
                continue;
            }

            LOG("Failed to read netlink: %s", handle_err());
            failcounter++;
            continue;
        }

        failcounter = 0;

        for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (__u32)len); nh = NLMSG_NEXT(nh, len))
        {
            if (_signal == SIGINT)
                THROW("Interrupted...");

            size_t len, info_len, devtype_len;
            struct ifinfomsg *msg;
            struct rtattr *rta, *info, *devtype;

            if (nh->nlmsg_type == NLMSG_DONE)
                goto nldone;

            if (nh->nlmsg_type != RTM_BASE)
                continue;

            msg = (struct ifinfomsg *)NLMSG_DATA(nh); // message payload

            if (msg->ifi_type != ARPHRD_ETHER)
                continue;

            lambda_setup();

            target_idx = 0;
            parent_idx = 0;
            master_idx = 0;
            devtype_id = 0;

            target_idx = msg->ifi_index;

            rta = IFLA_RTA(msg); // message attributes
            len = nh->nlmsg_len - NLMSG_LENGTH(sizeof *msg);

            for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
            {
                if (_signal == SIGINT)
                    THROW("Interrupted...");

                switch (rta->rta_type)
                {
                case IFLA_LINK:
                    parent_idx = *(__u16 *)((char *)rta + NLA_HDRLEN);
                    break;
                case IFLA_MASTER:
                    master_idx = *(__u16 *)((char *)rta + NLA_HDRLEN);
                    break;
                default:
                    break;
                }

                if (rta->rta_type == IFLA_LINKINFO)
                {
                    info = (rtattr *)RTA_DATA(rta);
                    info_len = RTA_PAYLOAD(rta);

                    while (RTA_OK(info, info_len))
                    {
                        if (_signal == SIGINT)
                            THROW("Interrupted...");

                        if (info->rta_type == IFLA_INFO_KIND)
                        {
                            kinddevname.clear();

                            if (strcmp((char *)RTA_DATA(info), "vlan") == 0)
                            {
                                kinddevname.assign("vlan");

                                info = RTA_NEXT(info, info_len);

                                if (RTA_OK(info, info_len))
                                {
                                    if (info->rta_type == IFLA_INFO_DATA)
                                    {
                                        devtype = (rtattr *)RTA_DATA(info);
                                        devtype_len = RTA_PAYLOAD(info);

                                        while (RTA_OK(devtype, devtype_len))
                                        {
                                            if (devtype->rta_type == IFLA_VLAN_ID)
                                                devtype_id = *(int *)RTA_DATA(devtype);

                                            devtype = RTA_NEXT(devtype, devtype_len);
                                        }
                                    }
                                }
                                else
                                    break;
                            }
                            else if (strncmp((char *)RTA_DATA(info), "bridge", IFNAMSIZ) == 0)
                                kinddevname.assign("bridge");
                            else if (strncmp((char *)RTA_DATA(info), "tun", IFNAMSIZ) == 0)
                                kinddevname.assign("tun");
                            else if (strncmp((char *)RTA_DATA(info), "veth", IFNAMSIZ) == 0)
                                kinddevname.assign("veth");
                        }
                        else if (info->rta_type == IFLA_INFO_SLAVE_KIND)
                        {
                            //							kinddevname.clear();

                            if (strncmp((char *)RTA_DATA(info), "bridge", IFNAMSIZ) == 0)
                            {
                                brmmap.insert(std::pair<__u32, __u32>(master_idx, target_idx));
                                //	brmmap.insert (std::pair<__u32, __u32>(master_idx, 32));
                                //	it_brmmap = brmmap.insert(std::pair<__u32, __u32>(master_idx, 33));
                                //	brmmap.insert(it_brmmap, std::pair<__u32, __u32>(master_idx, 34)); // useful for sequential inserts
                            }
                        }

                        info = RTA_NEXT(info, info_len);
                    }
                }
            }
        }
    }

nldone:

    close(fd);
    fd = EOF;

    lambda_setup();

    lambda_bridge_slave(tx_ports_list[CTR_PLS].txport, tx_ports_list[CTR_PLS].xdpport);

    if (tx_ports_list[CTR_PLS].xdpport > 0)
    {
        if (tx_ports_list[CTR_PLS].xdpport == tx_ports_list[CTR_PLS].txport)
            THROW("The controller interface is a bridge interface but it must have one slave interface.");
        else
        {
            bool checktun = false;

            for (it_tuns = tuns.begin(); it_tuns < tuns.end(); it_tuns++)
                if (*it_tuns == tx_ports_list[CTR_PLS].xdpport)
                {
                    checktun = true;
                    break;
                }

            if (checktun == false)
            {
                char name[IFNAMSIZ] = { 0 };
                if_indextoname(tx_ports_list[CTR_PLS].xdpport, name);
                THROW("There is something wrong with the setup of the controller %s interface because it is a brigde without tun interface.", name);
            }

            tx_ports_list[WAN_PLS].TxPorts.ssh_xdp = tx_ports_list[CTR_PLS].xdpport;
            tx_ports_list[CTR_PLS].TxPorts.ssh_xdp = tx_ports_list[CTR_PLS].xdpport;
            tx_ports_list[WAN_PLS].TxPorts.dmz_xdp = tx_ports_list[CTR_PLS].xdpport;
            tx_ports_list[CTR_PLS].TxPorts.dmz_xdp = tx_ports_list[CTR_PLS].xdpport;
        }
    }
    else
        tx_ports_list[CTR_PLS].xdpport = tx_ports_list[CTR_PLS].txport; // see lambda_bridge_slave function to understand this operation
#ifdef TRUNK_PORT
    lambda_bridge_slave(tx_ports_list[WAN_PLS].txport, tx_ports_list[WAN_PLS].xdpport);

    if (tx_ports_list[WAN_PLS].xdpport > 0)
    {
        if (tx_ports_list[WAN_PLS].xdpport == tx_ports_list[WAN_PLS].txport)
            THROW("The wan interface is a bridge interface but it must have one slave interface.");
        else if ((xdp_flags & XDP_FLAGS_SKB_MODE) == XDP_FLAGS_SKB_MODE)
        {
            bool checktun = false;

            for (it_tuns = tuns.begin(); it_tuns < tuns.end(); it_tuns++)
                if (*it_tuns == tx_ports_list[WAN_PLS].xdpport)
                {
                    checktun = true;
                    break;
                }

            if (checktun == false)
            {
                char name[IFNAMSIZ] = { 0 };
                if_indextoname(tx_ports_list[WAN_PLS].txport, name);
                THROW("There is something wrong with the setup of the %s interface because it is not a tun interface.", name);
            }

            tx_ports_list[WAN_PLS].TxPorts.wan_xdp = tx_ports_list[WAN_PLS].xdpport;
            tx_ports_list[CTR_PLS].TxPorts.wan_xdp = tx_ports_list[WAN_PLS].xdpport;
            tx_ports_list[LAN_PLS].TxPorts.wan_xdp = tx_ports_list[WAN_PLS].xdpport;
        }
        else
        {
            char name[IFNAMSIZ] = { 0 };
            if_indextoname(tx_ports_list[WAN_PLS].xdpport, name);
            THROW("There is something wrong with the setup of the wan %s interface because with XDP enabled it must be at least a physic interface.", name);
        }
    }
    else
        tx_ports_list[WAN_PLS].xdpport = tx_ports_list[WAN_PLS].txport; // see lambda_bridge_slave function to understand this operation

    lambda_bridge_slave(tx_ports_list[LAN_PLS].txport, tx_ports_list[LAN_PLS].xdpport);

    if (tx_ports_list[LAN_PLS].xdpport > 0)
    {
        if (tx_ports_list[LAN_PLS].xdpport == tx_ports_list[LAN_PLS].txport)
            THROW("The lan interface is a bridge interface but it must have one slave interface.");
        else if ((xdp_flags & XDP_FLAGS_SKB_MODE) == XDP_FLAGS_SKB_MODE)
        {
            bool checktun = false;

            for (it_tuns = tuns.begin(); it_tuns < tuns.end(); it_tuns++)
                if (*it_tuns == tx_ports_list[LAN_PLS].xdpport)
                {
                    checktun = true;
                    break;
                }

            if (checktun == false)
            {
                char name[IFNAMSIZ] = { 0 };
                if_indextoname(tx_ports_list[LAN_PLS].xdpport, name);
                THROW("There is something wrong with the setup of the %s interface because it is not a tun interface.", name);
            }

            tx_ports_list[WAN_PLS].TxPorts.lan_xdp = tx_ports_list[LAN_PLS].xdpport;
            tx_ports_list[LAN_PLS].TxPorts.lan_xdp = tx_ports_list[LAN_PLS].xdpport;
        }
        else
        {
            char name[IFNAMSIZ] = { 0 };
            if_indextoname(tx_ports_list[LAN_PLS].xdpport, name);
            THROW("There is something wrong with the setup of the lan %s interface because with XDP enabled it must be at least a physic interface.", name);
        }
    }
    else
    { // as normal trunk configuration lan xdp port must be the parent of the vlan interface
        tx_ports_list[LAN_PLS].xdpport = tx_ports_list[LAN_PLS].txport; // see lambda_bridge_slave function to understand this operation
        tx_ports_list[LAN_PLS].txport = tx_ports_list[LAN_PLS].TxPorts.lan;
    }

    if (strnlen(setup->conf_getval(Setup::wanifindex).strval, IFNAMSIZ) >= IFNAMSIZ)
        THROW("Wan interface name tool long.");
    else if (strnlen(setup->conf_getval(Setup::sshifindex).strval, IFNAMSIZ) >= IFNAMSIZ)
        THROW("Ssh interface name tool long.");
    else if (strnlen(setup->conf_getval(Setup::dmzifindex).strval, IFNAMSIZ) >= IFNAMSIZ)
        THROW("Dmz interface name tool long.");
    else if (strnlen(setup->conf_getval(Setup::lanifindex).strval, IFNAMSIZ) >= IFNAMSIZ)
        THROW("Lan interface name tool long.");

//	cout << tx_ports_list[CTR_PLS].xdpport << "==" << tx_ports_list[CTR_PLS].txport << endl;
//	cout << tx_ports_list[WAN_PLS].xdpport << "==" << tx_ports_list[WAN_PLS].txport << endl;
//	cout << tx_ports_list[LAN_PLS].xdpport << "==" << tx_ports_list[LAN_PLS].txport << endl;
#endif

#ifndef TRUNK_PORT
    assert(tx_ports_list[WAN_PLS].xdpport == tx_ports_list[WAN_PLS].txport);
    assert(tx_ports_list[LAN_PLS].xdpport == tx_ports_list[LAN_PLS].txport);
#endif
}

//
// Name: ~Mienro
//
// Description: Destructor for Mienro class
//
Mienro::~Mienro() // dtor
{
    delete[] tx_ports_list;
}

//
// Name: Mienro::bpf_fs_check
//
// Description: Verify BPF-filesystem is mounted on given file path
//
// Input:
//
// Output:
//
// Return:
//
void Mienro::bpf_fs_check(void)
{
    struct statfs stfs;

    if (statfs((char *)bpfpath.c_str(), &stfs))
        THROW("ERR: failed to statfs %s: (%d)%s", bpfpath.c_str(), errno, handle_err());

    if (stfs.f_type != BPF_FS_MAGIC)
        THROW("ERR: %s is not a BPF FS\n\n"
              " You need to mount the BPF filesystem type like:\n"
              " mount -t bpf bpf /sys/fs/bpf/\n\n",
            bpfpath);
}

//
// Name: Mienro::bpf_fs_check_path
//
// Description: Verify if path is part of BPF-filesystem
//
// Input:
//  path - the path to check
//
// Output:
//
// Return:
//
int Mienro::bpf_fs_check_path(const char *path)
{
    struct statfs st_fs;
    char *dname, *dir;
    int err = 0;

    if (path == nullptr)
        return -EINVAL;

    dname = strdup(path);
    if (dname == nullptr)
        return -ENOMEM;

    dir = dirname(dname);

    if (statfs(dir, &st_fs))
    {
        fprintf(stderr, "ERR: failed to statfs %s: (%d)%s\n", dir, errno, handle_err());
        err = -errno;
    }

    free(dname);

    if (!err && st_fs.f_type != BPF_FS_MAGIC)
    {
        fprintf(stderr,
            "ERR: specified path %s is not on BPF FS\n\n"
            " You need to mount the BPF filesystem type like:\n"
            "  mount -t bpf bpf /sys/fs/bpf/\n\n",
            path);
        err = -EINVAL;
    }

    return err;
}

//
// Name: Mienro::nl_handle_msg
//
// Description: handle the netlink messages
//
// Input:
//  conn - the netlink message header
//  configured_ifaces - save a list o configured network interfaces
//
// Output:
//
// Return:
//
void Mienro::nl_handle_msg(nl_conn_t *conn, bool *configured_ifaces)
{
    char buffer[MAX_STR_LEN];

    if (conn->nh->nlmsg_type == RTM_NEWADDR || conn->nh->nlmsg_type == RTM_DELADDR)
    {
        struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(conn->nh);

        if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
            return;

        struct rtattr *rth = IFA_RTA(ifa);
        int rtl = IFA_PAYLOAD(conn->nh);

        while (rtl && RTA_OK(rth, rtl))
        {
            if (rth->rta_type == IFA_ADDRESS)
            {
                char name[IFNAMSIZ] = { 0 };
                if_indextoname(ifa->ifa_index, name);
                char ipv4address[INET_ADDRSTRLEN] = { 0 };
                char ipv6address[INET6_ADDRSTRLEN] = { 0 };
                auto key = UNTRUSTED_MAX;
                const char *keyname = nullptr;
                int ret = EOF;

                if ((ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6))
                {
                    if (ifa->ifa_index == if_nametoindex(setup->conf_getval(Setup::wanifindex).strval))
                    {
                        key = UNTRUSTED_TO_WAN;
                        keyname = setup->list[Setup::wanifindex];
                    }
                    else if (ifa->ifa_index == if_nametoindex(setup->conf_getval(Setup::sshifindex).strval))
                    {
                        key = UNTRUSTED_TO_SSH;
                        keyname = setup->list[Setup::sshifindex];
                    }
                    else if (ifa->ifa_index == if_nametoindex(setup->conf_getval(Setup::dmzifindex).strval))
                    {
                        key = UNTRUSTED_TO_DMZ;
                        keyname = setup->list[Setup::dmzifindex];
                    }
                    else if (ifa->ifa_index == if_nametoindex(setup->conf_getval(Setup::lanifindex).strval))
                    {
                        key = UNTRUSTED_TO_LAN;
                        keyname = setup->list[Setup::lanifindex];
                    }
                    else
                    {
                        rth = RTA_NEXT(rth, rtl);
                        continue;
                    }

                    if (keyname)
                    {
                        if (setup->conf_getval(Setup::lbhf).longval != 0x00000001 && setup->conf_getval(Setup::lbhf).longval != 0x00000003 && setup->conf_getval(Setup::lbhf).longval != 0x00000007 && setup->conf_getval(Setup::lbhf).longval != 0x0000000f && setup->conf_getval(Setup::lbhf).longval != 0x0000001f)
                            THROW("Invalid reverse bitmask for %s configuration paramenter. Hint: check systemd-networkd config file.", setup->list[Setup::lbhf]);

                        if (ifa->ifa_family == AF_INET)
                        {
                            __u8 loop_required_cidr = (sizeof(in4_addr) * CHAR_BIT);
                            const __u8 mincidr = 26, maxcidr = 31;
                            ipv4address[0] = ASCII_NUL;
                            inet_ntop(AF_INET, RTA_DATA(rth), ipv4address, INET_ADDRSTRLEN);

                            __u8 bits = setup->conf_getval(Setup::lbhf).longval;

                            do
                                loop_required_cidr--;
                            while (bits >>= 1);

                            switch (key)
                            {
                            case UNTRUSTED_TO_SSH:
                                if (*((in4_addr *)RTA_DATA(rth)) != 0xFFFFA8C0)
                                    THROW("IPv4 address for interface %s can be only 192.168.255.255. Hint: check systemd-networkd config file.", keyname);
                                break;
                            case UNTRUSTED_TO_DMZ:
                                if (ifa->ifa_prefixlen != 31) // accept address in network with cidr 31
                                    THROW("Cidr must be 31 for %s network. Hint: check systemd-networkd config file.", keyname);

                                this->amasks.dmz = ifa->ifa_prefixlen << 8;
                                break;
                            case UNTRUSTED_TO_LAN:
                                if ((*((in4_addr *)RTA_DATA(rth)) & 0x0000F0FF) != 0x000010AC)
                                    THROW("The %s network must be part of 172.16.0.0/12. Hint: check systemd-networkd config file.", keyname);

                                if (ifa->ifa_prefixlen < mincidr) // accept address in network with cidr major than 25
                                    THROW("Cidr cannot be minor than %u for %s network. Hint: check systemd-networkd config file.", mincidr, keyname);

                                if (ifa->ifa_prefixlen > maxcidr) // network lan is too small
                                    THROW("Cidr is too high for %s network. Hint: check systemd-networkd config file.", keyname);

                                if (ifa->ifa_prefixlen >= loop_required_cidr)
                                    THROW("Insufficient %s network cidr (%u) for %s cidr (%u). Hint: check systemd-networkd config file.", keyname, ifa->ifa_prefixlen, setup->list[Setup::lbhf], loop_required_cidr);

                                this->amasks.lan = ifa->ifa_prefixlen << 8;
                                this->amasks.lop = loop_required_cidr << 8;
                                break;
                            default:
                                this->amasks.wan = ifa->ifa_prefixlen << 8;
                                break;
                            }

                            if ((ret = bpf_map_update_elem(map_wan_fd[UNTRUST_V4_MAP_IDX], &key, (in4_addr *)RTA_DATA(rth), 0)) == 0)
                            {
                                snprintf(buffer, MAX_STR_LEN, "%s%s(Local addresses interface ...ACTION_ADD) IP:%s key:%s%s", GRE, __func__, ipv4address, keyname, NOR);

                                DISPLAYONSUCCESS;
                            }
                        }
                        else if (ifa->ifa_family == AF_INET6)
                        {
                            __u8 loop_required_cidr = (sizeof(struct in6_addr) * CHAR_BIT);
                            const __u8 mincidr = 122, maxcidr = 127;
                            ipv6address[0] = ASCII_NUL;
                            inet_ntop(AF_INET6, RTA_DATA(rth), ipv6address, INET6_ADDRSTRLEN);

                            __u8 bits = setup->conf_getval(Setup::lbhf).longval;

                            do
                                loop_required_cidr--;
                            while (bits >>= 1);

                            if (((*((struct in6_addr *)RTA_DATA(rth))).s6_addr16[0] & 0xC0FF) == 0x80FE) // skip ipv6 link-local addresses
                                continue;

                            switch (key)
                            {
                            case UNTRUSTED_TO_SSH:
                                if (configured_ifaces)
                                {
                                    if ((*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[0] == 0xFFFFFFFD && (*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[1] == 0xFFFFFFFF && (*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[2] == 0xFFFFFFFF && (*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[3] == 0xFFFFFF1F)
                                        configured_ifaces[key] = true;
                                    else
                                        THROW("IPv6 address for interface %s can be only fdff:ffff:ffff:ffff:ffff:ffff:1fff:ffff. Hint: check systemd-networkd config file.", keyname);
                                }
                                else
                                {
                                    if ((*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[0] == 0xFFFFFFFD && (*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[1] == 0xFFFFFFFF && (*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[2] == 0xFFFFFFFF && (*((struct in6_addr *)RTA_DATA(rth))).s6_addr32[3] == 0xFFFFFF1F)
                                        ;
                                    else
                                        THROW("IPv6 address for interface %s can be only fdff:ffff:ffff:ffff:ffff:ffff:1fff:ffff. Hint: check systemd-networkd config file.", keyname);
                                }
                                break;
                            case UNTRUSTED_TO_DMZ:
                                if (ifa->ifa_prefixlen != maxcidr) // accept address in network with cidr 127
                                    THROW("Cidr must be 127 for %s network. Hint: check systemd-networkd config file.", keyname);
                                else if (configured_ifaces)
                                    configured_ifaces[key] = true;

                                this->amasks.dmz = ((this->amasks.dmz & 0xFF00) | ifa->ifa_prefixlen);
                                break;
                            case UNTRUSTED_TO_LAN:
                                if (((*((struct in6_addr *)RTA_DATA(rth))).s6_addr[0] & 0xFE) != 0xFC)
                                    THROW("The %s network must be part of fc00::/7. Hint: check systemd-networkd config file.", keyname);

                                if (ifa->ifa_prefixlen < mincidr) // accept address in network with cidr 122
                                    THROW("Cidr cannot be minor than %u for %s network. Hint: check systemd-networkd config file.", mincidr, keyname);
                                else if (configured_ifaces)
                                    configured_ifaces[key] = true;

                                if (ifa->ifa_prefixlen > maxcidr) // network lan is too small
                                    THROW("Cidr is too high for %s network. Hint: check systemd-networkd config file.", keyname);

                                if (ifa->ifa_prefixlen >= loop_required_cidr)
                                    THROW("Insufficient %s network cidr (%u) for %s cidr (%u). Hint: check systemd-networkd config file.", keyname, ifa->ifa_prefixlen, setup->list[Setup::lbhf], loop_required_cidr);

                                this->amasks.lan = ((this->amasks.lan & 0xFF00) | ifa->ifa_prefixlen);
                                this->amasks.lop = ((this->amasks.lop & 0xFF00) | loop_required_cidr);
                                break;
                            default:
                                this->amasks.wan = ((this->amasks.wan & 0xFF00) | ifa->ifa_prefixlen);
                                break;
                            }

                            if ((ret = bpf_map_update_elem(map_wan_fd[UNTRUST_V6_MAP_IDX], &key, (struct in6_addr *)RTA_DATA(rth), 0)) == 0)
                            {
                                snprintf(buffer, MAX_STR_LEN, "%s%s(Local addresses interface ...ACTION_ADD) IP:%s key:%s%s", GRE, __func__, ipv6address, keyname, NOR);

                                DISPLAYONSUCCESS;
                            }
                        }
                    }
                }

                if ((ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6) && ret != 0) // 0 == success
                {
                    if (errno == 17) // already in list
                    {
                        rth = RTA_NEXT(rth, rtl);
                        continue;
                    }

                    if (keyname)
                    {
                        if (ifa->ifa_family == AF_INET)
                            snprintf(buffer, MAX_STR_LEN, "%s%s() IP:%s key:%s ", RED, __func__, ipv4address, keyname);
                        if (ifa->ifa_family == AF_INET6)
                            snprintf(buffer, MAX_STR_LEN, "%s%s() IP:%s key:%s ", RED, __func__, ipv6address, keyname);

                        if (errno)
                            THROW("Cannot update map (bpf_map_update_elem errno(%d/%s))", errno, handle_err());

                        DISPLAYONSUCCESS;
                    }
                    else
                        THROW("Cannot get local address errno(%d/%s)", errno, handle_err());
                }
            }

            rth = RTA_NEXT(rth, rtl);
        }
    }

    return;
}

//
// Name: Mienro::bpf_fs_prepare
//
// Description: Creating a hierarchy of directories into bpf filesystem
//
// Input:
//
// Output:
//
// Return:
//
void Mienro::bpf_fs_prepare()
{
    bool found = false;
    struct stat64 statbuf;

    bpf_fs_check();

    std::string xdpdir = bpfpath + "xdp/";
    std::string bpf_fs_progdir = xdpdir + classname + "/";

    if (stat64(mappath.c_str(), &statbuf) == 0 && S_ISDIR(statbuf.st_mode))
        found = true;

    // Create directories
    if (found == false)
        std::cerr << "Creating a hierarchy of directories ...";

    int rc = mkdir(xdpdir.c_str(), 0777);

    if (rc != 0 && errno != EEXIST)
        THROW("Failed to create %s directory: %s", xdpdir.c_str(), handle_err());

    rc = mkdir(bpf_fs_progdir.c_str(), 0777);

    if (rc != 0 && errno != EEXIST)
        THROW("Failed to create %s directory: %s", bpf_fs_progdir.c_str(), handle_err());

    rc = mkdir(mappath.c_str(), 0777);

    if (rc != 0 && errno != EEXIST)
        THROW("Failed to create %s directory: %s", mappath.c_str(), handle_err());

    std::queue<string> dirs;
    dirs.push("lanif");
    dirs.push("ctrif");
    dirs.push("wanif");

    while (!dirs.empty())
    {
        char dirname[PATH_MAX];
        snprintf(dirname, PATH_MAX, "%s%s", mappath.c_str(), dirs.front().c_str());
        dirs.pop();

        int rc = mkdir(dirname, 0777);

        if (rc != 0 && errno != EEXIST)
            THROW("Failed to create %s directory: %s", dirname, handle_err());
    }

    if (found == false)
        std::cerr << " done " << std::endl;
}

//
// Name: Mienro::nl_process_req
//
// Description: prepare and process netlink request
//
// Input:
//  conn - the connection data to be prepared
//  pid - the pid of this process
//
// Output:
//
// Return:
//
void Mienro::nl_process_req(nl_conn_t *conn, __u16 nlmsg_type, pid_t pid)
{
    memset(&conn->sa_us, 0, sizeof(struct sockaddr_nl));
    conn->sa_us.nl_family = AF_NETLINK;

    switch (nlmsg_type)
    {
    case RTM_GETLINK:
        if (bind(conn->nlfd, (struct sockaddr *)&conn->sa_us, sizeof(conn->sa_us)) < 0)
        {
            perror("Cannot bind, are you root ? if yes, check netlink/rtnetlink kernel support");
            close(conn->nlfd);
            conn->nlfd = EOF;
            exit(EXIT_FAILURE);
        }
    case RTM_GETADDR:
    case RTM_GETROUTE:
        break;
    default:
        conn->sa_us.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
        conn->sa_us.nl_pid = pid; // Port ID

        if (bind(conn->nlfd, (struct sockaddr *)&conn->sa_us, sizeof(conn->sa_us)) < 0)
        {
            perror("Cannot bind, are you root ? if yes, check netlink/rtnetlink kernel support");
            close(conn->nlfd);
            conn->nlfd = EOF;
            exit(EXIT_FAILURE);
        }
        break;
    }

    memset(&conn->req, 0, sizeof(conn->req));
    memset(&conn->io, 0, sizeof(struct iovec));
    memset(&conn->msg, 0, sizeof(struct msghdr));
    conn->req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    ;
    conn->req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    conn->req.hdr.nlmsg_type = nlmsg_type;
    conn->req.hdr.nlmsg_seq = time(NULL);
    conn->req.hdr.nlmsg_pid = pid;
    conn->req.msg.ifi_family = AF_UNSPEC;
    conn->req.msg.ifi_change = 0xFFFFFFFF;
    conn->req.msg.ifi_change = IFF_UP;
    conn->req.msg.ifi_flags = IFF_UP;
    conn->req.msg.ifi_index = ~0;
    conn->io.iov_base = &conn->req;
    conn->io.iov_len = conn->req.hdr.nlmsg_len;
    conn->msg.msg_iov = &conn->io;
    conn->msg.msg_iovlen = 1;
    conn->msg.msg_name = &conn->sa_us;
    conn->msg.msg_namelen = sizeof(conn->sa_us);

    sendmsg(conn->nlfd, (struct msghdr *)&conn->msg, 0);

    /* parse reply */
    conn->io.iov_base = conn->reply_buffer;
    conn->io.iov_len = IFLIST_REPLY_BUFFER;
}

//
// Name: Mienro::nl_handle_msg
//
// Description: handle the netlink messages. This function is called from load.cc
//
// Input:
//  conn - the netlink message header called from external
//  ifidx_map - idx list to save inside std::map accepted by reference
//
// Output:
//
// Return:
//
void Mienro::nl_handle_msg(nl_conn_t *conn, map<__u32, int> &ifidx_map)
{
    char buffer[MAX_STR_LEN];

    if (conn->nh->nlmsg_type == RTM_NEWADDR || conn->nh->nlmsg_type == RTM_DELADDR)
    {
        /* struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(conn->nh);

        if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
                return;

        struct rtattr *rth = IFA_RTA(ifa);
        int rtl = IFA_PAYLOAD(conn->nh);

        while (rtl && RTA_OK(rth, rtl))
        {
                if (rth->rta_type == IFA_ADDRESS)
                {
                        char name[IFNAMSIZ] = {0};
                        if_indextoname(ifa->ifa_index, name);
                        char ipv4address[INET_ADDRSTRLEN] = {0};
                        char ipv6address[INET6_ADDRSTRLEN] = {0};
                        inet_ntop(ifa->ifa_family, RTA_DATA(rth), (ifa->ifa_family == AF_INET) ? ipv4address : ipv6address, (ifa->ifa_family == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);

                        LOG("interface %s (%d) scope %d ip: %s/%d %s", name, ifa->ifa_index, ifa->ifa_scope, (ifa->ifa_family == AF_INET) ? ipv4address : ipv6address, ifa->ifa_prefixlen, ((conn->nh->nlmsg_type == RTM_NEWADDR) ? "added" : "removed"));
                }

                rth = RTA_NEXT(rth, rtl);
        } */

        return;
    }
    else if (conn->nh->nlmsg_type == RTM_NEWROUTE || conn->nh->nlmsg_type == RTM_DELROUTE)
    {
        struct rtmsg *route_entry = (struct rtmsg *)NLMSG_DATA(conn->nh);

        // filter here is not optimal for performances reasons but this a netlink limit at the moment
        if (route_entry->rtm_table != RT_TABLE_MAIN && route_entry->rtm_scope != RT_SCOPE_UNIVERSE)
            return;

        if (route_entry->rtm_protocol != RTPROT_BOOT && // for routes changes
            route_entry->rtm_protocol != RTPROT_STATIC) // for already present routes
            return;

        struct rtattr *rta; // This struct contain route attributes (route type)
        int rta_len = 0;
        in4_addr dst_ipv4addr = 0;
        //		in4_addr gw_ipv4addr = 0;
        struct in6_addr dst_ipv6addr = { 0 };
        //		struct in6_addr gw_ipv6addr = {0};
        char dst_ipv4address[INET_ADDRSTRLEN] = { 0 };
        //		char gw_ipv4address[INET_ADDRSTRLEN] = {0};
        char dst_ipv6address[INET6_ADDRSTRLEN] = { 0 };
        //		char gw_ipv6address[INET6_ADDRSTRLEN] = {0};
        __u32 ifidx = 0;
        // #endif
        rta = (struct rtattr *)RTM_RTA(route_entry);
        rta_len = RTM_PAYLOAD(conn->nh); // Get the route atttibutes len

        // Loop through all attributes
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len))
        {
            // Get the destination address
            if (rta->rta_type == RTA_DST)
            {
                inet_ntop(route_entry->rtm_family, RTA_DATA(rta), (route_entry->rtm_family == AF_INET) ? dst_ipv4address : dst_ipv6address, (route_entry->rtm_family == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);

                if (route_entry->rtm_family == AF_INET)
                    dst_ipv4addr = *(in4_addr *)RTA_DATA(rta);
                else
                    memcpy(&dst_ipv6addr, RTA_DATA(rta), sizeof(struct in6_addr));
            }

            /* Get the gateway (Next hop)
            if (rta->rta_type == RTA_GATEWAY)
            {
                    inet_ntop(route_entry->rtm_family, RTA_DATA(rta), (route_entry->rtm_family == AF_INET) ? gw_ipv4address : gw_ipv6address, (route_entry->rtm_family == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);

                    if (route_entry->rtm_family == AF_INET)
                            gw_ipv4addr = *(in4_addr *)RTA_DATA(rta);
                    else
                            memcpy(&gw_ipv6addr, RTA_DATA(rta), sizeof(struct in6_addr));
            } */

            if (rta->rta_type == RTA_OIF)
                ifidx = *(__u32 *)RTA_DATA(rta);
        }

        if (route_entry->rtm_protocol == RTPROT_BOOT || route_entry->rtm_protocol == RTPROT_STATIC)
        {
#ifdef TRUNK_PORT
            int err = EOF;
            __u32 if_idx = 0;
            __u32 prev_if_idx = ~0;
#endif
            if ((route_entry->rtm_family == AF_INET) ? route_entry->rtm_dst_len == (sizeof(in4_addr) * CHAR_BIT) : route_entry->rtm_dst_len == (sizeof(struct in6_addr) * CHAR_BIT)) // check max cidr
            {
                ifidx_t ifinfo = { 0 };
                ingress_vlan_t vlaninfo = { 0 };
#ifdef TRUNK_PORT
                while (bpf_map_get_next_key(map_pinned_fd[MNET_MAP_IDX], &prev_if_idx, &if_idx) == 0)
                {
                    if (ifidx == if_idx && (err = bpf_map_lookup_elem_flags(map_pinned_fd[MNET_MAP_IDX], &if_idx, &ifinfo, BPF_F_LOCK)) && setup->param()[Setup::verbose].cnfdata.vdata.boval == true)
                        LOG("Failed looking index interface %u on %s map (ret: %d)", if_idx, map_wan_names[MNET_MAP_IDX], err);

                    if (ifinfo.xdp_idx == tx_ports_list[WAN_PLS].xdpport)
                    {
                        if (ifinfo.vlan_id == 0)
                            return;

                        break;
                    }
                    else
                        memset(&ifinfo, 0, sizeof(ifidx_t));

                    prev_if_idx = if_idx;
                }

                if (ifinfo.vlan_id == 0)
                    return;
#else
                if (ifidx != tx_ports_list[WAN_PLS].txport)
                    return;
#endif
                vlaninfo.vlan_id = ifinfo.vlan_id;

                if (route_entry->rtm_family == AF_INET)
                {
                    ingress_vlan_t vlan_info = { 0 };

                    if (bpf_map_lookup_elem_flags(map_pinned_fd[BGPNEIGH_V4WL_MAP_IDX], &dst_ipv4addr, &vlan_info, BPF_F_LOCK) == 0 && vlan_info.vlan_id == 0x0FFF) // bgp server blacklist can be only inserted during startup
                        return;

                    if (conn->nh->nlmsg_type == RTM_NEWROUTE && bpf_map_update_elem(map_pinned_fd[BGPNEIGH_V4WL_MAP_IDX], &dst_ipv4addr, &vlaninfo, (BPF_F_LOCK | BPF_ANY)) == 0)
                    {
                        snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp neighbor for wan interface%s%s ...ACTION_ADD) Ip:%s Vlan id:%d%s", GRE, __func__, LGR, NOR, GRE, dst_ipv4address, ifinfo.vlan_id, NOR); // dst_ip ... become a source

                        if (setup->param()[Setup::debug].cnfdata.vdata.boval == true)
                            DISPLAYONSUCCESS;
                    }
                    else if (conn->nh->nlmsg_type == RTM_DELROUTE && bpf_map_delete_elem(map_pinned_fd[BGPNEIGH_V4WL_MAP_IDX], &dst_ipv4addr) == 0)
                    {
                        snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp neighbor for wan interface%s%s ...ACTION_DEL) Ip:%s%s", GRE, __func__, LGR, NOR, GRE, dst_ipv4address, NOR); // dst_ip ... become a source

                        if (setup->param()[Setup::debug].cnfdata.vdata.boval == true)
                            DISPLAYONSUCCESS;
                    }
                    else if (conn->nh->nlmsg_type == RTM_NEWROUTE || conn->nh->nlmsg_type == RTM_DELROUTE)
                    {
                        snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp neighbor for wan interface%s%s ...ERROR) Ip:%s Vlan id:%d%s", RED, __func__, LRE, NOR, RED, dst_ipv4address, ifinfo.vlan_id, NOR);

                        if (setup->param()[Setup::debug].cnfdata.vdata.boval == true)
                            DISPLAYONSUCCESS;

                        if (errno)
                            LOG("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
                    }
                }
                else if (route_entry->rtm_family == AF_INET6)
                {
                    ingress_vlan_t vlan_info = { 0 };

                    if (bpf_map_lookup_elem_flags(map_pinned_fd[BGPNEIGH_V6WL_MAP_IDX], &dst_ipv6addr, &vlan_info, BPF_F_LOCK) == 0 && vlan_info.vlan_id == 0x0FFF) // bgp server blacklist can be only inserted during startup
                        return;

                    if (conn->nh->nlmsg_type == RTM_NEWROUTE && bpf_map_update_elem(map_pinned_fd[BGPNEIGH_V6WL_MAP_IDX], &dst_ipv6addr, &vlaninfo, (BPF_F_LOCK | BPF_ANY)) == 0)
                    {
                        snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp neighbor for wan interface%s%s ...ACTION_ADD) Ip:%s Vlan id:%d%s", GRE, __func__, LGR, NOR, GRE, dst_ipv6address, ifinfo.vlan_id, NOR); // dst_ip ... become a source

                        if (setup->param()[Setup::debug].cnfdata.vdata.boval == true)
                            DISPLAYONSUCCESS;
                    }
                    else if (conn->nh->nlmsg_type == RTM_DELROUTE && bpf_map_delete_elem(map_pinned_fd[BGPNEIGH_V6WL_MAP_IDX], &dst_ipv6addr) == 0)
                    {
                        snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp neighbor for wan interface%s%s ...ACTION_DEL) Ip:%s%s", GRE, __func__, LGR, NOR, GRE, dst_ipv6address, NOR); // dst_ip ... become a source

                        if (setup->param()[Setup::debug].cnfdata.vdata.boval == true)
                            DISPLAYONSUCCESS;
                    }
                    else if (conn->nh->nlmsg_type == RTM_NEWROUTE || conn->nh->nlmsg_type == RTM_DELROUTE)
                    {
                        snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp neighbor for wan interface%s%s ...ERROR) Ip:%s Vlan id:%d%s", RED, __func__, LRE, NOR, RED, dst_ipv6address, ifinfo.vlan_id, NOR);

                        if (setup->param()[Setup::debug].cnfdata.vdata.boval == true)
                            DISPLAYONSUCCESS;

                        if (errno)
                            LOG("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
                    }
                }
            }
        }

        //		if (setup->param()[Setup::debug].cnfdata.vdata.boval == true &&
        //			setup->param()[Setup::verbose].cnfdata.vdata.boval == true)
        //	LOG("route to destination --> %s/%d proto %d gateway %s interface %d %s", (route_entry->rtm_family == AF_INET) ? dst_ipv4address : dst_ipv6address, route_entry->rtm_dst_len, route_entry->rtm_protocol, (route_entry->rtm_family == AF_INET) ? gw_ipv4address : gw_ipv6address, ifidx, (conn->nh->nlmsg_type == RTM_NEWROUTE ? "added" : "deleted"));

        return;
    }

    int err = EOF;
    size_t len, info_len, vlan_len;
    struct ifinfomsg *msg;
    struct rtattr *rta, *info, *vlan;
    static __u32 target_idx = 0;
    static __u32 parent_idx = 0;
    bool ifup = false; // if true: interface up
    bool ifrun = false; // if true: The driver has allocated resources for the interface, and is ready to transmit and receive packets. This is a read-only option that is set by the driver. If false: non carrier
    __u32 vlan_id = 0;

    msg = (struct ifinfomsg *)NLMSG_DATA(conn->nh); // message payload

    if (msg->ifi_type != ARPHRD_ETHER)
        return;

    target_idx = 0;
    parent_idx = 0;
    vlan_id = 0;
    ifup = false;
    ifrun = false; // if true: The driver has allocated resources for the interface, and is ready to transmit and receive packets. This is a read-only option that is set by the driver

    if (msg->ifi_flags & IFF_UP)
        ifup = true;

    if (msg->ifi_flags & IFF_RUNNING)
        ifrun = true;

    target_idx = msg->ifi_index;

    rta = IFLA_RTA(msg); // message attributes
    len = conn->nh->nlmsg_len - NLMSG_LENGTH(sizeof *msg);

    // Loop through all attributes
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
    {
        if (rta->rta_type == IFLA_LINK) // there is a "parent" device
            parent_idx = *(__u16 *)((char *)rta + NLA_HDRLEN);

        if (rta->rta_type == IFLA_LINKINFO)
        {
            info = (rtattr *)RTA_DATA(rta);
            info_len = RTA_PAYLOAD(rta);

            while (RTA_OK(info, info_len))
            {
                if (info->rta_type == IFLA_INFO_KIND && // check if interface type is tun, bridge, vlan and so on
                    strncmp((char *)RTA_DATA(info), "vlan", strlen("vlan")) == 0)
                {
                    info = RTA_NEXT(info, info_len);

                    if (RTA_OK(info, info_len))
                    {
                        if (info->rta_type == IFLA_INFO_DATA)
                        {
                            vlan = (rtattr *)RTA_DATA(info);
                            vlan_len = RTA_PAYLOAD(info);

                            while (RTA_OK(vlan, vlan_len))
                            {
                                if (vlan->rta_type == IFLA_VLAN_ID)
                                    vlan_id = *(__u32 *)RTA_DATA(vlan);

                                vlan = RTA_NEXT(vlan, vlan_len);
                            }
                        }
                    }
                    else
                        break;
                }

                info = RTA_NEXT(info, info_len);
            }
        }
    }

    // store in std::map and bpf_map only mienro interfaces
    if (conn->sa_us.nl_groups == 0) // already configured interfaces before starting mienro
    {
        if (ifup == true && ifrun == true && vlan_id > 0)
        {
            ifidx_t ifinfo = { 0 };

            if (target_idx == if_nametoindex(setup->conf_getval(Setup::lanifindex).strval))
                ifinfo.xdp_idx = tx_ports_list[LAN_PLS].xdpport;
            else if (parent_idx == tx_ports_list[WAN_PLS].txport)
                ifinfo.xdp_idx = tx_ports_list[WAN_PLS].xdpport;

            if (ifinfo.xdp_idx > 0)
            {
                ifidx_map[target_idx] = vlan_id; // each vlan idx that has the wan or lan as parent interface must be stored in ifidx_map

                ifinfo.vlan_id = vlan_id;

                if ((err = bpf_map_update_elem(map_wan_fd[MNET_MAP_IDX], &target_idx, &ifinfo, BPF_F_LOCK)))
                    THROW("Failed inserting index interface %u on %s map (ret: %d)", target_idx, map_wan_names[MNET_MAP_IDX], err);
                else
                    DVCON LOG("idx %d parent %d vlan id %d%s%s", target_idx, parent_idx, vlan_id, (ifup == true) ? " up" : " down", (ifrun == true) ? " running" : " not running");
            }
        }
    }
    else // live updates of interfaces can only be done for wan interface
    {
        //	if (target_idx == if_nametoindex(setup->conf_getval(Setup::wanifindex).strval) ||
        //		target_idx == if_nametoindex(setup->conf_getval(Setup::lanifindex).strval))
        if (vlan_id > 0 && parent_idx == tx_ports_list[WAN_PLS].txport)
        {
            if (conn->nh->nlmsg_type == RTM_DELLINK)
            {
                if (bpf_map_delete_elem(map_pinned_fd[MNET_MAP_IDX], &target_idx) == 0)
                    LOG("idx %u parent %u vlan id %d%s%s", target_idx, parent_idx, vlan_id, (ifup == true) ? " up" : " down", (ifrun == true) ? " running" : " not running");
            }
            else if (ifup == true && ifrun == true)
            {
                ifidx_t ifinfo = { 0 };

                if (bpf_map_lookup_elem_flags(map_pinned_fd[MNET_MAP_IDX], &target_idx, &ifinfo, BPF_F_LOCK) == 0)
                {
                    if (ifinfo.xdp_idx != tx_ports_list[WAN_PLS].xdpport || ifinfo.vlan_id != vlan_id)
                    {
                        ifinfo.xdp_idx = tx_ports_list[WAN_PLS].xdpport;
                        ifinfo.vlan_id = vlan_id;

                        if ((err = bpf_map_update_elem(map_pinned_fd[MNET_MAP_IDX], &target_idx, &ifinfo, BPF_F_LOCK)))
                            LOG("Failed inserting vlan index interface %u on %s map (ret: %d)", target_idx, map_wan_names[MNET_MAP_IDX], err);
                        else
                            DVCON LOG("idx %u parent %u vlan id %d%s%s", target_idx, parent_idx, vlan_id, (ifup == true) ? " up" : " down", (ifrun == true) ? " running" : " not running");
                    }
                }
                else
                {
                    ifinfo.xdp_idx = tx_ports_list[WAN_PLS].xdpport;
                    ifinfo.vlan_id = vlan_id;

                    if ((err = bpf_map_update_elem(map_pinned_fd[MNET_MAP_IDX], &target_idx, &ifinfo, BPF_F_LOCK)))
                        LOG("Failed inserting vlan index interface %u on %s map (ret: %d)", target_idx, map_wan_names[MNET_MAP_IDX], err);
                    else
                        DVCON LOG("idx %u parent %u vlan id %d%s%s", target_idx, parent_idx, vlan_id, (ifup == true) ? " up" : " down", (ifrun == true) ? " running" : " not running");
                }
            }
        }
    }

    // TODO use also part of this code fetched from tests
    /*		if (conn->nh->nlmsg_type == RTM_DELLINK)
                            fprintf(stderr, "idx %d parent %d vlan id %d deleted\n", target_idx, parent_idx, vlan_id);
                    else if (ifup == false) // TODO inferface is down when is added or deleted (check map)
                            fprintf(stderr, "idx %d parent %d vlan id %d added\n", target_idx, parent_idx, vlan_id);
                    else
                            fprintf(stderr, "idx %d parent %d vlan id %d%s%s", target_idx, parent_idx, vlan_id, (ifup == true) ? " up" : " down", (ifrun == true) ? " running" : " not running"); */
}

//
// Name: Mienro::configure_network_interfaces
//
// Description: Load wan address in array map for kernel program
//
// Input:
//
// Output:
//
// Return:
//
void Mienro::configure_network_interfaces(void)
{
    char ipv4address[INET_ADDRSTRLEN];
    char ipv6address[INET6_ADDRSTRLEN];
    int ret = EOF;
    __u16 failcounter = 0;
    __u16 nlmsg_type = RTM_GETLINK;
    pid_t pid = getpid(); // our process ID to build the correct netlink address
    nl_conn_t nl_conn;
#ifndef TRUNK_PORT
    bool configured_ifaces[UNTRUSTED_MAX] = { false };
#endif
    in4_addr prev_addrV4 = 0, addrV4;
    __u32 if_idx = 0;
    __u32 prev_if_idx = ~0;
    struct in6_addr prev_addrV6 = { 0 }, addrV6;

    // flush pinned interface id map
    while (bpf_map_get_next_key(map_wan_fd[MNET_MAP_IDX], &prev_if_idx, &if_idx) == 0)
    {
        if ((ret = bpf_map_delete_elem(map_wan_fd[MNET_MAP_IDX], &if_idx)) != 0)
            THROW("Failed deleting interface %d on %s map (ret: %d)", if_idx, map_wan_names[MNET_MAP_IDX], ret);

        prev_if_idx = if_idx;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    // flush pinned ipv4 bgp neighbor maps
    while (bpf_map_get_next_key(map_wan_fd[BGPNEIGH_V4WL_MAP_IDX], &prev_addrV4, &addrV4) == 0)
    {
        if ((ret = bpf_map_delete_elem(map_wan_fd[BGPNEIGH_V4WL_MAP_IDX], &addrV4)) != 0)
        {
            inet_ntop(AF_INET, &addrV4, ipv4address, INET_ADDRSTRLEN);
            THROW("Failed flushing ip address %s on %s map (ret: %d)", ipv4address, map_wan_names[BGPNEIGH_V4WL_MAP_IDX], ret);
        }

        prev_addrV4 = addrV4;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    // flush pinned ipv6 bgp neighbor maps
    while (bpf_map_get_next_key(map_wan_fd[BGPNEIGH_V6WL_MAP_IDX], &prev_addrV6, &addrV6) == 0)
    {
        if ((ret = bpf_map_delete_elem(map_wan_fd[BGPNEIGH_V6WL_MAP_IDX], &addrV6)) != 0)
        {
            inet_ntop(AF_INET, &addrV6, ipv6address, INET_ADDRSTRLEN);
            THROW("Failed flushing ip address %s on %s map (ret: %d)", ipv6address, map_wan_names[BGPNEIGH_V6WL_MAP_IDX], ret);
        }

        prev_addrV6 = addrV6;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    nl_conn.nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (nl_conn.nlfd < 0)
    {
        LOG("Failed to open netlink socket: %s", handle_err());
        exit(EXIT_FAILURE);
    }

    nl_process_req(&nl_conn, nlmsg_type, pid);

rebind:

    while (true)
    {
        ssize_t len = EOF;

    redo:

        if (failcounter > 64)
        {
            if (failcounter > 64)
                LOG("Failed to rcvmsg to netlink socket: %s", handle_err());

            close(nl_conn.nlfd);
            nl_conn.nlfd = EOF;
            exit(EXIT_FAILURE);
        }

        // len = recvmsg(nl_conn.nlfd, &nl_conn.msg, MSG_DONTWAIT);
        len = recvmsg(nl_conn.nlfd, &nl_conn.msg, MSG_WAITALL);

        if (len < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;

            LOG("Failed to read netlink: %s", (char *)handle_err());
            failcounter++;
            continue;
        }

        if (nl_conn.msg.msg_namelen != sizeof(nl_conn.sa_us)) // check message length, just in case
        {
            LOG("Invalid length of the sender address struct");
            continue;
        }

        failcounter = 0;

        for (nl_conn.nh = (struct nlmsghdr *)nl_conn.reply_buffer; NLMSG_OK(nl_conn.nh, (__u32)len); nl_conn.nh = NLMSG_NEXT(nl_conn.nh, len))
        {
            // cout << nl_conn.sa_us.nl_groups << ' ' << RTM_NEWADDR << ' ' << RTM_DELADDR << endl;
            // cout << nl_conn.nh->nlmsg_type << ' ' << NLMSG_NOOP << ' ' << NLMSG_ERROR << ' ' << NLMSG_DONE << ' ' << NLMSG_OVERRUN << ' ' << NLMSG_MIN_TYPE << ' ' << endl;
            switch (nl_conn.nh->nlmsg_type)
            {
            case NLMSG_DONE:
                switch (nl_conn.nh->nlmsg_type)
                {
                case RTMGRP_LINK:
                case RTMGRP_IPV4_IFADDR:
                case RTMGRP_IPV6_IFADDR:
                case RTMGRP_IPV4_ROUTE:
                case RTMGRP_IPV6_ROUTE:
                    goto redo;
                    break;
                default:
                    switch (nlmsg_type)
                    {
                    case RTM_GETLINK:
                        nlmsg_type = RTM_GETADDR;
                        nl_process_req(&nl_conn, nlmsg_type, pid); // Get already configured addresses
                        break;
                    case RTM_GETADDR:
                        nlmsg_type = RTM_GETROUTE;
                        nl_process_req(&nl_conn, nlmsg_type, pid); // Get Already configured routes
                        break;
                    default:
                        goto ended;
                        break;
                    }

                    goto rebind;
                    break;
                }
                break;
            case RTM_BASE: // used for add link
            case RTM_NEWADDR:
            case RTM_NEWROUTE:
#ifndef TRUNK_PORT
                nl_handle_msg(&nl_conn, configured_ifaces);
#else
                nl_handle_msg(&nl_conn, NULL);
#endif
                break;
            default:
                break;
            }
        }
    }

ended:

    // clean up and finish properly
    close(nl_conn.nlfd);
    nl_conn.nlfd = EOF;

    auto key = UNTRUSTED_TO_LOP;
    auto mainv4network = setup->conf_getval(Setup::mainv4network).v4addr;
    auto mainv6network = setup->conf_getval(Setup::mainv6network).v6addr;

    // cidr 24
    if ((mainv4network >> 24) == 0)
        ret = bpf_map_update_elem(map_wan_fd[UNTRUST_V4_MAP_IDX], &key, &mainv4network, 0);
    else
    {
        ipv4address[0] = ASCII_NUL;
        inet_ntop(AF_INET, &mainv4network, ipv4address, INET_ADDRSTRLEN);
        THROW("Bad network address for %s", ipv4address);
    }

    if (ret)
        THROW("Failed creating untrust IPv4 addresses (ret: %d)", ret);

    // cidr 48
    if (mainv6network.s6_addr16[3] == 0 || mainv6network.s6_addr32[2] == 0 || mainv6network.s6_addr32[3] == 0)
        ret = bpf_map_update_elem(map_wan_fd[UNTRUST_V6_MAP_IDX], &key, &mainv6network, 0);
    else
    {
        ipv6address[0] = ASCII_NUL;
        inet_ntop(AF_INET6, &mainv6network, ipv6address, INET6_ADDRSTRLEN);
        THROW("Bad network address for %s", ipv4address);
    }

    if (ret)
        THROW("Failed creating untrust IPv6 addresses (ret: %d)", ret);

#ifndef TRUNK_PORT
    configured_ifaces[UNTRUSTED_TO_WAN] = true;
#endif

    __u32 _key = 0;
    ret = bpf_map_update_elem(map_wan_fd[AMASKS_MAP_IDX], &_key, &this->amasks, 0);

    if (ret)
        THROW("Failed creating cidr addresses (ret: %d)", ret);
#ifndef TRUNK_PORT
    __u8 cnf_if_cnt = 1;

    for (int i = 0; i < (int)UNTRUSTED_MAX; i++)
        if (configured_ifaces[static_cast<untrusted_t>(i)] == true)
            cnf_if_cnt++;

    if (cnf_if_cnt < UNTRUSTED_MAX)
        THROW("Missing configuration for some network interfaces (%d)", cnf_if_cnt);
#endif
}

//
// Name: Mienro::attach
//
// Description: Attach XDP program to nic device
//
// Input:
//  ifname - the interface name where attach xdp program
//  prog_fd - the filedescriptor pointing to the	program
//
// Output:
//
// Return:
//
void Mienro::attach(int *prog_fds) const
{
    int err = 0;

    // attach xdp programs to relative device
    if ((err = bpf_set_link_xdp_fd(tx_ports_list[WAN_PLS].xdpport, prog_fds[PROG_FWD_WAN], xdp_flags)) < 0)
    {
        if (errno == 0)
            THROW("Failed to attach program to wan interface %s", setup->conf_getval(Setup::wanifindex).strval);
        else
            THROW("Failed to attach program to wan interface %s err(%d): %s", setup->conf_getval(Setup::wanifindex).strval, err, handle_err());
    }

    if ((err = bpf_set_link_xdp_fd(tx_ports_list[CTR_PLS].xdpport, prog_fds[PROG_FWD_CTR], xdp_flags)) < 0)
    {
        if (errno == 0)
            THROW("Failed to attach program to controller interface");
        else
            THROW("Failed to attach program to controller: %s", handle_err());
    }

    if ((err = bpf_set_link_xdp_fd(tx_ports_list[LAN_PLS].xdpport, prog_fds[PROG_FWD_LAN], xdp_flags)) < 0)
    {
        if (errno == 0)
            THROW("Failed to attach program to lan interface %s", setup->conf_getval(Setup::lanifindex).strval);
        else
            THROW("Failed to attach program to lan interface %s err(%d): %s", setup->conf_getval(Setup::lanifindex).strval, err, handle_err());
    }

    // set Tx interfaces inside maps needed to bpf_redirect_map functions (pay attention to mapname_fd[PROG_MAP_IDX] and see also BPF_MAP_TYPE_DEVMAP)
    err = bpf_map_update_elem(map_wan_fd[PROG_MAP_IDX], &tx_ports_list[WAN_PLS].xdpport, &tx_ports_list[WAN_PLS].xdpport, 0); // it may not be necessary

    if (err)
        THROW("Failed using wan interface as TX-port (err: %d) for wan program", err);

    err = bpf_map_update_elem(map_wan_fd[PROG_MAP_IDX], &tx_ports_list[CTR_PLS].xdpport, &tx_ports_list[CTR_PLS].xdpport, 0);

    if (err)
        THROW("Failed using controller interface as TX-port (err: %d) for wan program", err);

    err = bpf_map_update_elem(map_wan_fd[PROG_MAP_IDX], &tx_ports_list[LAN_PLS].xdpport, &tx_ports_list[LAN_PLS].xdpport, 0);

    if (err)
        THROW("Failed using lan interface as TX-port (err: %d) for wan program", err);

    err = bpf_map_update_elem(map_ctr_fd[PROG_MAP_IDX], &tx_ports_list[WAN_PLS].xdpport, &tx_ports_list[WAN_PLS].xdpport, 0);

    if (err)
        THROW("Failed using wan interface as TX-port (err: %d) for controller program", err);

    err = bpf_map_update_elem(map_ctr_fd[PROG_MAP_IDX], &tx_ports_list[CTR_PLS].xdpport, &tx_ports_list[CTR_PLS].xdpport, 0); // it may not be necessary

    if (err)
        THROW("Failed using controller interface as TX-port (err: %d) for controller program", err);

    err = bpf_map_update_elem(map_lan_fd[PROG_MAP_IDX], &tx_ports_list[WAN_PLS].xdpport, &tx_ports_list[WAN_PLS].xdpport, 0);

    if (err)
        THROW("Failed using wan interface as TX-port (err: %d) for lan program", err);

    err = bpf_map_update_elem(map_lan_fd[PROG_MAP_IDX], &tx_ports_list[LAN_PLS].xdpport, &tx_ports_list[LAN_PLS].xdpport, 0); // it may not be necessary

    if (err)
        THROW("Failed using lan interface as TX-port (err: %d) for lan program", err);
}

//
// Name: Mienro::set_txports
//
// Description: Adding ifindex as a possible egress TX port (see tx_ports map).
//			  Note: traffic in ingress can be redirect to any interface and, traffic to any other interface can ONLY traverse router to reach egress interface.
//
// Input:
//
// Output:
//
// Return:
//
void Mienro::set_txports()
{
    int err = 0;
    const __u32 key = 0;

    err = bpf_map_update_elem(map_wan_fd[TXPORTS_MAP_IDX], &key, &tx_ports_list[WAN_PLS].TxPorts, 0);

    if (err)
        THROW("Failed creating list of TX-port numbers for xdp program attached to wan interface (err: %d)", err);

    err = bpf_map_update_elem(map_ctr_fd[TXPORTS_MAP_IDX], &key, &tx_ports_list[CTR_PLS].TxPorts, 0);

    if (err)
        THROW("Failed creating list of TX-port numbers for xdp program attached to controller interface (err: %d)", err);

    err = bpf_map_update_elem(map_lan_fd[TXPORTS_MAP_IDX], &key, &tx_ports_list[LAN_PLS].TxPorts, 0);

    if (err)
        THROW("Failed creating list of TX-port numbers for xdp program attached to lan interface (err: %d)", err);
}

//
// Name: Mienro::detach
//
// Description: Detach XDP program to nic device
//
// Input:
// idx - the interface number
//
// Output:
//
// Return:
//
void Mienro::detach(void) const
{
    // detach xdp programs from relative device
    if (bpf_set_link_xdp_fd(tx_ports_list[WAN_PLS].xdpport, EOF, xdp_flags) < 0)
    {
        if (errno == 0)
            THROW("Failed to detach program from wan interface");
        else
            THROW("Failed to detach program from wan interface: %s", handle_err());
    }

    if (bpf_set_link_xdp_fd(tx_ports_list[CTR_PLS].xdpport, EOF, xdp_flags) < 0)
    {
        if (errno == 0)
            THROW("Failed to detach program from controller interface");
        else
            THROW("Failed to detach program from controller interface: %s", handle_err());
    }

    if (bpf_set_link_xdp_fd(tx_ports_list[LAN_PLS].xdpport, EOF, xdp_flags) < 0)
    {
        if (errno == 0)
            THROW("Failed to detach program from lan interface");
        else
            THROW("Failed to detach program from lan interface: %s", handle_err());
    }
}

//
// Name: Mienro::get_bpfpath
//
// Description: Get the /sys/fs/bpf path
//
// Input:
//
// Output:
//
// Return: the absolute path
//
std::string Mienro::get_bpfpath() const
{
    return bpfpath;
}

//
// Name: Mienro::get_mappath
//
// Description: Get the maps path in the /sys/fs/bpf filesystem
//
// Input:
//
// Output:
//
// Return: the absolute path of maps directory
//
std::string Mienro::get_mappath() const
{
    return mappath;
}

//
// Name: Mienro::get_loadpath
//
// Description: Get the path to the file indicating that mienro is loaded
//
// Input:
//
// Output:
//
// Return: the absolute path of maps directory
//
std::string Mienro::get_loadpath() const
{
    return loadpath;
}

//
// Name: Mienro::map_cleanup
//
// Description: Close filemap descriptors and remove relatives files
//
// Input:
//
// Output:
//
// Return:
//
void Mienro::map_cleanup(void)
{
    /* TODO: Remember to cleanup map, when adding use of shared map
     *  bpf_map_delete_elem((map_fd, &idx);
     */

    char filemap_path[PATH_MAX];

    std::queue<string> dirs;
    dirs.push("wanif/");
    dirs.push("ctrif/");
    dirs.push("lanif/");

    while (!dirs.empty())
    {
        for (auto i = (int)EVENTS_MAP_IDX; i < (int)MAX_MAPS; i++)
        {
            memset(&filemap_path, 0, PATH_MAX);
            snprintf(filemap_path, sizeof(filemap_path), file_map[static_cast<idx_t>(i)], get_mappath().c_str(), dirs.front().c_str());

            errno = 0;

            if (bpf_fs_check_path(filemap_path) < 0)
                THROW("EXIT_FAIL_MAP_FS");

            int fd = bpf_obj_get(filemap_path);

            if (fd > 0) // Great: map file already existed use it  FIXME: Verify map size etc is the same
            {
                if (map_wan_fd[static_cast<idx_t>(i)] > 0)
                    close(map_wan_fd[static_cast<idx_t>(i)]); // TODO  is this enough to cleanup map???
            }

            unlink(filemap_path);
        }

        dirs.pop();
    }
}

//
// Name: acl_maps_fill
//
// Description: Populate acl maps
//
// Input:
//
// Return:
//
void Mienro::acl_maps_fill(void)
{
    Setup::vdata_t *vdata = nullptr;
    uint8_t v = 0;

    char ipv4daddr[INET_ADDRSTRLEN];
    char ipv6daddr[INET6_ADDRSTRLEN];
    char buffer[MAX_STR_LEN];
    in4_addr dstV4addr = 0;
    struct in6_addr dstV6addr = {};
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    xdp_stats_t values[nr_cpus];
    memset(values, 0, sizeof(xdp_stats_t) * nr_cpus);

    __u32 key = UNTRUSTED_TO_WAN;

    if (bpf_map_lookup_elem(map_wan_fd[UNTRUST_V4_MAP_IDX], &key, &dstV4addr) < 0)
        THROW("EXIT_FAIL_MAP");

    if (bpf_map_lookup_elem(map_wan_fd[UNTRUST_V6_MAP_IDX], &key, &dstV6addr) < 0)
        THROW("EXIT_FAIL_MAP");

    ipv4daddr[0] = ASCII_NUL;
    inet_ntop(AF_INET, &dstV4addr, ipv4daddr, INET_ADDRSTRLEN);
    ipv6daddr[0] = ASCII_NUL;
    inet_ntop(AF_INET6, &dstV6addr, ipv6daddr, INET6_ADDRSTRLEN);
#ifdef TRUNK_PORT
    v = setup->conf_getlist(Setup::pool_bridgedvlan, vdata);

    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::LONGINT)
        { // popolate map of vlan id
            if (vdata[i].longval > 0 && vdata[i].longval < 4095)
            {
                __u32 vlanid = vdata[i].longval;

                if (bpf_map_update_elem(map_wan_fd[BRIDGED_WAN_VLAN_MAP_IDX], &vlanid, &values, BPF_ANY) == 0)
                    snprintf(buffer, MAX_STR_LEN, "%s%s(%sBridged vlan id on wan interface%s%s ...ACTION_ADD) INPUT Vlan id:%ld to internal nas%s", GRE, __func__, LGR, NOR, GRE, vdata[i].longval, NOR);
                else
                {
                    snprintf(buffer, MAX_STR_LEN, "%s%s(%sBridged vlan id on wan interface%s%s ...ERROR) INPUT Vlan id:%ld to internal nas%s", GRE, __func__, LGR, NOR, GRE, vdata[i].longval, NOR);

                    if (errno)
                        THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
                }

                DISPLAYONSUCCESS;

                if (bpf_map_update_elem(map_lan_fd[BRIDGED_WAN_VLAN_MAP_IDX], &vlanid, &values, BPF_ANY) == 0)
                    snprintf(buffer, MAX_STR_LEN, "%s%s(%sBridged vlan id on lan interface%s%s ...ACTION_ADD) INPUT Vlan id:%ld to internal nas%s", GRE, __func__, LGR, NOR, GRE, vdata[i].longval, NOR);
                else
                {
                    snprintf(buffer, MAX_STR_LEN, "%s%s(%sBridged vlan id on lan interface%s%s ...ERROR) INPUT Vlan id:%ld to internal nas%s", GRE, __func__, LGR, NOR, GRE, vdata[i].longval, NOR);

                    if (errno)
                        THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
                }

                DISPLAYONSUCCESS;
            }
            else
                THROW("EXIT_FAIL_MAP_KEY: bad vlan id value. Check your configuration");
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);
#endif
    v = setup->conf_getlist(Setup::pool_blk, vdata);

    // store in maps bgpn... the address of the bgp neighbors for sharing ddos blacklists
    for (auto i = 0; i < v; i++)
    {
        ingress_vlan_t vlaninfo = { 0 };
        vlaninfo.vlan_id = 0x0FFF; // Attention: this value 0x0FFF (4095) is fictitious, it is only used to indicate to MiEnRo that the traffic coming from the bgp blacklist server has no restrictions on the wan used for access.

        if (vdata[i].tag == Setup::IN4ADDR)
        { // popolate map ipv4 whitelist
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            // popolate map ipv4 whitelist
            if (bpf_map_update_elem(map_wan_fd[BGPNEIGH_V4WL_MAP_IDX], &vdata[i].v4addr, &vlaninfo, (BPF_F_LOCK | BPF_NOEXIST)) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp for blacklist sharing%s%s ...ACTION_ADD) Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp for blacklist sharing%s%s ...ERROR) Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            // popolate map ipv4 whitelist
            if (bpf_map_update_elem(map_wan_fd[BGPNEIGH_V6WL_MAP_IDX], &vdata[i].v6addr, &vlaninfo, (BPF_F_LOCK | BPF_NOEXIST)) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp for blacklist sharing%s%s ...ACTION_ADD) Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sBgp for blacklist sharing%s%s ...ERROR) Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
    }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_rad, vdata);

    // store in maps radius... the address of radius
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[RADIUS_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[TCP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s Destination Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, ipv4daddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for wan%s%s ...ERROR) INPUT Source Ip:%s Destination Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, ipv4daddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[RADIUS_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[TCP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for lan across ctr%s%s ...ACTION_ADD) INPUT Dest Ip:%s Destination Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, ipv4daddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for lan across ctr%s%s ...ERROR) INPUT Dest Ip:%s Destination Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, ipv4daddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[RADIUS_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[TCP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s Destination Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, ipv6daddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for wan%s%s ...ERROR) INPUT Source Ip:%s Destination Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, ipv6daddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[RADIUS_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[TCP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for lan across ctr%s%s ...ACTION_ADD) INPUT Dest Ip:%s Destination Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, ipv6daddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sRadius remote server for lan across ctr%s%s ...ERROR) INPUT Dest Ip:%s Destination Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, ipv6daddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_dns, vdata);

    // store in maps dns... the address of dns
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[DNS_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[TCP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[DNS_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[TCP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[DNS_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[TCP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[DNS_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[TCP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sDns remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_ntp, vdata);

    // store in maps ntp... the address of ntp
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[NTP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[NTP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[NTP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[NTP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sNtp remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_vpn, vdata);

    // store in maps vpn... the address of vpn
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[VPN_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[VPN_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[VPN_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[VPN_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sVpn remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_mxx, vdata);

    // store in maps mail ... the address of mail exchange
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[MXX_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[TCP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[MXX_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[TCP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[MXX_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[TCP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[MXX_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[TCP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMail Exchange remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_mon, vdata);

    // store in maps monitor... the address of monitor
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[MON_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[MON_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[MON_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[MON_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sMonitor remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    v = setup->conf_getlist(Setup::pool_log, vdata);

    // store in maps log... the address of log
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[LOG_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[LOG_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V4WL_MAP_IDX], &vdata[i].v4addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv4saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            bpf_map_update_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);
            bpf_map_update_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY);

            if (bpf_map_update_elem(map_wan_fd[LOG_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_wan_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for wan%s%s ...ERROR) INPUT Source Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;

            if (bpf_map_update_elem(map_ctr_fd[LOG_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0 && bpf_map_update_elem(map_ctr_fd[UDP_V6WL_MAP_IDX], &vdata[i].v6addr, &values, BPF_ANY) == 0)
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for dmz%s%s ...ACTION_ADD) INPUT Dest Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);
            else
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sLog remote server for dmz%s%s ...ERROR) INPUT Dest Ip:%s%s", RED, __func__, LRE, NOR, RED, ipv6saddr, NOR);

                if (errno)
                    THROW("EXIT_FAIL_MAP_KEY: errno(%d/%s)", errno, handle_err());
            }

            DISPLAYONSUCCESS;
        }

    SETUP_DELETE(vdata);

    assert(vdata == nullptr);

    char ipv4addr[INET_ADDRSTRLEN];
    char ipv6addr[INET6_ADDRSTRLEN];
    in4_addr prev_addrV4 = 0, addrV4;
    struct in6_addr prev_addrV6 = { 0 }, addrV6;

    // iterate bpf icmp whitelist maps
    while (bpf_map_get_next_key(map_wan_fd[ICMP_V4WL_MAP_IDX], &prev_addrV4, &addrV4) == 0)
    {
        inet_ntop(AF_INET, &addrV4, ipv4addr, INET_ADDRSTRLEN);

        if (bpf_map_lookup_elem(map_wan_fd[ICMP_V4WL_MAP_IDX], &addrV4, &values) == 0)
        {
            snprintf(buffer, MAX_STR_LEN, "%s%s(%sIcmp whitelist for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4addr, NOR);

            DISPLAYONSUCCESS;
        }

        prev_addrV4 = addrV4;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    while (bpf_map_get_next_key(map_wan_fd[ICMP_V6WL_MAP_IDX], &prev_addrV6, &addrV6) == 0)
    {
        inet_ntop(AF_INET6, &addrV6, ipv6addr, INET6_ADDRSTRLEN);

        if (bpf_map_lookup_elem(map_wan_fd[ICMP_V6WL_MAP_IDX], &addrV6, &values) == 0)
        {
            snprintf(buffer, MAX_STR_LEN, "%s%s(%sIcmp whitelist for wan%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6addr, NOR);

            DISPLAYONSUCCESS;
        }

        prev_addrV6 = addrV6;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    prev_addrV4 = 0;
    memset(&prev_addrV6, 0, sizeof(struct in6_addr));

    while (bpf_map_get_next_key(map_ctr_fd[ICMP_V4WL_MAP_IDX], &prev_addrV4, &addrV4) == 0)
    {
        inet_ntop(AF_INET, &addrV4, ipv4addr, INET_ADDRSTRLEN);

        if (bpf_map_lookup_elem(map_ctr_fd[ICMP_V4WL_MAP_IDX], &addrV4, &values) == 0)
        {
            snprintf(buffer, MAX_STR_LEN, "%s%s(%sIcmp whitelist for ctr%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4addr, NOR);

            DISPLAYONSUCCESS;
        }

        prev_addrV4 = addrV4;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    while (bpf_map_get_next_key(map_ctr_fd[ICMP_V6WL_MAP_IDX], &prev_addrV6, &addrV6) == 0)
    {
        inet_ntop(AF_INET6, &addrV6, ipv6addr, INET6_ADDRSTRLEN);

        if (bpf_map_lookup_elem(map_ctr_fd[ICMP_V6WL_MAP_IDX], &addrV6, &values) == 0)
        {
            snprintf(buffer, MAX_STR_LEN, "%s%s(%sIcmp whitelist for ctr%s%s ...ACTION_ADD) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6addr, NOR);

            DISPLAYONSUCCESS;
        }

        prev_addrV6 = addrV6;

        if (_signal == SIGINT)
            THROW("Interrupted...");
    }

    DVCON LOG("%sClean the ssh bruteforce map from monitor servers addresses%s", LGR, NOR);

    errno = 0;

    v = setup->conf_getlist(Setup::pool_mon, vdata);

    // delete monitor address from ssh bruteforce maps
    for (auto i = 0; i < v; i++)
        if (vdata[i].tag == Setup::IN4ADDR)
        {
            char ipv4saddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &vdata[i].v4addr, ipv4saddr, INET_ADDRSTRLEN);

            if (bpf_map_delete_elem(map_pinned_fd[SSHV4TIMEO_MAP_IDX], &vdata[i].v4addr) == 0)
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sSSH V4 blacklist%s%s ...ACTION_DEL) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv4saddr, NOR);

                DISPLAYONSUCCESS;
            }
        }
        else if (vdata[i].tag == Setup::IN6ADDR)
        {
            char ipv6saddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &vdata[i].v6addr, ipv6saddr, INET6_ADDRSTRLEN);

            if (bpf_map_delete_elem(map_pinned_fd[SSHV4TIMEO_MAP_IDX], &vdata[i].v6addr) == 0)
            {
                snprintf(buffer, MAX_STR_LEN, "%s%s(%sSSH V6 blacklist%s%s ...ACTION_DEL) INPUT Source Ip:%s%s", GRE, __func__, LGR, NOR, GRE, ipv6saddr, NOR);

                DISPLAYONSUCCESS;
            }
        }

    SETUP_DELETE(vdata);

    errno = 0;

    assert(vdata == nullptr);
}

//
// Name: ssh_clr_map
//
// Description: Clear the ssh map used to prevent brute force attacks, from keys that have not been used for a long time
//
// Input:
//
// Return:
//
void Mienro::ssh_clr_map(void)
{
    struct sysinfo s_info;

    if (sysinfo(&s_info) != 0)
    {
        std::cout << RED << "Ssh blacklist map cannot be flushed because cannot get system uptime." << std::endl;
    }
    else
    {
        in4_addr prev_addrV4 = 0, addrV4;
        struct in6_addr prev_addrV6 = {}, addrV6;

        // clear ssh ipv4 blacklist
        while (bpf_map_get_next_key(map_ctr_fd[SSHV4TIMEO_MAP_IDX], &prev_addrV4, &addrV4) == 0)
        {
            timeo_t timeo = {};

            assert(bpf_map_lookup_elem(map_ctr_fd[SSHV4TIMEO_MAP_IDX], &addrV4, &timeo) == 0);

            if (s_info.uptime > 0)
            {
                if (timeo.creationtime + setup->conf_getval(Setup::sshbfquar).longval < (long long unsigned)s_info.uptime)
                    bpf_map_delete_elem(map_ctr_fd[SSHV4TIMEO_MAP_IDX], &addrV4);
            }
            else
                bpf_map_delete_elem(map_ctr_fd[SSHV4TIMEO_MAP_IDX], &addrV4);

            prev_addrV4 = addrV4;
        }

        // clear ssh ipv6 blacklist
        while (bpf_map_get_next_key(map_ctr_fd[SSHV6TIMEO_MAP_IDX], &prev_addrV6, &addrV6) == 0)
        {
            timeo_t timeo = {};

            assert(bpf_map_lookup_elem(map_ctr_fd[SSHV6TIMEO_MAP_IDX], &addrV6, &timeo) == 0);

            if (s_info.uptime > 0)
            {
                if (timeo.creationtime + setup->conf_getval(Setup::sshbfquar).longval < (long long unsigned)s_info.uptime)
                    bpf_map_delete_elem(map_ctr_fd[SSHV6TIMEO_MAP_IDX], &addrV6);
            }
            else
                bpf_map_delete_elem(map_ctr_fd[SSHV6TIMEO_MAP_IDX], &addrV6);

            prev_addrV6 = addrV6;
        }

        errno = 0;
    }
}

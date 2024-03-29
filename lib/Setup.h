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

#ifndef __SETUP_INCLUDED_H
#define __SETUP_INCLUDED_H
#include "common.h"

// Setup - parse configuration -
#define PCONFMVSIZE 40 // max value size
#define PCONFNAMESIZE 32 // max name size
#define PCONFGRPMAX 32 // max elements in group
#define SETUP_EXIT_BRIEF INT_MAX
#define SETUP_CFREE(data) \
    if (data)             \
    {                     \
        free(data);       \
        data = nullptr;   \
    }
#define SETUP_DELETE(data) \
    if (data)              \
    {                      \
        delete[] data;     \
        data = nullptr;    \
    }
#define SETUP_CCFREE(data) \
    if (data)              \
    {                      \
        delete data;       \
        data = nullptr;    \
    }

class Setup
{

private:
    const char *classname;

    enum conf_optmask_t : uint8_t
    {
        CNF_OPT_FALSE = 0, // can be use as "virtual negative value", or to set to 0 full optmask
        CNF_OPT_INTERNAL = 1, // option cannot be set from user
        CNF_OPT_LINEONLY = 1 << 1, // option cannot be set from config file
        CNF_OPT_UNUSED = 1 << 2,
        CNF_OPT__UNUSED = 1 << 3,
        CNF_OPT___UNUSED = 1 << 4,
        CNF_OPT____UNUSED = 1 << 5,
        CNF_OPT_____UNUSED = 1 << 6,
        CNF_OPT______UNUSED = 1 << 7
    };

    typedef struct
    {
        long int longdef; // default value
        double doudef; // default value
        long int longmin;
        long int longmax;
        double doumin;
        double doumax;
        char unit[20];
    } default_t;

public:
    enum tag_t
    {
        CHARS, // default is for (char *)
        BOOL,
        LONGINT,
        DOUBLE,
        IN4ADDR,
        IN6ADDR,
        GRPADDR, // array of ip addresses
        GRPVLAN // array of vlan id Note: longint and tollerance value must be done out of setup class because it is discontinuous
    };

    typedef struct
    {
        tag_t tag;

        union
        {
            char *strval; // strval pointer assigned only if tag eq CHARS
            bool boval;
            long int longval;
            double douval;
            in4_addr v4addr;
            struct in6_addr v6addr;
        };
    } vdata_t;

private:
    typedef struct cnfdata
    {
        default_t *def;

        vdata_t vdata;

        cnfdata *next; // Linked List
    } cnfdata_t;

    typedef struct
    {
        const char *name;

        bool visited;

        cnfdata_t cnfdata;

    } cnfp_t;

    sigset_t mask, orig_mask;
    struct rlimit default_rlim_memlock;
    bool alarm;
    bool ut; // Unit Test

    cnfp_t *parameters;

    // this values must be set after fork
    char *HIOpath;
    char *NIOpath;
    char *NETpath;

    // user variables
    const char *username;
    const char *salt;

    //
    // Description: Print the usage informations.
    //
    void usage(void);

    //
    // Description: Populate the parameters array
    //
    void set_parameters(cnfp_t *);

    //
    // Description: Set configuration option.
    //
    void conf_option_set(uint8_t, conf_optmask_t, bool);

    //
    // Description: Get configuration option.
    //
    bool conf_option_get(uint8_t, conf_optmask_t, bool);

public:
    int sock_listen_raw;
    int sock_send_raw;
    struct sigaction action;
    fd_set rfds;
    uid_t map_owner;
    gid_t map_group;

    enum parname_t : uint8_t
    {
        debug,
        verbose,
        locale, // the locale setup
        direct, // direct
        skbmode, // XDP_FLAGS_SKB_MODE (xdp generic)
        wanifindex, // numeric identifier of wan interface
        sshifindex, // numeric identifier of ssh interface
        dmzifindex, // numeric identifier of dmz interface
        lanifindex, // numeric identifier of lan interface
        pool_bridgedvlan, // the vlan configured on wan inteface
        lockdir, // where put lock files
        rundir, // where put pid files
        logdir, // where put parent logs
        lbhf, // loopback host field bits
        mmonwait, // how long can mienromon wait (without do anything) before exit
        sshscanint, // interval to scan ssh bpf map
        sshbfquar, // ssh bruteforce quarantine (must be the same table value of controller node)
        icmpgranttime, // grant time icmp diagnostics message reply
        mainv4network, // the main ipv4 network
        mainv6network, // the main ipv6 network
        pool_blk, // the bgp neighbor for IPv4 blacklist
        pool_rad, // the addresses of radius servers
        pool_dns, // the addresses of dns servers
        pool_ntp, // the addresses of ntp servers
        pool_vpn, // the addresses of vpn (aka ipv6 intranet) servers
        pool_mxx, // the addresses of mail exchanger servers
        pool_mon, // the addresses of monitor servers
        pool_log, // the addresses of log servers
        user, // bpf map user
        paramsize // used only to detect number of configuration parameters
    };

    const char list[paramsize][PCONFNAMESIZE] = {
        "debug",
        "verbose",
        "locale",
        "direct",
        "skbmode",
        "wanifindex",
        "sshifindex",
        "dmzifindex",
        "lanifindex",
        "pool_bridgedvlan",
        "lockdir",
        "rundir",
        "logdir",
        "lbhf",
        "mmonwait",
        "sshscanint",
        "sshbfquar",
        "icmpgranttime",
        "mainv4network",
        "mainv6network",
        "pool_blk",
        "pool_rad",
        "pool_dns",
        "pool_ntp",
        "pool_vpn",
        "pool_mxx",
        "pool_mon",
        "pool_log",
        "user"
    };

    Setup(void); // ctor

    Setup(bool); // ctor

    Setup(const char *); // ctor

    ~Setup(); // dtor

    //
    // Description: Get line options and parse starting configuration.
    //
    cnfp_t *param(void) const;

    //
    // Description: Get line options and parse starting configuration.
    //
    int parseconf(int, char **);

    //
    // Description: Check if basepaths exists, set signals, set logstream and drop admin privileges
    //
    int prepare(pid_t &);

    //
    // Description: Get list of values assigned to configuration paramenter
    //
    vdata_t conf_getval(const parname_t) const;

    //
    // Description: Get list of values assigned to configuration paramenter
    //
    uint8_t conf_getlist(const parname_t, vdata_t *&) const;

    //
    // Description: Get default limits of system memlock resources.
    //
    void get_default_memlock_rlimit(struct rlimit &) const;

    //
    // Description: Create user resources.
    //
    void usercleanup(void);

    //
    // Description: Return current username.
    //
    const char *current_username(void) const;

    //
    // Description: Return current user hiopath.
    //
    const char *current_hiopath(void) const;

    //
    // Description: Return current user hiopath.
    //
    const char *current_niopath(void) const;

    //
    // Description: Return current user hiopath.
    //
    const char *current_netpath(void) const;

    //
    // Description: Write pid file.
    //
    int pid_write(pid_t, const char *) const;

    //
    // Description: Read pid file.
    //
    int pid_read(pid_t &, const char *) const;

    //
    // Description: Delete pid file.
    //
    int pid_del(const char *) const;
};

//
// Description: Function called by sa_sigaction when signal is received.
//
void sighandler(int, siginfo_t *, void *);

#endif // __SETUP_INCLUDED_H

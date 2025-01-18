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

#pragma once
#include "CopyrightData.h"
#include "common.h"

// Setup - parse configuration -
#define PCONFMVSIZE 40 // max value size
#define PCONFNAMESIZE 32 // max name size
#define PCONFGRPMAX 32 // max elements in group
#define SETUP_EXIT_BRIEF INT_MAX

class Setup
{

private:
    std::string classname;

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

    // It is used for keep the default values for each parameter
    struct default_t
    {
        long int longdef; // default value
        double doudef; // default value
        long int longmin;
        long int longmax;
        double doumin;
        double doumax;
        std::array<char, 20> unit;

        default_t() = default; // Ensure default constructor is available
    };

public:
    enum tag_t
    {
        DEFAULT, // values datatypes handled throught std::variant
        GRPADDR, // array of ip addresses
        GRPVLAN // array of vlan id Note: longint and tollerance value must be done out of setup class because it is discontinuous
    };

    using vdata_t = std::variant<std::monostate, std::string, bool, long int, double, in4_addr, struct in6_addr>;

private:
    typedef struct cnfdata
    {
		std::optional<default_t> def;

        vdata_t vdata = std::monostate {};

        cnfdata() = default; // Ensure default constructor is available
    } cnfdata_t;

    struct cnfp_t
    {
        std::string name;

        bool visited;

        tag_t tag = DEFAULT;

        std::forward_list<cnfdata_t> cnfdata;

        cnfp_t() = default; // Ensure default constructor is available
    };

    sigset_t mask, orig_mask;
    struct rlimit default_rlim_memlock;
    bool alarm;
    bool ut; // Unit Test

    cnfp_t *parameters;

    // this values must be set after fork
    std::string HIOpath;
    std::string NIOpath;
    std::string NETpath;

    // user variables
    std::string username;

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
    using pret_t = std::tuple<size_t, std::string, std::string>;

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
    // Name: parser
    //
    // Description: Iterate to parameters configuration or to list of tests
    //
    // Input:
    //   ss - reference to std::stringstream
    //
    // Return:
    //   Coro::Geko<T> Object
    //
    template <typename T>
    Coro::Geko<T> parser(std::ifstream &ifs, std::stringstream &ss)
    {
		static_assert(std::same_as<T, std::string> || std::same_as<T, pret_t>,
                          "parser<T>: T must be either std::string or Setup::pret_t");

        auto trim_leading_spaces = [](std::string &s) -> void
        {
            s.erase(s.begin(), std::ranges::find_if(s, [](unsigned char ch)
            {
                return not std::isspace(ch); // Find the first non-space character
            }));
        };

        auto trim_trailing_spaces = [](std::string &s) -> void
        {
            s.erase(std::ranges::find_if(s.rbegin(), s.rend(), [](unsigned char ch)
                        {
                            return not std::isspace(ch); // Find the first non-space character from the end
                        })
                        .base(),
                s.end());
        };

        // Lambda to check if ifstream is valid
        auto is_ifstream_valid = [](std::ifstream &ifs) -> bool
        {
            return ifs.is_open() && ifs.good();
        };

        // Lambda to check if stringstream is valid
        auto is_stringstream_valid = [](std::stringstream &ss) -> bool
        {
            return ss.good();
        };

        // Check the initial states of the streams
        bool ifs_state = is_ifstream_valid(ifs);
        bool ss_state = false;

        if (ifs_state == false)
            ss_state = is_stringstream_valid(ss);

        std::string token;
        size_t linecount = 0;

        while ((ifs_state && std::getline(ifs, token)) || (ss_state && std::getline(ss, token)))
        {
            if (ss_state)
                std::cout << token << " -> ";
            else
                linecount++;

            size_t off = token.find(ASCII_NU);

            if (off != std::string::npos)
                token.erase(off, std::string::npos);

            if (token.empty())
                continue;

            std::ranges::replace_if(token, ::isspace, ASCII_SP);

            std::istringstream input;
            uniquestr(token, ASCII_SP);
            input.str(token);

            if (input.str().empty())
                continue;
            //	std::cout << input.str() << std::endl << std::endl;
            std::ostringstream output;

            if (getline(input, token, '='))
            {
                if (token.compare(token.size() - 1, 1, " ") == 0)
                    token.erase(token.end() - 1, token.end()); // remove last space

                if (token.find(' ') != std::string::npos)
                    continue;

                output << token << " ";
            }

            // Instead of capturing trim_trailing_spaces function by reference (auto lambda = [trim_trailing_spaces] (std::string & token) -> bool) leading forward capturing by value is preferred.
            std::function<void(std::string &)> trim_trailing_spaces_function = trim_trailing_spaces;

            auto lambda = [trim_trailing_spaces_function](std::string &token) -> bool
            {
                trim_trailing_spaces_function(token);

                std::string::size_type offset_end = token.find(ASCII_SBC);

                if (offset_end != std::string::npos)
                {
                    offset_end = token.find(ASCII_SBC);

                    token.erase(offset_end, 1);
                }

                if (token.contains(ASCII_SBC))
                    return false;

                trim_trailing_spaces_function(token);

                return true;
            };

            if (getline(input, token))
            {
                if (token.contains(ASCII_EQ))
                    continue;

                //	std::cout << '|' << token << '|' << std::endl;

                std::string::size_type offset_begin = token.find(ASCII_SBO);

                if (offset_begin != std::string::npos)
                {
                    if (lambda(token) == false)
                        continue;

                    token.erase(offset_begin, 1);

                    if (token.contains(ASCII_SBO))
                        continue;

                    trim_leading_spaces(token);

                    output << token;
                }
                else if (token.contains(ASCII_SP))
                {
                    if (not token.empty())
                    {
                        std::string value(token);
                        uniquestr(value, ASCII_SP);

                        if (value.front() == ASCII_SP)
                            value.erase(0, 1);

                        if (value.back() == ASCII_SP)
                            value.pop_back();

                        if (value.contains(ASCII_SP))
                            continue;
                        else
                            output << value << " ";
                    }
                    else
                        continue;
                }
                else
                    output << token << " ";

                // static_assert(std::same_as<T, pret_t>, "T is not std::string!");  // Debugging line
                // static_assert(std::same_as<T, std::string>, "T is not std::string!");  // Debugging line

                if constexpr (std::same_as<T, pret_t>)
                {
                    std::string out = output.str();
                    size_t space_pos = out.find(ASCII_SP);

                    if (space_pos != std::string::npos)
                    {
                        std::string parname = out.substr(0, space_pos);
                        std::string value = out.substr(++space_pos);

                        trim_trailing_spaces(value);

                        if (not parname.empty() and not value.empty())
                            co_yield std::make_tuple(linecount, parname, value);
                    }
                }
                else if (std::same_as<T, std::string>)
                    co_yield output.str();
            }
        }
    }

    //
    // Description: Get line options and parse starting configuration.
    //
    int parseconf(int, char **);

    //
    // Description: Check if basepaths exists, set signals, set logstream and drop admin privileges
    //
    int prepare(pid_t &);

    //
    // Description: Get the element holds by std::variant
    //
    template <typename T>
    T variant_gethold(const vdata_t &v) const
    {
        return std::visit([](auto &&arg) -> T
            {
                // Check that the argument type matches the requested type
                if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, T>)
                    return arg; // Return the value if types match
                else
                    throw std::bad_variant_access(); // Throw if types don't match
            },
            v);
    }

    //
    // Descripion: Remove all consecutive duplicate characters in a string
    //
    void uniquestr(std::string &, const char) const;

    //
    // Deduct datatype of std::variant and convert it in a readable format
    //
    std::string variant_deduct_to_string(const vdata_t, bool = false) const;

    //
    // Description: Get list of values assigned to configuration parameter
    //
    vdata_t conf_getval(const parname_t) const;

    //
    // Description: Get list of values assigned to configuration parameter
    //
    std::vector<vdata_t> conf_getlist(const parname_t) const;

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
    std::optional<std::string> current_username(void) const;

    //
    // Description: Return current user hiopath.
    //
    std::string current_hiopath(void) const;

    //
    // Description: Return current user hiopath.
    //
    std::string current_niopath(void) const;

    //
    // Description: Return current user hiopath.
    //
    std::string current_netpath(void) const;

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

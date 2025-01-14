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

#pragma once

#include <iomanip> // std::setfill, std::setw
#include <bitset> // std::bitset<bitsize>(val)
#include <map>
// #include <cmath>
#include <pwd.h>
#include <stdio.h> //For standard things
#include <stdlib.h> //malloc, strtod
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <limits.h>
#include <ifaddrs.h>
#include <math.h> // HUGE_VAL for strtod(...)
#include <thread> // std::this_thread::sleep_for
#include <atomic>
#include <queue>
#include <chrono> // std::chrono::seconds
#include <coroutine>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/icmp6.h> //Provides declarations for icmp header
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h> // To get defns of NI_MAXSERV and NI_MAXHOST
#include <net/if.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <pwd.h>
#include <libgen.h>
#include <fstream>
#include <ifaddrs.h>
#include <sys/resource.h> // limits
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>

// Local Library
#include "bpf_insn.h"
#include "common.h"
#include "const.h"
// #include <bitmask.h>
//

// DON'T TOUCH THIS VALUES!
#define MINID 8
#define MAXID 32768
#define WORKPREF 0x8ffffffe // definitive prefix to assign at ALL device.
#define VOIDSLOT (bucket_t)(~0)

#define DCON if (setup->variant_gethold<bool>(setup->conf_getval(Setup::debug)) == true)
#define DVCON if (setup->variant_gethold<bool>(setup->conf_getval(Setup::debug)) == true and (setup->variant_gethold<bool>(setup->conf_getval(Setup::verbose)) == true))

#ifdef DEBUG
#define COLOR BRO
#define EXCEPBANNER "Exception message"
#define THROW(...) Log::throw_(__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define LOG(...) Log::log(__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define CLOG(...)                                                      \
    {                                                                  \
        _color = COLOR;                                                \
        Log::log(__PRETTY_FUNCTION__, __FILE__, __LINE__, __VA_ARGS__); \
    }
#define LOGE(exception_buffer)          \
    Log::logexception(exception_buffer); \
    return EXIT_FAILURE
#define CLOGE(exception_buffer)             \
    {                                       \
        _color = COLOR;                     \
        Log::logexception(exception_buffer); \
        return EXIT_FAILURE;                \
    }
#define BADINIT Log::log(__func__, __FILE__, __LINE__, "%s: bad initialization.", PROGRAM_STR(progid)); // generic bad initialization
#define BADALLOCINIT Log::log(__func__, __FILE__, __LINE__, "%s: initialization bad_alloc caught: %s", PROGRAM_STR(progid), ba.what()); // generic bad initialization
#else
#define COLOR BRO
#define EXCEPBANNER "Exception message"
#define THROW(...) Log::throw_(__VA_ARGS__)
#define LOG(...) Log::log(__VA_ARGS__)
#define CLOG(...)             \
    {                         \
        _color = COLOR;       \
        Log::log(__VA_ARGS__); \
    }
#define LOGE(exception_buffer)          \
    Log::logexception(exception_buffer); \
    return EXIT_FAILURE
#define CLOGE(exception_buffer)             \
    {                                       \
        _color = COLOR;                     \
        Log::logexception(exception_buffer); \
        return EXIT_FAILURE;                \
    }
#define BADINIT Log::log("%s: bad initialization.", PROGRAM_STR(progid)); // generic bad initialization
#define BADALLOCINIT Log::log("%s: initialization bad_alloc caught: %s", PROGRAM_STR(progid), ba.what()); // generic bad initialization
#endif

#define handle_err() err2msg(errno)

//
// Description: check if system timezone environment is setting to UTC and if not, force setting to UTC
//
void utc_timezone_setup(void);

//
//
//
class SwVer
{
    int ver, subver, day, month, year;

public:
    SwVer(int, int, int, int, int); // ctor

    // Prepare for the Output Stream Object the formatted software version number (see class SwVer header section)
    friend std::ostream &operator<<(std::ostream &, const SwVer &);
};

//
//
//
namespace Log
{
char *gettime_r(char *&); // get time string in readable format. After use timebuf memory must be deleted.

void throw_(const char *, const char *, int, const char *, ...);

void log(const char *, const char *, int, const char *, ...);

void throw_(const char *, ...);

void log(const char *, ...);

void logexception(const char *);
};

//
// Description: Function called by sa_sigaction when signal is received.
//
void sighandler(int, siginfo_t *, void *);

//
// Description: Lock a file.
//
bool file_lock(FILE *, const bool);

//
// Description: Lock a file descriptor.
//
bool fd_lock(int, const bool);

//
// Description: Get the lock type of a file.
//
struct flock get_flock(const char *, const char *, const bool);

//
// Description: Unlock file.
//
bool file_unlock(FILE *);

//
// Description: Unlock file.
//
bool fd_unlock(int);

//
// Description: Convert errno to message.
//
char *err2msg(int &_errno);

//
// Description:
//
namespace DataRetention
{
// concatenate directory name
char *makedir(const char *, const char *);

// concatenate direcory name
char *makedir(const char *, std::string);

// append filename to the current working directory
char *makefile(char *, const char *);
}

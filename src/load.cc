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

#include "mcommon.h"
#include "Setup.h"
#include "Mienro.h"
#include <sys/mman.h> // mmap munmap

extern const char *projectname;
extern const char *_color;
extern sig_atomic_t _signal;
extern sig_atomic_t _signal_quit;
extern program_t progid;
extern bool ischild;
extern bool disclog;
extern int map_wan_fd[MAX_MAPS];
extern int map_ctr_fd[MAX_MAPS];
extern int map_lan_fd[MAX_MAPS];
extern int map_pinned_fd[MAX_MAPS];

void chldmon_daemon(std::unique_ptr<Setup> &, Mienro *);
void monnet(std::unique_ptr<Setup> &, Mienro *);
void mon4(std::unique_ptr<Setup> &setup, Mienro *mienro);
void mon6(std::unique_ptr<Setup> &setup, Mienro *mienro);

int main(int argc, char **argv)
{
#ifndef MIENRO_KOBJPATH
#define TEMP_MIENRO_KOBJ
#define MIENRO_KOBJPATH "../kern"
#endif

    Mienro *mienro = nullptr;
    int fd = EOF;
    char lockpath[MAX_STR_LEN] = { 0 };

    errno = 0;

    try
    {
        const char *prog_wan_name = prog_names[PROG_FWD_WAN];
        const char *prog_ctr_name = prog_names[PROG_FWD_CTR];
        const char *prog_lan_name = prog_names[PROG_FWD_LAN];
        __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
        int prog_fds[PROG_OPT_MAX] = { EOF };
        char filepathname[PATH_MAX];
        struct bpf_object *obj_wan, *obj_ctr, *obj_lan;

        int err;
        pid_t pid = 0;

        // srand(time(NULL));

        // load startup configuration
        std::unique_ptr<Setup> setup(new Setup());

        // load command line options and parse file configuration
        int rc = setup->parseconf(argc, argv);

        switch (rc)
        {
        case SETUP_EXIT_BRIEF:
            setup.reset();
            exit(EXIT_SUCCESS);
        case EXIT_FAILURE:
            BADINIT;
            setup.reset();
            exit(EXIT_FAILURE);
        default:
            break;
        }

        // set signals, drop admin privileges, create pid file // use when and if needed
        if (setup->prepare(pid) == EXIT_FAILURE)
        {
            BADINIT;
            setup.reset();
            exit(EXIT_FAILURE);
        }

        strcpy(lockpath, setup->variant_gethold<std::string>(setup->conf_getval(Setup::lockdir)).c_str());
        strncat(lockpath, "/", 2);
        strncat(lockpath, PROGRAM_STR(MIENROLOAD), (strnlen(PROGRAM_STR(MIENROLOAD), MAX_STR_LEN) + 1));
        strncat(lockpath, ".lock", 6);
#ifdef __linux__
        auto lock = get_flock((const char *)lockpath, PROGRAM_STR(MIENROLOAD), false);
#else
        auto lock = get_flock((const char *)lockpath, PROGRAM_STR(MIENROLOAD), true);
#endif
        if (lock.l_len == EOF)
        {
            if (errno == ENOENT) // No such file or directory
            {
                errno = 0;

                if ((fd = open((const char *)lockpath, O_RDWR | O_CREAT, S_IREAD | S_IWRITE | S_IRGRP | S_IROTH)) == EOF) // Open read/write to obtain the file descriptor
                    THROW("open: %s on %s", handle_err(), lockpath);

                if (fcntl(fd, F_GETFL) == EOF)
                    THROW("fcntl: %s on %s", handle_err(), lockpath);

                lock.l_len = 0;
                lock.l_type = F_WRLCK;
#ifdef __linux__
                if (fcntl(fd, F_OFD_SETLKW, &lock) == EOF)
#else
                if (fcntl(fd, F_SETLK, &lock) == EOF)
#endif
                    THROW("fcntl: %s on %s", handle_err(), lockpath);
            }
            else
            {
#ifdef __linux__
                DVCON LOG("fcntl error setting F_OFD_GETLK on %s", lockpath);
#else
                DVCON LOG("fcntl error setting F_GETLK on %s", lockpath);
#endif
                exit(EXIT_FAILURE);
            }
        }
        else if (lock.l_type == F_UNLCK)
        {
            if ((fd = open((const char *)lockpath, O_RDWR, S_IREAD | S_IWRITE | S_IRGRP | S_IROTH)) == EOF) // Open read/write to obtain the file descriptor
                THROW("open: %s on %s", handle_err(), lockpath);

            if (fcntl(fd, F_GETFL) == EOF)
                THROW("fcntl: %s on %s", handle_err(), lockpath);

            lock.l_type = F_WRLCK;
#ifdef __linux__
            if (fcntl(fd, F_OFD_SETLKW, &lock) == EOF)
#else
            if (fcntl(fd, F_SETLK, &lock) == EOF)
#endif
                THROW("fcntl: %s on %s", handle_err(), lockpath);
        }
        else if (lock.l_type == F_WRLCK)
        {
            DVCON LOG("Another %s instance is running", PROGRAM_STR(MIENROLOAD));

            exit(EXIT_FAILURE);
        }
        else
            exit(EXIT_FAILURE);

        // load Mienro class

        if (setup->variant_gethold<std::string>(setup->conf_getval(Setup::skbmode)).size() == 2 && setup->variant_gethold<std::string>(setup->conf_getval(Setup::skbmode)).compare("on") == 0)
            xdp_flags |= XDP_FLAGS_SKB_MODE;
        else
            xdp_flags |= XDP_FLAGS_DRV_MODE;

        mienro = new Mienro(setup.get(), xdp_flags);

        mienro->bpf_fs_prepare();

        if (setup->variant_gethold<std::string>(setup->conf_getval(Setup::direct)).size() == 2 && setup->variant_gethold<std::string>(setup->conf_getval(Setup::direct)).compare("on") == 0)
        {
            prog_wan_name = prog_names[PROG_FWD_WAN_DIRECT];
            prog_ctr_name = prog_names[PROG_FWD_CTR_DIRECT];
            prog_lan_name = prog_names[PROG_FWD_LAN_DIRECT];
        }

        memset(&map_lan_fd, -1, sizeof(int) * MAX_MAPS);
        memset(&map_ctr_fd, -1, sizeof(int) * MAX_MAPS);
        memset(&map_wan_fd, -1, sizeof(int) * MAX_MAPS);

        char filemap_path[PATH_MAX];

        std::queue<string> types;
        types.push("lanif");
        types.push("ctrif");
        types.push("wanif");

        // Load Kernel programs
        while (!types.empty())
        {
            struct bpf_program *program;
            [[maybe_unused]] struct bpf_prog_load_attr prog_load_attr = {
                .prog_type = BPF_PROG_TYPE_XDP,
                .log_level = 4 // Set log level to maximum verbosity (debug)
            };

#ifdef TEMP_MIENRO_KOBJ
            snprintf(filepathname, PATH_MAX, argv[0]);
            char *p = strrchr(filepathname, ASCII_SL);
            snprintf(p, PATH_MAX - ((p - filepathname + 1)), "/%s/%s_%s_kern.o", MIENRO_KOBJPATH, projectname, types.front().c_str());
#else
            snprintf(filepathname, PATH_MAX, "%s/%s_%s_kern.o", MIENRO_KOBJPATH, projectname, types.front().c_str());
#endif

            if (access(filepathname, O_RDONLY) < 0)
                THROW("%s: error accessing file %s: %s", PROGRAM_STR(progid), filepathname, handle_err());

            prog_load_attr.file = filepathname; // Path to your BPF program

            if (types.front().compare("wanif") == 0)
                err = bpf_prog_load(filepathname, BPF_PROG_TYPE_XDP, &obj_wan, &prog_fds[PROG_FWD_WAN]);
            else if (types.front().compare("ctrif") == 0)
                err = bpf_prog_load(filepathname, BPF_PROG_TYPE_XDP, &obj_ctr, &prog_fds[PROG_FWD_CTR]);
            else
                err = bpf_prog_load(filepathname, BPF_PROG_TYPE_XDP, &obj_lan, &prog_fds[PROG_FWD_LAN]);
            // err = bpf_prog_load_xattr(&prog_load_attr, &obj_lan, &prog_fds[PROG_FWD_LAN]); // May be unused

            if (err)
                THROW("Does kernel support devmap lookup?"); // If not, the error message will be: "cannot pass map_type 14 into func bpf_map_lookup_elem#1"

            if (types.front().compare("wanif") == 0)
            {
                program = bpf_object__find_program_by_title(obj_wan, prog_wan_name);

                prog_fds[PROG_FWD_WAN] = bpf_program__fd(program);

                if (prog_fds[PROG_FWD_WAN] < 0)
                    THROW("program not found: %s", strerror(prog_fds[PROG_FWD_WAN]));
            }
            else if (types.front().compare("ctrif") == 0)
            {
                program = bpf_object__find_program_by_title(obj_ctr, prog_ctr_name);

                prog_fds[PROG_FWD_CTR] = bpf_program__fd(program);

                if (prog_fds[PROG_FWD_CTR] < 0)
                    THROW("program not found: %s", strerror(prog_fds[PROG_FWD_CTR]));
            }
            else
            {
                program = bpf_object__find_program_by_title(obj_lan, prog_lan_name);

                prog_fds[PROG_FWD_LAN] = bpf_program__fd(program);

                if (prog_fds[PROG_FWD_LAN] < 0)
                    THROW("program not found: %s", strerror(prog_fds[PROG_FWD_LAN]));
            }

            if (types.front().compare("wanif") == 0)
            {
                map_wan_fd[PROG_MAP_IDX] = bpf_object__find_map_fd_by_name(obj_wan, map_wan_names[PROG_MAP_IDX]);

                if (map_wan_fd[PROG_MAP_IDX] < 0)
                    THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map_wan_fd[PROG_MAP_IDX]);
            }
            else if (types.front().compare("ctrif") == 0)
            {
                map_ctr_fd[PROG_MAP_IDX] = bpf_object__find_map_fd_by_name(obj_ctr, map_ctr_names[PROG_MAP_IDX]);

                if (map_ctr_fd[PROG_MAP_IDX] < 0)
                    THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map_ctr_fd[PROG_MAP_IDX]);
            }
            else
            {
                map_lan_fd[PROG_MAP_IDX] = bpf_object__find_map_fd_by_name(obj_lan, map_lan_names[PROG_MAP_IDX]);

                if (map_lan_fd[PROG_MAP_IDX] < 0)
                    THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map_lan_fd[PROG_MAP_IDX]);
            }

            types.pop();
        }

        types.push("lanif/");
        types.push("ctrif/");
        types.push("wanif/");

        // Pin bpf maps (only for already unexported maps)
        while (!types.empty())
        {
            for (auto i = (int)EVENTS_MAP_IDX; i < (int)MAX_MAPS; i++)
            {
                int rc = 0;

                errno = 0;
                memset(&filemap_path, 0, PATH_MAX);
                snprintf(filemap_path, sizeof(filemap_path), file_map[static_cast<idx_t>(i)], mienro->get_mappath().c_str(), types.front().c_str());

                int pathfd = bpf_obj_get(filemap_path);

                if (pathfd > 0)
                {
                    struct bpf_map *map = NULL;

                    if (types.front().compare("wanif/") == 0)
                        map = bpf_object__find_map_by_name(obj_wan, map_wan_names[static_cast<idx_t>(i)]);
                    else if (types.front().compare("ctrif/") == 0)
                        map = bpf_object__find_map_by_name(obj_ctr, map_ctr_names[static_cast<idx_t>(i)]);
                    else if (types.front().compare("lanif/") == 0)
                        map = bpf_object__find_map_by_name(obj_lan, map_lan_names[static_cast<idx_t>(i)]);

                    if (map)
                    {
                        if (libbpf_get_error(map))
                            THROW("map not found: %s", handle_err());
                    }
                    else
                        THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map);

                    // std::cout << bpf_map__name(map) << std::endl;

                    if (types.front().compare("wanif/") == 0)
                        map_wan_fd[static_cast<idx_t>(i)] = pathfd;
                    else if (types.front().compare("ctrif/") == 0)
                        map_ctr_fd[static_cast<idx_t>(i)] = pathfd;
                    else if (types.front().compare("lanif/") == 0)
                        map_lan_fd[static_cast<idx_t>(i)] = pathfd;
                }
                else
                {
                    if (types.front().compare("wanif/") == 0)
                    {
                        map_wan_fd[static_cast<idx_t>(i)] = bpf_object__find_map_fd_by_name(obj_wan, map_wan_names[static_cast<idx_t>(i)]);

                        if (map_wan_fd[static_cast<idx_t>(i)] < 0)
                            THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map_wan_fd[static_cast<idx_t>(i)]);

                        rc = bpf_obj_pin(map_wan_fd[static_cast<idx_t>(i)], filemap_path); // create file from scratch
                    }
                    else if (types.front().compare("ctrif/") == 0)
                    {
                        map_ctr_fd[static_cast<idx_t>(i)] = bpf_object__find_map_fd_by_name(obj_ctr, map_ctr_names[static_cast<idx_t>(i)]);

                        if (map_ctr_fd[static_cast<idx_t>(i)] < 0)
                            THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map_ctr_fd[static_cast<idx_t>(i)]);

                        rc = bpf_obj_pin(map_ctr_fd[static_cast<idx_t>(i)], filemap_path); // create file from scratch
                    }
                    else if (types.front().compare("lanif/") == 0)
                    {
                        map_lan_fd[static_cast<idx_t>(i)] = bpf_object__find_map_fd_by_name(obj_lan, map_lan_names[static_cast<idx_t>(i)]);

                        if (map_lan_fd[static_cast<idx_t>(i)] < 0)
                            THROW("bpf_object__find_map_fd_by_name return bad_file_descriptor (%d)", map_lan_fd[static_cast<idx_t>(i)]);

                        rc = bpf_obj_pin(map_lan_fd[static_cast<idx_t>(i)], filemap_path); // create file from scratch
                    }

                    if (rc != 0)
                        THROW("When update map path %s: bpf: obj pin ret:(%d, %s)", filemap_path, rc, handle_err());
                }
            }

            types.pop();
        }

        try
        {
            mienro->configure_network_interfaces(); // Load interface and addresses on bpf map

            std::queue<idx_t> _types;
            _types.push(SSHV4TIMEO_MAP_IDX);
            _types.push(SSHV6TIMEO_MAP_IDX);
            _types.push(MNET_MAP_IDX);
            _types.push(BGPNEIGH_V4WL_MAP_IDX);
            _types.push(BGPNEIGH_V6WL_MAP_IDX);

            memset(&map_pinned_fd, EOF, sizeof(int) * MAX_MAPS);

            char filemap_path[PATH_MAX];

            // Begin of pinning get files Note: this process inside main program is done only for reference uses
            while (!_types.empty())
            {
                memset(&filemap_path, 0, PATH_MAX);
                snprintf(filemap_path, sizeof(filemap_path), file_map[_types.front()], "/sys/fs/", "bpf/");

                if ((map_pinned_fd[_types.front()] = bpf_obj_get(filemap_path)) <= 0)
                    THROW("map cannot be loaded: %s Hint: is mienro loaded?", handle_err());

                _types.pop();
            }

            mienro->acl_maps_fill(); // populate whitelist for acl
        }
        catch (char *e)
        {
            if (map_wan_fd[PROG_MAP_IDX] >= 0 || map_ctr_fd[PROG_MAP_IDX] >= 0 || map_lan_fd[PROG_MAP_IDX] >= 0)
                mienro->map_cleanup();

            throw(e);
        }
        catch (const char *e)
        {
            if (map_wan_fd[PROG_MAP_IDX] >= 0 || map_ctr_fd[PROG_MAP_IDX] >= 0 || map_lan_fd[PROG_MAP_IDX] >= 0)
                mienro->map_cleanup();

            throw(e);
        }
        catch (std::exception const &e)
        {
            if (map_wan_fd[PROG_MAP_IDX] >= 0 || map_ctr_fd[PROG_MAP_IDX] >= 0 || map_lan_fd[PROG_MAP_IDX] >= 0)
                mienro->map_cleanup();

            throw(e.what());
        }

        // Attach XDP programs to devices
        mienro->attach(prog_fds);

        // Clear ssh's map from unused keys
        mienro->ssh_clr_map();

        try
        {
            mienro->set_txports();
        }
        catch (char *e)
        {
            if (map_wan_fd[PROG_MAP_IDX] >= 0 || map_ctr_fd[PROG_MAP_IDX] >= 0 || map_lan_fd[PROG_MAP_IDX] >= 0)
            {
                mienro->map_cleanup();
                mienro->detach();
            }

            throw(e);
        }
        catch (const char *e)
        {
            if (map_wan_fd[PROG_MAP_IDX] >= 0 || map_ctr_fd[PROG_MAP_IDX] >= 0 || map_lan_fd[PROG_MAP_IDX] >= 0)
            {
                mienro->map_cleanup();
                mienro->detach();
            }

            throw(e);
        }
        catch (std::exception const &e)
        {
            if (map_wan_fd[PROG_MAP_IDX] >= 0 || map_ctr_fd[PROG_MAP_IDX] >= 0 || map_lan_fd[PROG_MAP_IDX] >= 0)
            {
                mienro->map_cleanup();
                mienro->detach();
            }

            throw(e.what());
        }

        errno = 0;

        // Create file that indicate that mienro kernel programs are loading on interfaces
        FILE *file = fopen(mienro->get_loadpath().c_str(), "w");

        if ((errno != 0 && errno != 2) || file == nullptr)
            THROW("couldn't open %s %s", mienro->get_loadpath().c_str(), handle_err());

        if (fclose(file) == EOF)
            THROW("couldn't close %s %s", mienro->get_loadpath().c_str(), handle_err());

        // Run childs daemon
        if (setup->variant_gethold<bool>(setup->conf_getval(Setup::debug)) == true)
        {
            CLOG("Start monitors in foreground mode");
            chldmon_daemon(setup, mienro);
        }
        else
        {
            pid_t chldpid = 0;

            if ((chldpid = fork()) > 0)
            { // logs must be keep alive for child reports, setup destruction cannot close it
                disclog = false;
                DVCON CLOG("Start childs");
            }
            else if (chldpid == 0)
            {
#ifdef SYSTEMD_ACTIVE
                assert(setup->pid_write(getpid(), nullptr) == EXIT_SUCCESS);
#endif

                chldmon_daemon(setup, mienro);

                // detach xdp programs
                mienro->map_cleanup();
                mienro->detach();
                delete mienro;
                delete setup.release(); // delete setup must be used here
                exit(EXIT_SUCCESS);
            }
            else
                throw("Internal error: fork() failed!");
        }

        if (setup->variant_gethold<bool>(setup->conf_getval(Setup::debug)) == true)
        {
            // Delete file that indicate that mienro kernel programs are loading on interfaces
            if (unlink(mienro->get_loadpath().c_str()) == EOF)
                THROW("unlink file %s %s", mienro->get_loadpath().c_str(), handle_err());

            // detach xdp programs
            mienro->map_cleanup();
            mienro->detach();
        }

        delete mienro;
        return EXIT_SUCCESS;
    }
    catch (char *e)
    {
        if (mienro)
            delete mienro;

        LOGE(e);
    }
    catch (const char *e)
    {
        if (mienro)
            delete mienro;

        LOGE(e);
    }
    catch (std::exception const &e)
    {
        if (mienro)
            delete mienro;

        LOGE(e.what());
    }
}

//
// Name: Mienro::chldmon_daemon
//
// Description:
//
// Input:
//
// Return:
//
void chldmon_daemon(std::unique_ptr<Setup> &setup, Mienro *mienro)
{
    try
    {
        bool init = true;
#define PRGOFFSET 1

        std::array<cld_stat_t, INVALIDPROG> chldpid_vec;

        if (nice(19)) // lowest priority
            while (ischild == false)
            {
                int wstatus = 0;
                pid_t pid = EOF;

                if (init == false && (pid = waitpid(0, &wstatus, WUNTRACED)) == EOF && errno == EINTR)
                {
                ___exit:
                    if (_signal == SIGTERM)
                    { // before reset _signal wait the ending childs
                        for (__u8 iter = (MIENROLOAD + PRGOFFSET); iter < chldpid_vec.size(); iter++)
                            if ((chldpid_vec.at(iter)).pid > 0)
                            {
                                if (kill((chldpid_vec.at(iter)).pid, SIGTERM) == EOF)
                                {
                                    DVCON LOG("kill process with pid %d: %d", (int)(chldpid_vec.at(iter)).pid, strerror(errno));

                                    if (errno == ESRCH)
                                        continue;
                                }
                                else
                                    (chldpid_vec.at(iter)).rkl = true;
                            }

                        for (__u8 iter = (MIENROLOAD + PRGOFFSET); iter < chldpid_vec.size(); iter++)
                            if ((chldpid_vec.at(iter)).pid > 0 && (chldpid_vec.at(iter)).rkl == true)
                            {
                                DVCON
                                {
                                    if (waitpid((chldpid_vec.at(iter)).pid, &wstatus, WUNTRACED) == (chldpid_vec.at(iter)).pid)
                                        LOG("killed process with pid %d", (int)(chldpid_vec.at(iter)).pid);
                                    else
                                        LOG("already dead process with pid %d: %s", (int)(chldpid_vec.at(iter)).pid, strerror(errno));
                                }
                                else waitpid((chldpid_vec.at(iter)).pid, &wstatus, WUNTRACED);
                            }

                        _signal = 0; // set signal to 0 for next function calls
                        _signal_quit = 0; // set signal to 0 for next function calls
                        return;
                    }
                }
                else if (_signal == SIGINT)
                {

                    for (__u8 iter = (MIENROLOAD + PRGOFFSET); iter < chldpid_vec.size(); iter++)
                        if ((chldpid_vec.at(iter)).pid > 0)
                        {
                            DVCON
                            {
                                if (waitpid((chldpid_vec.at(iter)).pid, &wstatus, WUNTRACED) == (chldpid_vec.at(iter)).pid)
                                    LOG("killed process with pid %d", (int)(chldpid_vec.at(iter)).pid);
                                else
                                    LOG("already dead process with pid %d: %s", (int)(chldpid_vec.at(iter)).pid, strerror(errno));
                            }
                            else waitpid((chldpid_vec.at(iter)).pid, &wstatus, WUNTRACED);
                        }

                    _signal = 0; // set signal to 0 for next function calls
                    _signal_quit = 0; // set signal to 0 for next function calls
                    return;
                }

                for (__u8 iter = (MIENROLOAD + PRGOFFSET); iter < chldpid_vec.size(); iter++)
                {
                    if (init == true || (chldpid_vec.at(iter)).pid == pid)
                    {
                        if (init == true)
                            goto tryfork;

                        switch (errno)
                        {
                        case ECHILD: // no child process anymore
                            if (_signal == 0)
                                goto tryfork;

                            break;
                        default:
                            if (WIFEXITED(wstatus))
                            {
                                DVCON LOG("Map scan child %d exited with termination signal status: SIGTERM", (int)pid);

                                if (WEXITSTATUS(wstatus) == EXIT_SUCCESS)
                                {
                                    switch (_signal)
                                    {
                                    case SIGTERM:
                                        goto tryfork;
                                    case SIGINT:
                                        continue;
                                        break;
                                    default:
                                        if (_signal_quit == SIGQUIT)
                                        {
                                            kill((chldpid_vec.at(iter)).pid, SIGQUIT);

                                            _signal_quit = 0;
                                        }

                                        goto tryfork;
                                    }
                                }
                                else if (WEXITSTATUS(wstatus) == EXIT_FAILURE)
                                {
                                    LOG("%s exit cause internal error", PROGRAM_STR((chldpid_vec.at(iter)).cld));

                                    if (setup->variant_gethold<bool>(setup->conf_getval(Setup::debug)) == true)
                                        _signal = SIGINT;
                                    else
                                        _signal = SIGTERM;

                                    (chldpid_vec.at(iter)).pid = 0;
                                    goto ___exit;
                                }
                            }
                            else if (WIFSIGNALED(wstatus))
                            {
#ifdef WCOREDUMP
                                DVCON LOG("Map scan child %d exited with abnormal termination signal status: %s%s", (int)pid, strsignal(WTERMSIG(wstatus)), (WCOREDUMP(wstatus) ? " (core file generated)" : ""));
#else
                                DVCON LOG("Map scan child %d exited with abnormal termination signal status: %s", (int)pid, strsignal(WTERMSIG(wstatus)));
#endif
                            }
                            else if (WIFSTOPPED(wstatus))
                            {
                                DVCON LOG("Map scan child %d exited with stopped termination signal status: %s", (int)pid, strsignal(WSTOPSIG(wstatus)));
                            }
                            else if (WIFCONTINUED(wstatus)) // Note: SIGSTOP is administratively disabled
                            {
                                DVCON LOG("Map scan child %d resumed after receive signal status: %s", (int)pid, strsignal(SIGCONT));
                                continue;
                            }
                            else
                                DVCON LOG("Map scan child %d exited with unknown termination", (int)pid);

                        tryfork:

                            if (init == true)
                                (chldpid_vec.at(iter)).cld = (program_t)iter;

                            pid_t cldpid = fork();

                            if (cldpid == 0)
                            { // logs must be keep alive for child reports and setup destruction cannot close it
                                disclog = false;
                                ischild = true;

                                if (geteuid() == 0)
                                {
                                    struct passwd *pwd = getpwnam(setup->variant_deduct_to_string(setup->conf_getval(Setup::user)).c_str());

                                    if (pwd == nullptr)
                                    {
                                        DVCON LOG("User %s do not exists", setup->variant_deduct_to_string(setup->conf_getval(Setup::user)).c_str());
                                        std::this_thread::sleep_for(std::chrono::milliseconds((unsigned short)(500)));
                                        throw std::runtime_error("Internal error");
                                    }

                                    if (setuid(pwd->pw_uid) != 0 || seteuid(pwd->pw_uid) != 0)
                                    {
                                        DVCON LOG("Cannot suid to user %s", setup->variant_deduct_to_string(setup->conf_getval(Setup::user)).c_str());
                                        std::this_thread::sleep_for(std::chrono::milliseconds((unsigned short)(500)));
                                        throw std::runtime_error("Internal error");
                                    }
                                }

                                program_t *id = (program_t *)mmap(NULL, sizeof(program_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, EOF, 0);

                                if (id == MAP_FAILED)
                                {
                                    DVCON LOG("mmap failed %s", strerror(errno));
                                    std::this_thread::sleep_for(std::chrono::milliseconds((unsigned short)(500)));
                                    throw std::runtime_error("Internal error");
                                }

                                *id = (chldpid_vec.at(iter)).cld;

                                // Mark the memory area as read-only mode.
                                if (mprotect(id, sizeof(program_t), PROT_READ))
                                {
                                    DVCON LOG("mprotect failed %s", strerror(errno));
                                    std::this_thread::sleep_for(std::chrono::milliseconds((unsigned short)(500)));
                                    throw std::runtime_error("Internal error");
                                }

                                if (nice(19)) // lowest priority
                                    switch (*id)
                                    {
                                    case MIENROMON4:
                                        //    munmap(id, sizeof(program_t));

                                        mon4(setup, mienro);
                                        break;
                                    case MIENROMON6:
                                        //    munmap(id, sizeof(program_t));

                                        mon6(setup, mienro);
                                        break;
                                    case MIENROMONNET:
                                        //    munmap(id, sizeof(program_t));

                                        monnet(setup, mienro);
                                        break;
                                    default:
                                        break;
                                    }

                                throw std::runtime_error("Internal error");
                            }
                            else
                            {
                                (chldpid_vec.at(iter)).pid = cldpid;

                                DVCON LOG("Map scan child %d %d started", iter, (int)cldpid);

                                if (iter == chldpid_vec.size() - 1)
                                    init = false;
                            }
                        }
                    }
                }
            }
    }
    catch (char *e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
    catch (const char *e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
    catch (std::runtime_error const &e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
    catch (std::exception const &e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
}

//
// Name: Mienro::monnet
//
// Description: Monitor vlan updates on wan interface and routes updates to bgp peers
//
// Input:
//
// Return:
//
void monnet(std::unique_ptr<Setup> &setup, Mienro *mienro)
{
    try
    {
        std::map<__u32, int> ifidx_map;
        int err = EOF;
        __u16 failcounter = 0;
        __u32 if_idx = 0;
        __u32 prev_if_idx = 0;
        __u16 nlmsg_type = RTM_GETLINK;
        pid_t pid = getpid(); // our process ID to build the correct netlink address
        nl_conn_t nl_conn;

        nl_conn.nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

        if (nl_conn.nlfd < 0)
        {
            LOG("Failed to open netlink socket: %s", handle_err());
            throw std::runtime_error("Internal error");
        }

        mienro->nl_process_req(&nl_conn, nlmsg_type, pid);

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
                throw std::runtime_error("Internal error");
            }

            // len = recvmsg(nl_conn.nlfd, &nl_conn.msg, MSG_DONTWAIT);
            len = recvmsg(nl_conn.nlfd, &nl_conn.msg, MSG_WAITALL);

            if (len < 0)
            {
                switch (_signal)
                {
                case SIGTERM:
                case SIGINT:
                case SIGQUIT:
                    DVCON LOG("Map scan child terminated");

                    if (mienro)
                        delete mienro;

                    if (setup)
                        setup.reset();

                    close(nl_conn.nlfd);
                    nl_conn.nlfd = EOF;
                    exit(EXIT_SUCCESS);
                }

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
                            mienro->nl_process_req(&nl_conn, nlmsg_type, pid); // Get already configured addresses
                            break;
                        case RTM_GETADDR:
                            nlmsg_type = RTM_GETROUTE;
                            mienro->nl_process_req(&nl_conn, nlmsg_type, pid); // Get Already configured routes
                            break;
                        default:
                            mienro->nl_process_req(&nl_conn, (RTM_GETLINK | RTM_GETADDR | RTM_GETROUTE), pid); // Get all and monitor interfaces

                            prev_if_idx = ~0;

                            // syncronize bpf map to remove existant vlan
                            while (bpf_map_get_next_key(map_pinned_fd[MNET_MAP_IDX], &prev_if_idx, &if_idx) == 0)
                            {
                                if (ifidx_map.find(if_idx) == ifidx_map.end()) // if not found in std::map then, delete also for bpf_map
                                {
                                    if ((err = bpf_map_delete_elem(map_pinned_fd[MNET_MAP_IDX], &if_idx)) < 0)
                                        LOG("Failed deleting interface %d on %s map (ret: %d)", if_idx, map_wan_names[MNET_MAP_IDX], err);
                                }

                                prev_if_idx = if_idx;

                                switch (_signal)
                                {
                                case SIGTERM:
                                case SIGINT:
                                case SIGQUIT:
                                    DVCON LOG("Map scan child terminated");

                                    if (mienro)
                                        delete mienro;

                                    if (setup)
                                        setup.reset();

                                    close(nl_conn.nlfd);
                                    nl_conn.nlfd = EOF;
                                    exit(EXIT_SUCCESS);
                                }
                            }

                            ifidx_map.clear();

                            DCON LOG("Interfaces monitor ready. %sPress Ctrl+c to stop%s", LPU, NOR);
                            break;
                        }

                        goto rebind;
                        break;
                    }
                    break;
                case RTM_BASE: // used for add link
                case RTM_DELLINK:
                case RTM_NEWADDR:
                case RTM_DELADDR:
                case RTM_NEWROUTE:
                case RTM_DELROUTE:
                    mienro->nl_handle_msg(&nl_conn, ifidx_map);
                    break;
                default: // for education only, print any message that would not be DONE or NEWLINK, which should not happen here
                    //    printf("message type %d, length %d\n", nl_conn.nh->nlmsg_type, nl_conn.nh->nlmsg_len);
                    break;
                }
            }

            switch (_signal)
            {
            case SIGTERM:
            case SIGINT:
            case SIGQUIT:
                DVCON LOG("Map scan child terminated");

                if (mienro)
                    delete mienro;

                if (setup)
                    setup.reset();

                close(nl_conn.nlfd);
                nl_conn.nlfd = EOF;
                exit(EXIT_SUCCESS);
            }
        }

        if (mienro)
            delete mienro;

        // clean up and finish properly
        close(nl_conn.nlfd);
        nl_conn.nlfd = EOF;
    }
    catch (char *e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
    catch (const char *e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
    catch (std::runtime_error const &e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
    catch (std::exception const &e)
    {
        if (mienro)
            delete mienro;

        if (setup)
            setup.reset();

        exit(EXIT_FAILURE);
    }
}

//
// Name: mon4
//
// Description: Keep trace of ssh requests on ipv4 protocol
//
// Input:
//
// Return:
//
void mon4(std::unique_ptr<Setup> &setup, Mienro *mienro)
{
    in4_addr prev_addrV4 = 0, addrV4;

    while (true)
    { // scan bpf map to remove ssh ipv4 blacklist when quarantine is ended
        if (bpf_map_get_next_key(map_pinned_fd[SSHV4TIMEO_MAP_IDX], &prev_addrV4, &addrV4) == 0)
        {
            struct sysinfo s_info;

            if (sysinfo(&s_info) != 0)
                break;

            timeo_t timeo = {};

            assert(bpf_map_lookup_elem_flags(map_pinned_fd[SSHV4TIMEO_MAP_IDX], &addrV4, &timeo, BPF_F_LOCK) == 0);

            if (s_info.uptime > 0)
            {
                if (timeo.creationtime + setup->variant_gethold<long int>(setup->conf_getval(Setup::sshbfquar)) < (long long unsigned)s_info.uptime)
                    bpf_map_delete_elem(map_pinned_fd[SSHV4TIMEO_MAP_IDX], &addrV4);
            }
            else
                bpf_map_delete_elem(map_pinned_fd[SSHV4TIMEO_MAP_IDX], &addrV4);

            prev_addrV4 = addrV4;
            // memset(&addrV4, 0, sizeof(in4_addr));
        }
        else
            prev_addrV4 = 0;

        switch (_signal)
        {
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
            DVCON LOG("Map scan child terminated");

            if (mienro)
                delete mienro;

            if (setup)
                setup.reset();

            exit(EXIT_SUCCESS);
        }

        std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned short>(setup->variant_gethold<long int>(setup->conf_getval(Setup::mmonwait)))));
    }
}

//
// Name: Mienro::mon6
//
// Description: Keep trace of ssh requests on ipv6 protocol
//
// Input:
//
// Return:
//
void mon6(std::unique_ptr<Setup> &setup, Mienro *mienro)
{
    struct in6_addr prev_addrV6 = { 0 }, addrV6;

    while (true)
    { // scan bpf map to remove ssh ipv6 blacklist when quarantine is ended
        if (bpf_map_get_next_key(map_pinned_fd[SSHV6TIMEO_MAP_IDX], &prev_addrV6, &addrV6) == 0)
        {
            struct sysinfo s_info;

            if (sysinfo(&s_info) != 0)
                break;

            timeo_t timeo = {};

            assert(bpf_map_lookup_elem_flags(map_pinned_fd[SSHV6TIMEO_MAP_IDX], &addrV6, &timeo, BPF_F_LOCK) == 0);

            if (s_info.uptime > 0)
            {
                if (timeo.creationtime + setup->variant_gethold<long int>(setup->conf_getval(Setup::sshbfquar)) < (long long unsigned)s_info.uptime)
                    bpf_map_delete_elem(map_pinned_fd[SSHV6TIMEO_MAP_IDX], &addrV6);
            }
            else
                bpf_map_delete_elem(map_pinned_fd[SSHV6TIMEO_MAP_IDX], &addrV6);

            prev_addrV6 = addrV6;
            // memset(&addrV6, 0, sizeof(struct in6_addr));
        }
        else
            memset(&prev_addrV6, 0, sizeof(struct in6_addr));

        switch (_signal)
        {
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
            DVCON LOG("Map scan child terminated");

            if (mienro)
                delete mienro;

            if (setup)
                setup.reset();

            exit(EXIT_SUCCESS);
        }

        std::this_thread::sleep_for(std::chrono::seconds(static_cast<unsigned short>(setup->variant_gethold<long int>(setup->conf_getval(Setup::mmonwait)))));
    }
}

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

// Inherited from common.cc
extern const char *projectname;
extern char *progname;
extern program_t progid;
extern FILE *logstream;
extern bool leavelogs;
extern bool ischild;
extern bool disclog;
extern sig_atomic_t _signal;
extern sig_atomic_t _signal_quit;
extern const char *_color;
extern bool _debug;

// chldinfo_t chldinfo;

//
// Name: sighandler
//
// Description: Function called by sa_sigaction when signal is received.
// If signal is SIGCHLD, try to put pid and return status of calling child into chldinfo.brief buffer else, set _signal to sig value.
//
// Input:
//	sig - the signal (always present)
//	info - the structure containing information about closed child process
//	ucontext - unused value
//
// Return:
//
void sighandler(int sig, siginfo_t *info, void *ucontext)
{
    /*
     * SIGTERM 	termination request, sent to the program
     * SIGSEGV 	invalid memory access (segmentation fault)
     * SIGINT 	external interrupt, usually initiated by the user
     * SIGILL 	invalid program image, such as invalid instruction
     * SIGABRT 	abnormal termination condition, as is e.g. initiated by std::abort()
     * SIGFPE 	erroneous arithmetic operation such as divide by zero
     */
    switch (sig)
    {
    case SIGINT:
        _signal = sig;
        //		std::cerr << std::endl << "Finished " << std::endl;
        break;
    case SIGQUIT:
        _signal_quit = sig;
        break;
    /*
    case SIGCHLD: // when receive SIGCHLD function become single thread and status can be handled in blocking mode therefore, there is not the need to use atomic data (locally tested)
            // SIGCHLD fills in si_pid, si_uid, si_status, si_utime, and si_stime, providing information about the child. // man 2 sigaction
            // Warning: some signals can be lost and this is a normal functionality.
            if (info->si_code == CLD_EXITED)
            {
                    switch (info->si_status)
                    {
                            case EXIT_FAILURE:
                                    LOG("\n%sA serious internal error was occurred from child with pid %d.%s\n", RED, (int)info->si_pid, NOR);
                                    assert(write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG)) == sizeof(SIGINT_MSG));
                                    _signal = SIGINT; // signal spoof
                            break;
                            default:

                                    for (uint8_t i = 0; i < MASKBITS; i++)
                                            if (bitinfo(chldinfo.signals, i) == OFF) // if bit is set to 0
                                            {
                                                    assert(chldinfo.brief[i].pid == 0); // TODO leave only during stress tests
                                                    assert(chldinfo.brief[i].status == 0); // TODO leave only during stress test
                                                    chldinfo.brief[i].pid = info->si_pid;
                                                    chldinfo.brief[i].status = info->si_status;
                                                    bitset(chldinfo.signals, i, ON); // set bit to 1
                                                    break;
                                            }
                            break;
                    };
            }
    break; */
    default:
        _signal = sig;
        break;
    }

    return;
}

//
// Name: Setup
//
// Description: Costructor for Setup class
//
Setup::Setup(void) // ctor
    : classname("Setup")
    , alarm(false)
    , ut(false)
    , parameters(nullptr)
    , sock_listen_raw(EOF)
    , sock_send_raw(EOF)
    , map_owner(EOF)
    , map_group(EOF)
{
    try
    {
        parameters = new cnfp_t[paramsize]; // Note function called work to 'this' temporary object and need to be deleted at the end of the same.
    }
    catch (std::bad_alloc &ba)
    {
        BADALLOCINIT;
    }

    set_parameters(parameters);

    //	memset(&chldinfo, 0, sizeof(chldinfo_t));
    //	chldinfo.homonym = MASKBITS;
}

//
// Name: Setup
//
// Description: Costructor for Setup class
//
Setup::Setup(bool A) // ctor
    : classname("Setup")
    , alarm(A)
    , ut(false)
    , parameters(nullptr)
    , sock_listen_raw(EOF)
    , sock_send_raw(EOF)
    , map_owner(EOF)
    , map_group(EOF)
{
    try
    {
        parameters = new cnfp_t[paramsize]; // Note function called work to 'this' temporary object and need to be deleted at the end of the same.
    }
    catch (std::bad_alloc &ba)
    {
        BADALLOCINIT;
    }

    set_parameters(parameters);

    //	memset(&chldinfo, 0, sizeof(chldinfo_t));
    //	chldinfo.homonym = MASKBITS;
}

//
// Name: Setup
//
// Description: Costructor for Setup class (Unit Test)
//
Setup::Setup(const char *UT) // ctor
    : classname("Setup")
    , alarm(false)
    , ut(false)
    , parameters(nullptr)
    , sock_listen_raw(EOF)
    , sock_send_raw(EOF)
    , map_owner(EOF)
    , map_group(EOF)
{
    try
    {
        parameters = new cnfp_t[paramsize]; // Note function called work to 'this' temporary object and need to be deleted at the end of the same.
    }
    catch (std::bad_alloc &ba)
    {
        BADALLOCINIT;
    }

    if (strncmp(UT, "UT", 2) == 0)
        ut = true;

    set_parameters(parameters);

    //	memset(&chldinfo, 0, sizeof(chldinfo_t));
    //	chldinfo.homonym = MASKBITS;
}

//
// Name: ~Setup
//
// Description: Destructor for Setup class
//
Setup::~Setup() // dtor
{
    if (disclog == true)
    {
        if (leavelogs == false)
        {
            if (ischild == false)
                LOG("%s: %sFinished%s", progname, GRE, NOR, leavelogs);
        }
        else
            CLOG("%s: Finished with exception", progname, leavelogs);

        if (leavelogs == false && logstream != nullptr && logstream != stderr)
        {
            assert(fclose(logstream) == 0);
            logstream = nullptr;
        }
    }

    if (parameters)
        for (unsigned short i = 0; i < paramsize; i++)
        {
            cnfdata_t *ptr = &parameters[i].cnfdata;
            cnfdata_t *keep_ptr = &parameters[i].cnfdata;
            bool grpvalues = false; // Only groups of addresses are supported
        scanvalue:
            switch (ptr->vdata.tag)
            {
            case CHARS:
                if (ptr->vdata.strval)
                    free(ptr->vdata.strval);
                break;
            default:
                break;
            }

            // Iterate Linked List - Warning: for this data structure first element cannot be delete here! -
            if (ptr->next)
            {
                keep_ptr = ptr->next;

                if (grpvalues == true && ptr)
                    delete ptr;

                ptr = keep_ptr;
                grpvalues = true;
                goto scanvalue;
            }
            else if (grpvalues == true && ptr)
                delete ptr;
        }

    if (progname)
        delete[] progname;

    if (parameters)
        delete[] parameters;

    if (sock_send_raw >= 0)
        assert(close(sock_send_raw) == 0);

    if (disclog == true && sock_listen_raw >= 0)
        assert(close(sock_listen_raw) == 0);
}

//
// Name: Setup::pid_write
//
// Description: Write pid file.
//
// Input:
// pid - the number of pid to save
// pidfile - the file where pid must be stored
//
// Output: the main process id
//
// Return: EXIT_SUCCESS on success, EXIT_FAILURE on failure.
//
int Setup::pid_write(pid_t pid, const char *pidfile) const
{
    char pid_path[PATH_MAX];
    int ret = 0;

    if (pidfile == nullptr)
        ret = snprintf(pid_path, PATH_MAX, "%s/%s.pid", param()[rundir].cnfdata.vdata.strval, progname);
    else
        ret = snprintf(pid_path, PATH_MAX, "%s/%s.pid", param()[rundir].cnfdata.vdata.strval, pidfile);

    if (ret <= 0 || ret >= PATH_MAX)
    {
        LOG("%s: %sBad pid filename%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    errno = 0;

    FILE *pidmax_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (errno != 0 || pidmax_file == nullptr)
    {
        LOG("%s: %scouldn't open max system pid value%s %s on %s", progname, RED, NOR, handle_err(), "/proc/sys/kernel/pid_max");
        return EXIT_FAILURE;
    }

    char pidmaxstr[(MAX_STR_LEN + 1)];
    memset(&pidmaxstr, 0, (MAX_STR_LEN + 1));

    size_t pidmax_readed = fread(pidmaxstr, sizeof(char), (MAX_STR_LEN + 1), pidmax_file);

    assert(fclose(pidmax_file) == 0);

    if (errno != 0)
    {
        LOG("%s: %scouldn't read file /proc/sys/kernel/pid_max%s %s", progname, RED, NOR, handle_err());
        return EXIT_FAILURE;
    }

    assert(pidmax_readed == (size_t)strlen(pidmaxstr));

    // exit if pid is invalid
    if (pid == 0 || pid > atoi(pidmaxstr))
    {
        LOG("%s: %sInvalid pid number%s (%d)", progname, RED, NOR, pid);
        return EXIT_FAILURE;
    }

    FILE *pid_file = fopen(pid_path, "w");

    if (errno != 0 || pid_file == nullptr)
    {
        LOG("%s: couldn't open %s.pid %s on %s\n", progname, RED, NOR, pidfile, handle_err(), param()[rundir].cnfdata.vdata.strval);
        return EXIT_FAILURE;
    }

    // protect file from writing from other programs during this writing
    if (file_lock(pid_file, false) == true)
    {
        char pidstr[(pidmax_readed + 1)];
        sprintf(pidstr, "%d\n", (int)pid);

        size_t written = fwrite(pidstr, sizeof(char), strnlen(pidstr, 20), pid_file);

        if (errno != 0)
        {
            LOG("%s: couldn't write file %s on %s\n", progname, RED, NOR, handle_err(), pid_path);
            return EXIT_FAILURE;
        }

        assert(written == (size_t)strlen(pidstr));
    }
    else
    {
        LOG("%s: couldn't not lock file %s\n", progname, RED, NOR, pid_path);
        assert(fclose(pid_file) == 0);
        return EXIT_FAILURE;
    }

    if (file_unlock(pid_file) == false)
    {
        LOG("%s: couldn't not unlock file %s\n", progname, RED, NOR, pid_path);
        assert(fclose(pid_file) == 0);
        return EXIT_FAILURE;
    }

    assert(fclose(pid_file) == 0);

    return EXIT_SUCCESS;
}

//
// Name: Setup::pid_read
//
// Description: Read pid file.
//
// Input:
// pid - the number of pid to save
// pidfile - the file where pid is stored
//
// Output: the pid value
//
// Return: EXIT_SUCCESS on success, EXIT_FAILURE on failure.
//
int Setup::pid_read(pid_t &pid, const char *pidfile) const
{
    char pid_path[PATH_MAX];
    int ret = 0;

    if (pidfile == nullptr)
        ret = snprintf(pid_path, PATH_MAX, "%s/%s.pid", param()[rundir].cnfdata.vdata.strval, progname);
    else
        ret = snprintf(pid_path, PATH_MAX, "%s/%s.pid", param()[rundir].cnfdata.vdata.strval, pidfile);

    if (ret <= 0 || ret >= PATH_MAX)
    {
        LOG("%s: %sBad pid filename%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    errno = 0;

    FILE *pidmax_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (errno != 0 || pidmax_file == nullptr)
    {
        LOG("%s: %scouldn't open max system pid value%s %s on %s", progname, RED, NOR, handle_err(), "/proc/sys/kernel/pid_max");

        if (pidmax_file)
            assert(fclose(pidmax_file) == 0);

        return EXIT_FAILURE;
    }

    char pidmaxstr[(MAX_STR_LEN + 1)];
    memset(&pidmaxstr, 0, (MAX_STR_LEN + 1));

    size_t pidmax_readed = fread(pidmaxstr, sizeof(char), (MAX_STR_LEN + 1), pidmax_file);

    if (errno != 0)
    {
        LOG("%s: %scouldn't read file /proc/sys/kernel/pid_max%s %s", progname, RED, NOR, handle_err());
        assert(fclose(pidmax_file) == 0);
        return EXIT_FAILURE;
    }

    assert(fclose(pidmax_file) == 0);

    assert(pidmax_readed == (size_t)strlen(pidmaxstr));

    FILE *pid_file = fopen(pid_path, "r");

    if (errno != 0 || pid_file == nullptr)
    {
        LOG("%s: couldn't open %s.pid %s on %s\n", progname, RED, NOR, pidfile, handle_err(), param()[rundir].cnfdata.vdata.strval);

        if (pid_file)
            assert(fclose(pid_file) == 0);

        return EXIT_FAILURE;
    }

    // protect file from reading from other programs during this writing
    if (file_lock(pid_file, true) == true)
    {
        char *pidstr = FCALLOC(char, CALLOC, (pidmax_readed + 1));

        size_t readed = fread(pidstr, sizeof(char), pidmax_readed, pid_file);

        if (errno != 0)
        {
            LOG("%s: couldn't read file %s on %s\n", progname, RED, NOR, handle_err(), pid_path);
            return EXIT_FAILURE;
        }

        assert(readed == (size_t)strlen(pidstr));

        // check first if pid file could be valid
        for (uint8_t i = 0; i < strlen(pidstr); i++)
        {
            if (isdigit(pidstr[i]))
                continue;
            else if (i == (strlen(pidstr) - 1) && pidstr[i] == ASCII_NL)
                break;
            else
                return EXIT_FAILURE;
        }

        pid = atoi(pidstr);
        free(pidstr);

        // exit if pid is invalid
        if (pid == 0 || pid > atoi(pidmaxstr))
            return EXIT_FAILURE;
    }
    else
    {
        LOG("%s: couldn't not lock file %s\n", progname, RED, NOR, pid_path);
        assert(fclose(pid_file) == 0);
        return EXIT_FAILURE;
    }

    if (file_unlock(pid_file) == false)
    {
        LOG("%s: couldn't not unlock file %s\n", progname, RED, NOR, pid_path);
        assert(fclose(pid_file) == 0);
        return EXIT_FAILURE;
    }

    assert(fclose(pid_file) == 0);

    return EXIT_SUCCESS;
}

//
// Name: Setup::pid_del
//
// Description: Delete pid file.
//
// Input:
// pid - the number of pid to save
// pidfile - the file where pid is stored
//
// Output: the pid value
//
// Return: true on success, false on failure.
//
int Setup::pid_del(const char *pidfile) const
{
    char pid_path[PATH_MAX];
    int ret = 0;

    if (pidfile == nullptr)
        ret = snprintf(pid_path, PATH_MAX, "%s/%s.pid", param()[rundir].cnfdata.vdata.strval, progname);
    else
        ret = snprintf(pid_path, PATH_MAX, "%s/%s.pid", param()[rundir].cnfdata.vdata.strval, pidfile);

    if (ret <= 0 || ret >= PATH_MAX)
    {
        fprintf(logstream, "Bad pid filename.");
        ;
        return EXIT_FAILURE;
    }

    if (unlink(pid_path) == EOF)
    {
        fprintf(logstream, "%s: unlink %s %s\n", progname, pid_path, handle_err());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

//
// Name: Setup::set_parameters
//
// Description: Populate the parameters array
//
// Input:
// parameters - the array of struct cnfp_t
//
// Output:
//
// Return:
//
void Setup::set_parameters(cnfp_t *parameters)
{
    if (parameters)
    {
        memset(parameters, 0, (sizeof(cnfp_t) * paramsize));

        for (unsigned short i = 0; i < paramsize; i++)
        {
            parameters[i].name = list[i];
            parameters[i].cnfdata.def = new default_t();
            memset(parameters[i].cnfdata.def, 0, sizeof(default_t));

            // set expected value datatype
            switch (i)
            {
            case debug:
                parameters[i].cnfdata.vdata.tag = BOOL;
                parameters[i].cnfdata.def->longdef = false;
                parameters[i].cnfdata.def->longmin = false;
                parameters[i].cnfdata.def->longmax = true;
                parameters[i].cnfdata.vdata.boval = (bool)parameters[i].cnfdata.def->longdef;
                break;
            case verbose:
                parameters[i].cnfdata.vdata.tag = BOOL;
                parameters[i].cnfdata.def->longdef = false;
                parameters[i].cnfdata.def->longmin = false;
                parameters[i].cnfdata.def->longmax = true;
                parameters[i].cnfdata.vdata.boval = (bool)parameters[i].cnfdata.def->longdef;
                break;
            case pool_bridgedvlan:
                parameters[i].cnfdata.vdata.tag = GRPVLAN;
                break;
            case lbhf:
                parameters[i].cnfdata.vdata.tag = LONGINT;
                parameters[i].cnfdata.def->longdef = 0x00000003;
                parameters[i].cnfdata.def->longmin = 0x00000001;
                parameters[i].cnfdata.def->longmax = 0x0000001f;
                parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                strncpy(parameters[i].cnfdata.def->unit, "hex value\0", 10);
                break;
            case mmonwait:
                parameters[i].cnfdata.vdata.tag = LONGINT;
                parameters[i].cnfdata.def->longdef = 5; // seconds
                parameters[i].cnfdata.def->longmin = 1; // seconds
                parameters[i].cnfdata.def->longmax = 10; // seconds
                parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                strncpy(parameters[i].cnfdata.def->unit, "seconds\0", 8);
                break;
            case sshscanint:
                parameters[i].cnfdata.vdata.tag = LONGINT;
                parameters[i].cnfdata.def->longdef = 5000; // one day in seconds
                parameters[i].cnfdata.def->longmin = 500; // one hour in seconds
                parameters[i].cnfdata.def->longmax = 50000; // one week in seconds
                parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                strncpy(parameters[i].cnfdata.def->unit, "milliseconds\0", 13);
                break;
            case sshbfquar:
                parameters[i].cnfdata.vdata.tag = LONGINT;
                parameters[i].cnfdata.def->longdef = 86400; // one day in seconds
                parameters[i].cnfdata.def->longmin = 3600; // one hour in seconds
                parameters[i].cnfdata.def->longmax = 604800; // one week in seconds
                parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                strncpy(parameters[i].cnfdata.def->unit, "seconds\0", 8);
                break;
            case icmpgranttime:
                parameters[i].cnfdata.vdata.tag = LONGINT;
                parameters[i].cnfdata.def->longdef = 3600; // one hour in seconds
                parameters[i].cnfdata.def->longmin = 60; // one minute in seconds
                parameters[i].cnfdata.def->longmax = 86400; // one day in seconds
                parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                strncpy(parameters[i].cnfdata.def->unit, "seconds\0", 8);
                break;
            case mainv4network:
                parameters[i].cnfdata.vdata.tag = IN4ADDR;
                break;
            case mainv6network:
                parameters[i].cnfdata.vdata.tag = IN6ADDR;
                break;
            case pool_blk:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_rad:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_dns:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_ntp:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_vpn:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_mxx:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_mon:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            case pool_log:
                parameters[i].cnfdata.vdata.tag = GRPADDR;
                break;
            default:
                parameters[i].cnfdata.vdata.tag = CHARS;
                break;
            };
        }
    }
}

//
// Name: Setup::conf_option_set
//
// Description: Set configuration option.
//
// Input:
//	target - the target
//	optmask - the conf_optmask_t value
//	boolean - true or false
//
// Return:
//
void Setup::conf_option_set(uint8_t target, conf_optmask_t optmask, bool boolean)
{
    if ((target & optmask) == boolean)
        return; // already set
    else
    {
        if ((target & optmask) == boolean)
        {
            if (boolean == true)
                target &= optmask;
            else
                target |= optmask;
        }
    }

    return;
}

//
// Name: Setup::conf_option_get
//
// Description: Get configuration option.
//
// Input:
//	target - the target
//	optmask - the conf_optmask_t value
//	boolean - true or false
//
// Return: true or false
//
bool Setup::conf_option_get(uint8_t target, conf_optmask_t optmask, bool boolean)
{
    if ((target & optmask) == boolean)
        return true;

    return false;
}

//
// Name: Setup::param
//
// Description: Return the structure of the configuration parameters.
//
// Input:
//
// Output: cnfp_t structure
//
// Return: pointer to structure cnfp_t
//
Setup::cnfp_t *Setup::param(void) const
{
    return parameters;
}

//
// Name: Setup::parseconf
//
// Description: Get line options and parse starting configuration.
//
// Input:
//
// Output: cnfp_t structure
//
// Return: 0 if valid configuration else 1
//
int Setup::parseconf(int _argc, char **_argv)
{
    size_t pnlen = 0;
    char *pslash = nullptr;

    if (parameters == nullptr)
    {
        std::cerr << "No parameters to handle." << std::endl;
        return EXIT_FAILURE;
    }

    pslash = strrchr(_argv[0], ASCII_SL);
    errno = 0;

    if (pslash)
        pnlen = strnlen(++pslash, 20);
    else
        pnlen = strnlen(_argv[0], 20);

    progname = nullptr;

    try
    {
        progname = new char[(pnlen + 1)];
    }
    catch (std::bad_alloc &ba)
    {
        std::cerr << "main bad_alloc caught: " << ba.what();
        return EXIT_FAILURE;
    }

    progname[0] = ASCII_NUL;

    if (pslash)
        strncpy(progname, pslash, pnlen);
    else
        strncpy(progname, _argv[0], pnlen);

    progname[pnlen] = ASCII_NUL;

    for (auto i = (int)MIENROLOAD; i < (int)INVALIDPROG; i++)
        if (pnlen == strlen(PROGRAM_STR(i)) && strcmp(progname, PROGRAM_STR(i)) == 0) // TODO correct like this also in my other projects
            progid = static_cast<program_t>(i);

    std::string config_filepath("/etc/mienro.conf");

    while (1)
    {
        int option_index = 0;

        static struct option long_options[] = {
            { "help", 0, 0, 0 },
            { "version", 0, 0, 0 },
            { "config", 1, 0, 0 },
            { parameters[debug].name, 0, 0, 0 },
            { parameters[verbose].name, 0, 0, 0 },
            { 0, 0, 0, 0 }
        };

        char c = getopt_long(_argc, _argv, "hVc:dv", long_options, &option_index);

        if (c == EOF)
            break;

        switch (c)
        {
        case 0:
            if (!strcmp(long_options[option_index].name, parameters[verbose].name))
                parameters[verbose].cnfdata.vdata.boval = true;
            // parameters[verbose].cnfdata.vdata.boval = (bool)atoi(optarg);
            else if (!strcmp(long_options[option_index].name, parameters[debug].name))
            {
                parameters[debug].cnfdata.vdata.boval = true;
                _debug = true;
            }
            else if (!strncmp(long_options[option_index].name, "file", 4))
            {
                config_filepath.clear();
                config_filepath.assign(optarg);
            }
            else if (!strncmp(long_options[option_index].name, "help", 4))
            {
                usage();
                return SETUP_EXIT_BRIEF;
            }
            else if (!strncmp(long_options[option_index].name, "version", 7))
            {
#include "version.h"
                std::cout << ver << std::endl;
                return SETUP_EXIT_BRIEF;
            }

            break;
        case 'd':
            parameters[debug].cnfdata.vdata.boval = true;
            _debug = true;
            break;
        case 'c':
            config_filepath.clear();
            config_filepath.assign(optarg);
            break;
        case 'v':
            parameters[verbose].cnfdata.vdata.boval = true;
            // parameters[verbose].cnfdata.vdata.boval = (bool)atoi(optarg);
            break;
        case 'V':
        {
#include "version.h"
            std::cout << ver << std::endl;
        }
            return SETUP_EXIT_BRIEF;
        default:
            usage();
            return SETUP_EXIT_BRIEF;
        }
    }

    if (parameters[debug].cnfdata.vdata.boval == false)
        parameters[verbose].cnfdata.vdata.boval = false;

    struct stat st_path;
    memset(&st_path, 0, sizeof(struct stat));
    stat(config_filepath.c_str(), &st_path);

    if (S_ISREG(st_path.st_mode) == false)
    {
        fprintf(logstream, "%s: %serror%s %s is not a file\n", progname, RED, NOR, config_filepath.c_str());

        // free memory for structure of default and tolerance values
        for (unsigned short i = 0; i < paramsize; i++)
            delete parameters[i].cnfdata.def;

        return EXIT_FAILURE;
    }

    FILE *config_file = fopen64(config_filepath.c_str(), "r");

    if (errno != 0)
    {
        fprintf(logstream, "%s: %serror%s %s %s\n", progname, RED, NOR, config_filepath.c_str(), handle_err());

        // free memory for structure of default and tolerance values
        for (unsigned short i = 0; i < paramsize; i++)
            delete parameters[i].cnfdata.def;

        return EXIT_FAILURE;
    }

    if (config_file == nullptr)
    {
        fprintf(logstream, "%s: error opening configuration file", progname);

        // free memory for structure of default and tolerance values
        for (unsigned short i = 0; i < paramsize; i++)
            delete parameters[i].cnfdata.def;

        return EXIT_FAILURE;
    }

    char *line = nullptr; // memory allocation is done by getline function
    size_t linelen = 0;
    ssize_t readed = 0;
    size_t linecount = 0;
    char eq = ASCII_NUL;
    char sbo = ASCII_SBO; // [
    char sbc = ASCII_SBC; // ]
    char *name = nullptr;
    char *value = nullptr;
    char *valueA = nullptr;
    char *valueB = nullptr;
    bool abend = true; // Abend: (Abnormal End)

    // optional check
    for (unsigned short i = 0; i < paramsize; i++)
        if (parameters[i].cnfdata.vdata.tag == CHARS)
            assert(parameters[i].cnfdata.vdata.strval == nullptr);

    // Read lines from input file
    while ((readed = getline(&line, &linelen, config_file)) != EOF)
    {
        int n = 0;
        char *pequalchar = nullptr;
        char *phashchar = nullptr;
        char *pchar = nullptr;

        linecount++;

        if (readed > 640)
            continue;

        // missing equal char and skip line
        if ((pequalchar = strchr(line, ASCII_EQ)) == nullptr)
            continue;

        // line with comment (#) before equal char are ignored
        phashchar = strchr(line, ASCII_NU);

        if (phashchar && phashchar < pequalchar)
            continue;

        // truncate comments
        if (phashchar)
            *phashchar = ASCII_NUL;

        // too many equal char and skip line
        if (strchr((pequalchar + 1), ASCII_EQ))
            continue;

        if ((n = sscanf(line, "%ms %c %c", &name, &eq, &sbo)) == 3 && sbo == ASCII_SBO)
        {
            // nam =val
            // nam =val#comments
            // nam =val  #comments
            // nam = val
            // nam = val#comments
            // nam = val  #comments

            assert(name);

            if (eq == ASCII_EQ && (pchar = strrchr(line, ASCII_SBC)))
            {
                *pchar = ASCII_NUL;

                if (strrchr(line, ASCII_SBC))
                {
                    std::cerr << "bad syntax at line: " << RED << linecount << NOR << std::endl;
                    SETUP_CFREE(name)
                    goto close;
                }

                *pchar = ASCII_SBC;
                pchar++;

                while (*pchar == ASCII_SP)
                    pchar++;

                if (*pchar != ASCII_NUL && *pchar != ASCII_NL)
                {
                    std::cerr << "bad syntax at line: " << RED << linecount << NOR << std::endl;
                    SETUP_CFREE(name)
                    goto close;
                }

                // store values
                for (unsigned short i = 0; i < paramsize; i++)
                {
                    if ((strncmp(name, parameters[i].name, strnlen(parameters[i].name, PCONFNAMESIZE)) == 0) && (strnlen(name, PCONFNAMESIZE) == strnlen(parameters[i].name, PCONFNAMESIZE)))
                    {
                        if (parameters[i].visited == true)
                        {
                            std::cerr << "duplicate line: " << RED << linecount << NOR << std::endl;
                            SETUP_CFREE(name)
                            goto close;
                        }

                        parameters[i].visited = true;

                        uint8_t c = 0;

                        // detect valid input datatype
                        if (parameters[i].cnfdata.vdata.tag == GRPADDR)
                        {
                            if ((pchar = strrchr(line, ASCII_SBO)))
                            {
                                *pchar = ASCII_NUL;

                                if (strrchr(line, ASCII_SBO))
                                {
                                    std::cerr << "bad syntax at line: " << RED << linecount << NOR << std::endl;
                                    SETUP_CFREE(name)
                                    goto close;
                                }

                                *pchar = ASCII_SBO;
                                pchar++;
                            }

                            cnfdata_t *temp_ptr = nullptr;

                            for (uint8_t o = 0; o <= PCONFGRPMAX; o++)
                            {
                                if (o == PCONFGRPMAX)
                                {
                                    std::cerr << "too many values associated with the parameter at line: " << RED << linecount << NOR << std::endl;
                                    SETUP_CFREE(name)
                                    goto close;
                                }

                                while (pchar && *pchar == ASCII_SP)
                                    pchar++;

                                if (((n = sscanf(pchar, "%ms %c", &valueA, &sbc)) == 2 && sbc == ASCII_SBC) || (n = sscanf(pchar, "%ms", &valueB)) == 1)
                                {
                                    char *pch = nullptr;
                                    char *pvalue = nullptr;

                                    if (n < 2)
                                    {
                                        pvalue = valueB;

                                        if ((pch = strrchr(pvalue, ASCII_SBC)))
                                        {
                                            sbc = ASCII_SBC;
                                            *pch = ASCII_NUL;
                                        }

                                        if (valueA)
                                        {
                                            free(valueA);
                                            valueA = nullptr;
                                        }
                                    }
                                    else
                                        pvalue = valueA;

                                    if (c == 0)
                                    {
                                        if (inet_pton(AF_INET, pvalue, &parameters[i].cnfdata.vdata.v4addr))
                                            parameters[i].cnfdata.vdata.tag = IN4ADDR;
                                        else if (inet_pton(AF_INET6, pvalue, &parameters[i].cnfdata.vdata.v6addr))
                                            parameters[i].cnfdata.vdata.tag = IN6ADDR;
                                        else
                                            std::cerr << "invalid value " << RED << pvalue << NOR << " at line: " << RED << linecount << NOR << std::endl;

                                        temp_ptr = &parameters[i].cnfdata;
                                    }
                                    else
                                    {
                                        cnfdata_t *next_ptr = new cnfdata;
                                        memset(next_ptr, 0, sizeof(cnfdata_t));

                                        if (inet_pton(AF_INET, pvalue, &next_ptr->vdata.v4addr))
                                            next_ptr->vdata.tag = IN4ADDR;
                                        else if (inet_pton(AF_INET6, pvalue, &next_ptr->vdata.v6addr))
                                            next_ptr->vdata.tag = IN6ADDR;
                                        else
                                            std::cerr << "invalid value " << RED << pvalue << NOR << " at line: " << RED << linecount << NOR << std::endl;

                                        temp_ptr->next = next_ptr;
                                        temp_ptr = next_ptr;
                                    }

                                    c++;

                                    SETUP_CFREE(pvalue);

                                    if (sbc == ASCII_SBC)
                                        break;
                                }

                                while (pchar && *pchar != ASCII_SP)
                                    pchar++;
                            }
                        }
                        else if (parameters[i].cnfdata.vdata.tag == GRPVLAN)
                        {
                            if ((pchar = strrchr(line, ASCII_SBO)))
                            {
                                *pchar = ASCII_NUL;

                                if (strrchr(line, ASCII_SBO))
                                {
                                    std::cerr << "bad syntax at line: " << RED << linecount << NOR << std::endl;
                                    SETUP_CFREE(name)
                                    goto close;
                                }

                                *pchar = ASCII_SBO;
                                pchar++;
                            }

                            cnfdata_t *temp_ptr = nullptr;

                            for (uint8_t o = 0; o <= PCONFGRPMAX; o++)
                            {
                                if (o == PCONFGRPMAX)
                                {
                                    std::cerr << "too many values associated with the parameter at line: " << RED << linecount << NOR << std::endl;
                                    SETUP_CFREE(name)
                                    goto close;
                                }

                                while (pchar && *pchar == ASCII_SP)
                                    pchar++;

                                if (((n = sscanf(pchar, "%ms %c", &valueA, &sbc)) == 2 && sbc == ASCII_SBC) || (n = sscanf(pchar, "%ms", &valueB)) == 1)
                                {
                                    char *pch = nullptr;
                                    char *pvalue = nullptr;
                                    char *endptr = nullptr;

                                    if (n < 2)
                                    {
                                        pvalue = valueB;

                                        if ((pch = strrchr(pvalue, ASCII_SBC)))
                                        {
                                            sbc = ASCII_SBC;
                                            *pch = ASCII_NUL;
                                        }

                                        if (valueA)
                                        {
                                            free(valueA);
                                            valueA = nullptr;
                                        }
                                    }
                                    else
                                        pvalue = valueA;

                                    if (c == 0)
                                    {

                                        parameters[i].cnfdata.vdata.longval = strtol(pvalue, &endptr, 10);

                                        if ((errno == ERANGE && (parameters[i].cnfdata.vdata.longval == LONG_MAX || parameters[i].cnfdata.vdata.longval == LONG_MIN)) || (errno != 0 && parameters[i].cnfdata.vdata.longval == 0) || (endptr == pvalue))
                                        {
                                            parameters[i].cnfdata.vdata.longval = 0;
                                            std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                        }
                                        else
                                            parameters[i].cnfdata.vdata.tag = LONGINT;

                                        temp_ptr = &parameters[i].cnfdata;
                                    }
                                    else
                                    {
                                        cnfdata_t *next_ptr = new cnfdata;
                                        memset(next_ptr, 0, sizeof(cnfdata_t));

                                        next_ptr->vdata.longval = strtol(pvalue, &endptr, 10);

                                        if ((errno == ERANGE && (next_ptr->vdata.longval == LONG_MAX || next_ptr->vdata.longval == LONG_MIN)) || (errno != 0 && next_ptr->vdata.longval == 0) || (endptr == pvalue))
                                        {
                                            next_ptr->vdata.longval = 0;
                                            std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                        }
                                        else
                                            next_ptr->vdata.tag = LONGINT;

                                        temp_ptr->next = next_ptr;
                                        temp_ptr = next_ptr;
                                    }

                                    c++;

                                    SETUP_CFREE(pvalue);

                                    if (sbc == ASCII_SBC)
                                        break;
                                }

                                while (pchar && *pchar != ASCII_SP)
                                    pchar++;
                            }
                        }
                    }
                }

                SETUP_CFREE(name)
            }
            else
            {
                std::cerr << "bad syntax at line: " << RED << linecount << NOR << std::endl;
                SETUP_CFREE(name)
                goto close;
            }
        }
        else
        {
            SETUP_CFREE(name)

            if ((n = sscanf(line, "%ms %c %ms", &name, &eq, &value)) == 3)
            {

                // nam =val
                // nam =val#comments
                // nam =val  #comments
                // nam = val
                // nam = val#comments
                // nam = val  #comments

                assert(name);
                assert(value);

                if (eq == ASCII_EQ)
                {
                    // store values
                    for (unsigned short i = 0; i < paramsize; i++)
                    {
                        if ((strncmp(name, parameters[i].name, strnlen(parameters[i].name, PCONFNAMESIZE)) == 0) && (strnlen(name, PCONFNAMESIZE) == strnlen(parameters[i].name, PCONFNAMESIZE)))
                        {
                            if (parameters[i].visited == true)
                            {
                                std::cerr << "duplicate line: " << RED << linecount << NOR << std::endl;
                                free(name);
                                name = nullptr;
                                free(value);
                                value = nullptr;
                                goto close;
                            }

                            parameters[i].visited = true;

                            char *endptr = nullptr;

                            // detect valid input datatype
                            switch (parameters[i].cnfdata.vdata.tag)
                            {
                            case BOOL:
                                switch (i) // only some bool values are accepted
                                {
                                    /*	case strict:
                                                    if (strncmp(value, "true", 4) == 0)
                                                            parameters[i].cnfdata.vdata.longval = (long int)true;
                                                    else if	(strncmp(value, "false", 5) == 0)
                                                            parameters[i].cnfdata.vdata.longval = (long int)false;
                                                    else
                                                    {
                                                            parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                                                            std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                                            fprintf(logstream, "%s can have values true or false, (using %s).\n", parameters[i].name, parameters[i].cnfdata.def->longdef ? "true" : "false");
                                                            continue;
                                                    }
                                            break; */
                                default:
                                    break;
                                };
                                break;
                            case LONGINT:
                                errno = 0;

                                switch (i)
                                {
                                case lbhf:
                                    parameters[i].cnfdata.vdata.longval = strtol(value, &endptr, 16);
                                    break;
                                default:
                                    parameters[i].cnfdata.vdata.longval = strtol(value, &endptr, 10);
                                    break;
                                };

                                // Check for various possible errors
                                if ((errno == ERANGE && (parameters[i].cnfdata.vdata.longval == LONG_MAX || parameters[i].cnfdata.vdata.longval == LONG_MIN)) || (errno != 0 && parameters[i].cnfdata.vdata.longval == 0) || (endptr == value))
                                {
                                    parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    continue;
                                }
                                else if (parameters[i].cnfdata.vdata.longval < parameters[i].cnfdata.def->longmin || parameters[i].cnfdata.vdata.longval > parameters[i].cnfdata.def->longmax)
                                {
                                    parameters[i].cnfdata.vdata.longval = parameters[i].cnfdata.def->longdef;
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    fprintf(logstream, "%s can have values between %ld and %ld %s, (using %ld).\n", parameters[i].name, parameters[i].cnfdata.def->longmin, parameters[i].cnfdata.def->longmax, parameters[i].cnfdata.def->unit, parameters[i].cnfdata.def->longdef);
                                    continue;
                                }
                                break;
                            case DOUBLE:
                                errno = 0;
                                parameters[i].cnfdata.vdata.douval = strtod(value, &endptr);

                                // Check for various possible errors
                                if ((errno == ERANGE && (parameters[i].cnfdata.vdata.douval == -HUGE_VAL || parameters[i].cnfdata.vdata.douval == HUGE_VAL)) || (errno != 0 && parameters[i].cnfdata.vdata.douval == 0) || (endptr == value))
                                {
                                    parameters[i].cnfdata.vdata.douval = parameters[i].cnfdata.def->doudef;
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    continue;
                                }
                                else if (parameters[i].cnfdata.vdata.douval < parameters[i].cnfdata.def->doumin || parameters[i].cnfdata.vdata.douval > parameters[i].cnfdata.def->doumax)
                                {
                                    parameters[i].cnfdata.vdata.douval = parameters[i].cnfdata.def->doudef;
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    fprintf(logstream, "%s can have values between %f and %f %s, (using %f).\n", parameters[i].name, parameters[i].cnfdata.def->doumin, parameters[i].cnfdata.def->doumax, parameters[i].cnfdata.def->unit, parameters[i].cnfdata.def->doudef);
                                    continue;
                                }
                                break;
                            case IN4ADDR:
                                if (inet_pton(AF_INET, value, &parameters[i].cnfdata.vdata.v4addr) <= 0)
                                {
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    free(value);
                                    value = nullptr;
                                    continue;
                                }

                                switch (i)
                                {
                                case mainv4network: // must be a prefix with cidr 24
                                    if ((parameters[i].cnfdata.vdata.v4addr & 0xFF000000) > 0)
                                    {
                                        std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                        continue;
                                    }
                                    break;
                                default:
                                    break;
                                }
                                break;
                            case IN6ADDR:
                                if (inet_pton(AF_INET6, value, &parameters[i].cnfdata.vdata.v6addr) <= 0)
                                {
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    free(value);
                                    value = nullptr;
                                    continue;
                                }

                                switch (i)
                                {
                                case mainv6network: // must be a prefix with cidr 48
                                    if (parameters[i].cnfdata.vdata.v6addr.s6_addr16[3] > 0 || parameters[i].cnfdata.vdata.v6addr.s6_addr32[2] > 0 || parameters[i].cnfdata.vdata.v6addr.s6_addr32[3] > 0)
                                    {
                                        std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                        continue;
                                    }
                                    break;
                                default:
                                    break;
                                }
                                break;
                            default: // handle all string parameters here
                                assert(parameters[i].cnfdata.vdata.strval == nullptr);

                                size_t sizeval = strnlen(value, (PCONFMVSIZE + 1));

                                size_t ofsval = (sizeval - 1);

                                switch (i) // when dir remove exceeded last slash chars
                                {
                                case locale:
                                case direct:
                                case skbmode:
                                case wanifindex:
                                case sshifindex:
                                case dmzifindex:
                                case lanifindex:
                                case lockdir:
                                case rundir:
                                case logdir:
                                    while (ofsval > 0 && value[ofsval] == ASCII_SL)
                                    {
                                        value[ofsval] = ASCII_NUL;
                                        sizeval = ofsval;
                                        ofsval--;
                                    }
                                    break;
                                default:
                                    break;
                                };

                                if (sizeval == 0 || sizeval > PCONFMVSIZE)
                                {
                                    std::cerr << "invalid value at line: " << RED << linecount << NOR << std::endl;
                                    continue;
                                }

                                parameters[i].cnfdata.vdata.strval = value;
                                value = nullptr; // warning: value must not be set free here
                                assert(parameters[i].cnfdata.vdata.strval);
                                break;
                            };
                        }
                    }
                }
            }
        }

        SETUP_CFREE(name)
        SETUP_CFREE(value)
    }

    abend = false;

close:

    SETUP_CFREE(line);

    // Close
    int rc = fclose(config_file);

    if (errno != 0)
    {
        fprintf(logstream, "%s: error closing configuration file %s", progname, handle_err());

        // free memory for structure of default and tolerance values
        for (unsigned short i = 0; i < paramsize; i++)
            delete parameters[i].cnfdata.def;

        return EXIT_FAILURE;
    }

    if (rc != 0)
    { // free memory for structure of default and tolerance values
        for (unsigned short i = 0; i < paramsize; i++)
            delete parameters[i].cnfdata.def;

        fprintf(logstream, "%s: error closing configuration file (%d)", progname, rc);
        return EXIT_FAILURE;
    }

    if (abend == true)
    { // free memory for structure of default and tolerance values
        for (unsigned short i = 0; i < paramsize; i++)
            delete parameters[i].cnfdata.def;

        return EXIT_FAILURE;
    }

    for (unsigned short i = 0; i < paramsize; i++)
        if (parameters[i].cnfdata.vdata.tag == CHARS && (parameters[i].cnfdata.vdata.strval == nullptr || strnlen(parameters[i].cnfdata.vdata.strval, (PCONFMVSIZE + 1)) == 0))
        {
            std::cerr << RED << "Missing parameter " << parameters[i].name << " in configuration file." << NOR << std::endl;

            // free memory for structure of default and tolerance values
            for (unsigned short i = 0; i < paramsize; i++)
                delete parameters[i].cnfdata.def;

            return EXIT_FAILURE;
        }

    if (parameters[debug].cnfdata.vdata.boval == true)
    {
        char ipv4address[INET_ADDRSTRLEN];
        char ipv6address[INET6_ADDRSTRLEN];

        std::cout << LBR << "Display parameters of program:" << NOR << std::endl;

        for (unsigned short i = 0; i < paramsize; i++)
        {
            const char *pname = parameters[i].name;
            cnfdata_t *pvalue = &parameters[i].cnfdata;
            bool grpvalues = false; // Only groups of addresses are supported

        showvalue:

            switch (pvalue->vdata.tag)
            {
            case CHARS:
                if (pvalue->vdata.strval)
                    std::cout << GRE << pname << " = " << pvalue->vdata.strval << NOR << std::endl;
                break;
            case BOOL:
                switch (i)
                {
                    /*	case strict:
                                    std::cout << GRE << pname << " = " << std::boolalpha << (bool)pvalue->vdata.longval << std::noboolalpha << NOR << (char)ASCII_SP << pvalue->def->unit << std::endl;
                            break; */
                default:
                    break;
                };
                break;
            case LONGINT:
                switch (i)
                {
                case lbhf:
                    std::cout << GRE << pname << " = 0x" << std::hex << pvalue->vdata.longval << std::dec << NOR << (char)ASCII_SP << pvalue->def->unit << std::endl;
                    break;
                default:
                    std::cout << GRE << pname << " = " << pvalue->vdata.longval << NOR << (char)ASCII_SP << pvalue->def->unit << std::endl;
                    break;
                };
                break;
            case DOUBLE:
                std::cout << GRE << pname << " = " << pvalue->vdata.douval << NOR << (char)ASCII_SP << pvalue->def->unit << std::endl;
                break;
            case IN4ADDR:
                ipv4address[0] = ASCII_NUL;

                if (pvalue->next == nullptr)
                {
                    if (grpvalues == false)
                    {
                        if (inet_ntop(AF_INET, &pvalue->vdata.v4addr, ipv4address, INET_ADDRSTRLEN))
                            std::cout << GRE << pname << " = " << ipv4address << NOR << std::endl;
                    }
                    else
                    {
                        if (inet_ntop(AF_INET, &pvalue->vdata.v4addr, ipv4address, INET_ADDRSTRLEN))
                            std::cout << (char)ASCII_SP << ipv4address << (char)ASCII_SP << LBR << (char)ASCII_SBC << NOR << std::endl;
                    }
                }
                else
                {
                    if (grpvalues == false)
                    {
                        if (inet_ntop(AF_INET, &pvalue->vdata.v4addr, ipv4address, INET_ADDRSTRLEN))
                            std::cout << GRE << pname << " = " << LBR << "[ " << GRE << ipv4address;

                        grpvalues = true;
                    }
                    else if (inet_ntop(AF_INET, &pvalue->vdata.v4addr, ipv4address, INET_ADDRSTRLEN))
                        std::cout << (char)ASCII_SP << ipv4address;

                    if ((pvalue = pvalue->next))
                        goto showvalue;
                }
                break;
            case IN6ADDR:
                ipv6address[0] = ASCII_NUL;

                if (pvalue->next == nullptr)
                {
                    if (grpvalues == false)
                    {
                        if (inet_ntop(AF_INET6, &pvalue->vdata.v6addr, ipv6address, INET6_ADDRSTRLEN))
                            std::cout << GRE << pname << " = " << ipv6address << NOR << std::endl;
                    }
                    else
                    {
                        if (inet_ntop(AF_INET6, &pvalue->vdata.v6addr, ipv6address, INET6_ADDRSTRLEN))
                            std::cout << (char)ASCII_SP << ipv6address << (char)ASCII_SP << LBR << (char)ASCII_SBC << NOR << std::endl;
                    }
                }
                else
                {
                    if (grpvalues == false)
                    {
                        if (inet_ntop(AF_INET6, &pvalue->vdata.v6addr, ipv6address, INET6_ADDRSTRLEN))
                            std::cout << GRE << pname << " = " << LBR << "[ " << GRE << ipv6address;

                        grpvalues = true;
                    }
                    else if (inet_ntop(AF_INET6, &pvalue->vdata.v6addr, ipv6address, INET6_ADDRSTRLEN))
                        std::cout << (char)ASCII_SP << ipv6address;

                    if ((pvalue = pvalue->next))
                        goto showvalue;
                }
                break;
            default:
                break;
            };
        }
    }

    // free memory for structure of default and tolerance values
    for (unsigned short i = 0; i < paramsize; i++)
        delete parameters[i].cnfdata.def;

    return EXIT_SUCCESS;
}

//
// Name: Setup::prepare
//
// Description: Check if basepaths exists, set signals, set logstream, drop admin privileges.
//
// Input:
// pid - empty pid
//
// Output:
// pid - the process id of program
//
// Return: 0 if success
//
int Setup::prepare(pid_t &pid)
{
    struct stat64 statbuf;

    if (strnlen(param()[lockdir].cnfdata.vdata.strval, MAX_STR_LEN) == 0 || strnlen(param()[rundir].cnfdata.vdata.strval, MAX_STR_LEN) == 0 || strnlen(param()[logdir].cnfdata.vdata.strval, MAX_STR_LEN) == 0)
        THROW("errors in configuration file. Check lockdir,rundir or logdir parameters");

    if (stat64(param()[lockdir].cnfdata.vdata.strval, &statbuf) == EOF && mkdir(param()[lockdir].cnfdata.vdata.strval, 0700) != 0 && errno != EEXIST)
    {
        THROW("Failed to create %s directory", param()[lockdir].cnfdata.vdata.strval);
        return (EXIT_FAILURE);
    }

    if (stat64(param()[rundir].cnfdata.vdata.strval, &statbuf) == EOF && mkdir(param()[rundir].cnfdata.vdata.strval, 0700) != 0 && errno != EEXIST)
    {
        THROW("Failed to create %s directory", param()[rundir].cnfdata.vdata.strval);
        return (EXIT_FAILURE);
    }

    if (stat64(param()[logdir].cnfdata.vdata.strval, &statbuf) == EOF && mkdir(param()[logdir].cnfdata.vdata.strval, 0700) != 0 && errno != EEXIST)
    {
        THROW("Failed to create %s directory", param()[logdir].cnfdata.vdata.strval);
        return (EXIT_FAILURE);
    }

    memset(&statbuf, 0, sizeof(struct stat64));

    if (stat64(param()[rundir].cnfdata.vdata.strval, &statbuf) == EOF)
        THROW("directory %s not found.", param()[rundir].cnfdata.vdata.strval);

    memset(&statbuf, 0, sizeof(struct stat64));

    // Set parameters for sigaction
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT; // man 2 sigaction
    action.sa_sigaction = sighandler; // action.sa_sigaction need when use SA_SIGINFO
    // action.sa_flags = 0;
    // action.sa_handler = sighandler; // void sighandler(int);

    // Server should shut down on SIGTERM.
    if (sigaction(SIGTERM, &action, 0))
    {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    // Server should shut down on SIGTERM.
    if (alarm == true && sigaction(SIGALRM, &action, 0))
    {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    // In debug mode, program should shut down on SIGINT - ctrl+c - and display stats on SIGQUIT - ctrl+\ -.
    if (param()[debug].cnfdata.vdata.boval == true)
    {
        if (sigaction(SIGINT, &action, 0))
        {
            perror("sigaction");
            return EXIT_FAILURE;
        }

        if (sigaction(SIGQUIT, &action, 0))
        {
            perror("sigaction");
            return EXIT_FAILURE;
        }
    }
    /*
            // This server do action when received sigchld
            if (sigaction(SIGCHLD, &action, 0))
            {
                    perror ("sigaction");
                    return EXIT_FAILURE;
            }
    */
    sigemptyset(&mask);
    sigfillset(&mask); // set all possible signals as candidate disabled. (It is not possible to block SIGKILL or SIGSTOP.  Attempts to do so are silently ignored.)
    sigdelset(&mask, SIGCHLD); // unset
    sigdelset(&mask, SIGTERM); // unset

    if (alarm == true)
        sigdelset(&mask, SIGALRM); // unset

    if (param()[debug].cnfdata.vdata.boval == true)
    {
        sigdelset(&mask, SIGINT); // unset
        sigdelset(&mask, SIGQUIT); // unset
    }

    // Enable signals deleted from the bitwise (OR) mask
    // Now only checking '_signal' variable (handled by custom function sighandler(...)) program can exit with SIGTERM and SIGINT
    // Also SIGCHLD is enabled but not handled with '_signal' variable
#ifdef SYSTEMD_ACTIVE
    if (param()[debug].cnfdata.vdata.boval == true)
    {
        if (pthread_sigmask(SIG_SETMASK, &mask, NULL) < 0)
        {
            perror("sigprocmask");
            return EXIT_FAILURE;
        }
    }
    else if (sigprocmask(SIG_SETMASK, &mask, NULL) < 0) // (pthread_sigmask(SIG_SETMASK, &mask, NULL) < 0)
    {
        perror("sigprocmask");
        return EXIT_FAILURE;
    }
#else // multithreaded is used to shutdown monitor when systemd init is not present
    if (pthread_sigmask(SIG_SETMASK, &mask, NULL) < 0)
    {
        perror("sigprocmask");
        return EXIT_FAILURE;
    }
#endif

    if (param()[debug].cnfdata.vdata.boval == true)
        logstream = stderr;
    else
    {
        char logfile[MAX_STR_LEN];
        logfile[0] = ASCII_NUL;
        int size = snprintf(logfile, MAX_STR_LEN, "%s/%s.log", param()[logdir].cnfdata.vdata.strval, progname);
        assert(size >= 0 && size < MAX_STR_LEN);
        logstream = fopen64(logfile, "a"); // note: with disclog false valgrind report a memory leak but logstream become closed disclog true (it's all ok ;-))
    }

    if (logstream == nullptr)
    {
        fprintf(stderr, "Unable to handle logs.");
        return EXIT_FAILURE;
    }

    // Drop admin privileges, operations with root privileges must be done before this line.
    if (getuid() == 0)
    {
        struct passwd *pwd = getpwnam(param()[user].cnfdata.vdata.strval);

        if (pwd == nullptr)
        {
            LOG("Missing user %s and program cannot be executed.\n", param()[user].cnfdata.vdata.strval);
            return EXIT_FAILURE;
        }

        map_owner = pwd->pw_uid;
        map_group = pwd->pw_gid;
        /*
                        if (setuid(result->pw_uid) != 0 || seteuid(result->pw_uid) != 0)
                        {
                                LOG("Cannot suid to user %s\n", param()[user].cnfdata.vdata.strval);
                                return EXIT_FAILURE;
                        } */
    }

    // get the pid
    pid = getpid(); // get pid of running process

    // Apply the specified locale
    if (std::setlocale(LC_ALL, param()[locale].cnfdata.vdata.strval) == nullptr)
        THROW("setlocal %s failed.", param()[locale].cnfdata.vdata.strval);

    // System timezone always set to UTC
    utc_timezone_setup();

    LOG("%s: %sStarted%s", progname, LGR, NOR, false);

    if (param()[debug].cnfdata.vdata.boval == true)
        std::cout << "Locale is: " << setlocale(LC_ALL, nullptr) << std::endl;
    /* // disabled because the new version of miero provides that a single call takes care of starting all the child processes.
            char *lockpath = nullptr;

            if ((lockpath = FCALLOC(char, CALLOC, MAX_STR_LEN)) == nullptr)
                    THROW("Bad memory allocation error");

            strcpy(lockpath, param()[lockdir].cnfdata.vdata.strval);
            strncat(lockpath, "/", 2);
            strncat(lockpath, progname, (strnlen(progname, MAX_STR_LEN) + 1));
            strncat(lockpath, ".lock", 6);

            errno = 0;

            // Create an empty file for locking program. This automatically unlock at the exit of program
            FILE *lock_file = fopen((const char *)lockpath, "w");

            free(lockpath); lockpath = nullptr;

            if (errno != 0 || lock_file == nullptr)
                    return EXIT_FAILURE;

            // write lock - lock file program, is unlocked automatically at the exit of program -
            if (file_lock(lock_file, false) == false)
            {
                    if (lock_file)
                            assert(fclose(lock_file) == 0);

                    return EXIT_FAILURE;
            }

            if (lock_file)
                    assert(fclose(lock_file) == 0);
    */
    // Save system default memlock limits
    if (getrlimit(RLIMIT_MEMLOCK, &default_rlim_memlock))
    {
        perror("getrlimit(RLIMIT_MEMLOCK)");
        return EXIT_FAILURE;
    }

    // Unlimit system memlock
    if (ut == false)
    {
        struct rlimit r = { RLIM64_INFINITY, RLIM64_INFINITY };

        if (setrlimit(RLIMIT_MEMLOCK, &r))
        {
            perror("setrlimit(RLIMIT_MEMLOCK)");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

//
// Name: Setup::conf_getval
//
// Description: Get the value assigned to configuration paramenter
//
// Input:
//  parname - the name of paramenter to fetch
//
// Output:
//
// Return: copy of value
//
Setup::vdata_t Setup::conf_getval(const parname_t parname) const
{
    vdata_t vdata;

    if (parameters[parname].cnfdata.next == nullptr)
        memcpy(&vdata, &parameters[parname].cnfdata.vdata, sizeof(vdata_t));
    else
        memset(&vdata, 0, sizeof(vdata_t));

    return vdata;
}

//
// Name: Setup::conf_getlist
//
// Description: Get list of values assigned to configuration paramenter
//
// Input:
//  parname - the name of paramenter to fetch
//  vdata - pointer of area where value data must me stored
//
// Output:
//
// Return: number of elements in list
//
uint8_t Setup::conf_getlist(const parname_t parname, vdata_t *&vdata) const
{
    uint8_t n = 0;
    cnfdata_t *ptr = &parameters[parname].cnfdata;

    assert(vdata == nullptr);

    // Iterate Linked List from next structure to count number of elements
    do
        n++;
    while ((ptr = ptr->next));

    if (vdata == nullptr)
    {
        vdata = new vdata_t[n];

        memset(vdata, 0, (n * sizeof(vdata_t)));

        ptr = &parameters[parname].cnfdata;

        for (auto i = 0; i < n; i++)
        {
            assert(ptr);
            vdata[i] = ptr->vdata;
            ptr = ptr->next;
        }
    }

    return n;
}

//
// Name: Setup::get_default_memlock_rlimit
//
// Description: Get default system memlock resources.
//
// Input:
//
// Output:
//
// Return:
//
void Setup::get_default_memlock_rlimit(struct rlimit &default_rlim_memlock) const
{
    memcpy(&default_rlim_memlock, &this->default_rlim_memlock, sizeof(struct rlimit));
}

//
// Name: Setup::usercleanup
//
// Description: Cleanup user resources.
//
// Input:
//
// Output:
//
// Return:
//
void Setup::usercleanup(void)
{
    if (HIOpath)
    {
        free(HIOpath);
        HIOpath = nullptr;
    }

    if (NIOpath)
    {
        free(NIOpath);
        NIOpath = nullptr;
    }

    if (NETpath)
    {
        free(NETpath);
        NETpath = nullptr;
    }
}

//
// Name: Setup::current_username
//
// Description: Return the current user passphrase.
//
// Input:
//
// Output:
//
// Return:
//
const char *Setup::current_username(void) const
{
    return username;
}

//
// Name: Setup::current_hiopath
//
// Description: Return the current user hiopath.
//
// Input:
//
// Output:
//
// Return:
//
const char *Setup::current_hiopath(void) const
{
    if (HIOpath == nullptr)
        THROW("%s: usersetup not called after fork.", classname);

    return HIOpath;
}

//
// Name: Setup::current_niopath
//
// Description: Return the current user niopath.
//
// Input:
//
// Output:
//
// Return:
//
const char *Setup::current_niopath(void) const
{
    if (NIOpath == nullptr)
        THROW("%s: usersetup not called after fork.", classname);

    return NIOpath;
}

//
// Name: Setup::current_netpath
//
// Description: Return the current user hiopath.
//
// Input:
//
// Output:
//
// Return:
//
const char *Setup::current_netpath(void) const
{
    if (NETpath == nullptr)
        THROW("%s: usersetup not called after fork.", classname);

    return NETpath;
}

//
// Name: usage
//
// Description:
//   Prints the usage notice
//
void Setup::usage()
{
    std::cerr << "Usage: program [OPTION]" << std::endl;
    std::cerr << std::endl;
    std::cerr << " -c, --config <filename> read main configuration from file. Default /etc/mienro.conf" << std::endl;
    std::cerr << " -d, --debug             run in debug mode and log to stderr" << std::endl;
    std::cerr << " -v, --verbose           verbose debug level" << std::endl;
    std::cerr << " -V, --version           display software version" << std::endl;
    std::cerr << " -h, --help              this help message" << std::endl;
    std::cerr << std::endl;
}

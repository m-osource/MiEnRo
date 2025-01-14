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

        if (leavelogs == false and logstream != nullptr and logstream != stderr)
        {
            assert(fclose(logstream) == 0);
            logstream = nullptr;
        }
    }

    if (progname)
        delete [] progname;

    if (parameters)
    {
        for (unsigned short i = 0; i < paramsize; i++)
            if (parameters[i].cnfdata.front().def)
                parameters[i].cnfdata.front().def.reset();

        delete [] parameters;
    }

    if (sock_send_raw >= 0)
        assert(close(sock_send_raw) == 0);

    if (disclog == true and sock_listen_raw >= 0)
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
    std::string pid_path;

    std::string *rundir_ptr = std::get_if<std::string>(&parameters[rundir].cnfdata.front().vdata);

    if (rundir_ptr == nullptr)
    {
        LOG("%s: %sAn error is happened finding rundir parameter%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    if (pidfile == nullptr)
        pid_path = std::format("{}/{}.pid", *rundir_ptr, progname);
    else
        pid_path = std::format("{}/{}.pid", *rundir_ptr, pidfile);

    if (pid_path.empty() or pid_path.size() >= PATH_MAX)
    {
        LOG("%s: %sBad pid filename%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    errno = 0;

    FILE *pidmax_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (errno != 0 or pidmax_file == nullptr)
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
    if (pid == 0 or pid > atoi(pidmaxstr))
    {
        LOG("%s: %sInvalid pid number%s (%d)", progname, RED, NOR, pid);
        return EXIT_FAILURE;
    }

    FILE *pid_file = fopen(pid_path.c_str(), "w");

    if (errno != 0 or pid_file == nullptr)
    {
        LOG("%s: couldn't open %s.pid %s on %s\n", progname, RED, NOR, pidfile, handle_err(), rundir_ptr->c_str());
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
            LOG("%s: couldn't write file %s on %s\n", progname, RED, NOR, handle_err(), pid_path.c_str());
            return EXIT_FAILURE;
        }

        assert(written == (size_t)strlen(pidstr));
    }
    else
    {
        LOG("%s: couldn't not lock file %s\n", progname, RED, NOR, pid_path.c_str());
        assert(fclose(pid_file) == 0);
        return EXIT_FAILURE;
    }

    if (file_unlock(pid_file) == false)
    {
        LOG("%s: couldn't not unlock file %s\n", progname, RED, NOR, pid_path.c_str());
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
    std::string pid_path;

    std::string *rundir_ptr = std::get_if<std::string>(&parameters[rundir].cnfdata.front().vdata);

    if (rundir_ptr == nullptr)
    {
        LOG("%s: %sAn error is happened finding rundir parameter%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    if (pidfile == nullptr)
        pid_path = std::format("{}/{}.pid", *rundir_ptr, progname);
    else
        pid_path = std::format("{}/{}.pid", *rundir_ptr, pidfile);

    if (pid_path.empty() or pid_path.size() >= PATH_MAX)
    {
        LOG("%s: %sBad pid filename%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    errno = 0;

    FILE *pidmax_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (errno != 0 or pidmax_file == nullptr)
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

    FILE *pid_file = fopen(pid_path.c_str(), "r");

    if (errno != 0 or pid_file == nullptr)
    {
        LOG("%s: couldn't open %s.pid %s on %s\n", progname, RED, NOR, pidfile, handle_err(), rundir_ptr->c_str());

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
            LOG("%s: couldn't read file %s on %s\n", progname, RED, NOR, handle_err(), pid_path.c_str());
            return EXIT_FAILURE;
        }

        assert(readed == (size_t)strlen(pidstr));

        // check first if pid file could be valid
        for (uint8_t i = 0; i < strlen(pidstr); i++)
        {
            if (isdigit(pidstr[i]))
                continue;
            else if (i == (strlen(pidstr) - 1) and pidstr[i] == ASCII_NL)
                break;
            else
                return EXIT_FAILURE;
        }

        pid = atoi(pidstr);
        free(pidstr);

        // exit if pid is invalid
        if (pid == 0 or pid > atoi(pidmaxstr))
            return EXIT_FAILURE;
    }
    else
    {
        LOG("%s: couldn't not lock file %s\n", progname, RED, NOR, pid_path.c_str());
        assert(fclose(pid_file) == 0);
        return EXIT_FAILURE;
    }

    if (file_unlock(pid_file) == false)
    {
        LOG("%s: couldn't not unlock file %s\n", progname, RED, NOR, pid_path.c_str());
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
    std::string pid_path;

    std::string *rundir_ptr = std::get_if<std::string>(&parameters[rundir].cnfdata.front().vdata);

    if (rundir_ptr == nullptr)
    {
        LOG("%s: %sAn error is happened finding rundir parameter%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    if (pidfile == nullptr)
        pid_path = std::format("{}/{}.pid", *rundir_ptr, progname);
    else
        pid_path = std::format("{}/{}.pid", *rundir_ptr, pidfile);

    if (pid_path.empty() or pid_path.size() >= PATH_MAX)
    {
        LOG("%s: %sBad pid filename%s", progname, RED, NOR);
        return EXIT_FAILURE;
    }

    if (unlink(pid_path.c_str()) == EOF)
    {
        fprintf(logstream, "%s: unlink %s %s\n", progname, pid_path.c_str(), handle_err());
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
        // memset(parameters, 0, (sizeof(cnfp_t) * paramsize));

        for (unsigned short i = 0; i < paramsize; i++)
        {
            // The statement new (&parameters[i]) cnfp_t (); uses placement new to construct a cnfp_t object at the specific memory location &parameters[i].
            // The object is constructed using its default constructor, and no new memory allocation is performed.
            // This technique allows you to control the exact location in memory where the object is created, which can be useful for performance optimization or low-level memory management.
            new (&parameters[i]) cnfp_t();
            parameters[i].name.assign(list[i]);
            parameters[i].cnfdata.push_front(cnfdata_t());

            // set expected value datatype
            switch (i)
            {
            case debug:
                parameters[i].cnfdata.front().def->longdef = false;
                parameters[i].cnfdata.front().def->longmin = false;
                parameters[i].cnfdata.front().def->longmax = true;
                parameters[i].cnfdata.front().vdata = (bool)parameters[i].cnfdata.front().def->longdef;
                break;
            case verbose:
                parameters[i].cnfdata.front().def->longdef = false;
                parameters[i].cnfdata.front().def->longmin = false;
                parameters[i].cnfdata.front().def->longmax = true;
                parameters[i].cnfdata.front().vdata = (bool)parameters[i].cnfdata.front().def->longdef;
                break;
            case pool_bridgedvlan:
                parameters[i].tag = GRPVLAN;
                break;
            case lbhf:
                parameters[i].cnfdata.front().def->longdef = 0x00000003;
                parameters[i].cnfdata.front().def->longmin = 0x00000001;
                parameters[i].cnfdata.front().def->longmax = 0x0000001f;
                parameters[i].cnfdata.front().vdata = parameters[i].cnfdata.front().def->longdef;
                strncpy(parameters[i].cnfdata.front().def->unit.data(), "hex value\0", 10);
                break;
            case mmonwait:
                parameters[i].cnfdata.front().def->longdef = 5; // seconds
                parameters[i].cnfdata.front().def->longmin = 1; // seconds
                parameters[i].cnfdata.front().def->longmax = 10; // seconds
                parameters[i].cnfdata.front().vdata = parameters[i].cnfdata.front().def->longdef;
                strncpy(parameters[i].cnfdata.front().def->unit.data(), "seconds\0", 8);
                break;
            case sshscanint:
                parameters[i].cnfdata.front().def->longdef = 5000; // one day in seconds
                parameters[i].cnfdata.front().def->longmin = 500; // one hour in seconds
                parameters[i].cnfdata.front().def->longmax = 50000; // one week in seconds
                parameters[i].cnfdata.front().vdata = parameters[i].cnfdata.front().def->longdef;
                strncpy(parameters[i].cnfdata.front().def->unit.data(), "milliseconds\0", 13);
                break;
            case sshbfquar:
                parameters[i].cnfdata.front().def->longdef = 86400; // one day in seconds
                parameters[i].cnfdata.front().def->longmin = 3600; // one hour in seconds
                parameters[i].cnfdata.front().def->longmax = 604800; // one week in seconds
                parameters[i].cnfdata.front().vdata = parameters[i].cnfdata.front().def->longdef;
                strncpy(parameters[i].cnfdata.front().def->unit.data(), "seconds\0", 8);
                break;
            case icmpgranttime:
                parameters[i].cnfdata.front().def->longdef = 3600; // one hour in seconds
                parameters[i].cnfdata.front().def->longmin = 60; // one minute in seconds
                parameters[i].cnfdata.front().def->longmax = 86400; // one day in seconds
                parameters[i].cnfdata.front().vdata = parameters[i].cnfdata.front().def->longdef;
                strncpy(parameters[i].cnfdata.front().def->unit.data(), "seconds\0", 8);
                break;
            case mainv4network:
                parameters[i].cnfdata.front().vdata = in4_addr(); // Assign a defaulted value, and define a type
                break;
            case mainv6network:
                parameters[i].cnfdata.front().vdata = in6_addr(); // Assign a defaulted value, and define a type
                break;
            case pool_blk:
                parameters[i].tag = GRPADDR;
                break;
            case pool_rad:
                parameters[i].tag = GRPADDR;
                break;
            case pool_dns:
                parameters[i].tag = GRPADDR;
                break;
            case pool_ntp:
                parameters[i].tag = GRPADDR;
                break;
            case pool_vpn:
                parameters[i].tag = GRPADDR;
                break;
            case pool_mxx:
                parameters[i].tag = GRPADDR;
                break;
            case pool_mon:
                parameters[i].tag = GRPADDR;
                break;
            case pool_log:
                parameters[i].tag = GRPADDR;
                break;
            default:
                parameters[i].cnfdata.front().vdata = std::string(); // Assign a defaulted value, and define a type
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
        if (pnlen == strlen(PROGRAM_STR(i)) and strcmp(progname, PROGRAM_STR(i)) == 0)
            progid = static_cast<program_t>(i);

    std::string config_filepath("/etc/mienro.conf");

    while (true)
    {
        int option_index = 0;

        static struct option long_options[] = {
            { "help", 0, 0, 0 },
            { "version", 0, 0, 0 },
            { "config", 1, 0, 0 },
            { parameters[debug].name.c_str(), 0, 0, 0 },
            { parameters[verbose].name.c_str(), 0, 0, 0 },
            { 0, 0, 0, 0 }
        };

        char c = getopt_long(_argc, _argv, "hVc:dv", long_options, &option_index);

        if (c == EOF)
            break;

        switch (c)
        {
        case 0:
            if (parameters[verbose].name == long_options[option_index].name)
            {
                parameters[verbose].cnfdata.front().vdata = true;
                // parameters[verbose].cnfdata.front().vdata = static_cast<bool>atoi(optarg);
            }
            else if (parameters[debug].name == long_options[option_index].name)
            {
                parameters[debug].cnfdata.front().vdata = true;
                _debug = true;
            }
            else if (not strncmp(long_options[option_index].name, "file", 4))
            {
                config_filepath.clear();
                config_filepath.assign(optarg);
            }
            else if (not strncmp(long_options[option_index].name, "help", 4))
            {
                usage();
                return SETUP_EXIT_BRIEF;
            }
            else if (not strncmp(long_options[option_index].name, "version", 7))
            {
                std::cout << CopyrightData::copyright_text << std::endl;
                return SETUP_EXIT_BRIEF;
            }

            break;
        case 'd':
            parameters[debug].cnfdata.front().vdata = true;
            _debug = true;
            break;
        case 'c':
            config_filepath.clear();
            config_filepath.assign(optarg);
            break;
        case 'v':
            parameters[verbose].cnfdata.front().vdata = true;
            // parameters[verbose].cnfdata.front().vdata = static_cast<bool>atoi(optarg);
            break;
        case 'V':
        {
            std::cout << CopyrightData::copyright_text << std::endl;
        }
            return SETUP_EXIT_BRIEF;
        default:
            usage();
            return SETUP_EXIT_BRIEF;
        }
    }

    if (std::holds_alternative<bool>(parameters[debug].cnfdata.front().vdata))
    {
        try
        {
            if (std::get<bool>(parameters[debug].cnfdata.front().vdata) == false)
                parameters[verbose].cnfdata.front().vdata = false;
        }
        catch (const std::bad_variant_access &e)
        {
            throw e.what();
        }
    }

    struct stat st_path;
    memset(&st_path, 0, sizeof(struct stat));
    stat(config_filepath.c_str(), &st_path);

    if (S_ISREG(st_path.st_mode) == false)
    {
        fprintf(logstream, "%s: %serror%s %s is not a file\n", progname, RED, NOR, config_filepath.c_str());

        return EXIT_FAILURE;
    }

    std::ifstream ifs(config_filepath.c_str());
    std::stringstream ss;

    if (not ifs.good() and not ifs.is_open())
    {
        fprintf(logstream, "%s: %serror%s %s %s\n", progname, RED, NOR, config_filepath.c_str(), handle_err());

        return EXIT_FAILURE;
    }

    // optional check
    for (unsigned short i = 0; i < paramsize; i++)
    {
        if (std::holds_alternative<std::string>(parameters[i].cnfdata.front().vdata))
            assert(std::get<std::string>(parameters[i].cnfdata.front().vdata).empty());
    }

    bool abend = false;
    std::string exc;

    // starting parsing of configuration file
    // Warning: strings coming from the parser must not contain leading, trailng or duplicated spaces.
    auto so = parser<pret_t>(ifs, ss);

    try
    {
        while (so.next())
        {
            auto res = so.get_yielded_value();

            if (std::get<2>(res).find(ASCII_SP) != std::string::npos)
            {
                if (std::ranges::count(std::get<2>(res), ASCII_SP) == (PCONFGRPMAX - 1))
                {
                    exc = std::format("{}: {}{}{}", "too many values associated with the parameter at line", RED, std::get<0>(res), NOR);
                    throw std::logic_error(exc);
                }

                // store values
                for (unsigned short i = 0; i < paramsize; i++)
                {
                    if (std::get<1>(res).compare(parameters[i].name) == 0)
                    {
                        if (parameters[i].visited == true)
                        {
                            exc = std::format("{}: {}{}{}", "duplicate parameter name at line", RED, std::get<0>(res), NOR);
                            throw std::logic_error(exc);
                        }

                        parameters[i].visited = true;

                        // detect valid input datatype
                        if (parameters[i].tag == GRPADDR)
                        {
                            std::string addr;
                            in4_addr v4addr;
                            struct in6_addr v6addr;

                            std::istringstream iss(std::get<2>(res));
                            std::vector<in4_addr> in4_duplcheck;
                            std::vector<struct in6_addr> in6_duplcheck;

                            while (iss >> addr)
                            {
                                if (std::holds_alternative<std::monostate>(parameters[i].cnfdata.front().vdata))
                                {
                                    if (inet_pton(AF_INET, addr.c_str(), &v4addr))
                                    {
                                        if (std::ranges::find(in4_duplcheck, v4addr) != in4_duplcheck.end())
                                            in4_duplcheck.emplace_back(v4addr);
                                        parameters[i].cnfdata.front().vdata = v4addr;
                                    }
                                    else if (inet_pton(AF_INET6, addr.c_str(), &v6addr))
                                    {
                                        in6_duplcheck.emplace_back(v6addr);
                                        parameters[i].cnfdata.front().vdata = v6addr;
                                    }
                                    else
                                    {
                                        exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, addr, NOR, "at line", RED, std::get<0>(res), NOR);
                                        throw std::logic_error(exc);
                                    }
                                }
                                else
                                {
                                    cnfdata_t newcnfdata;

                                    if (inet_pton(AF_INET, addr.c_str(), &v4addr))
                                    {
                                        if (std::ranges::find(in4_duplcheck, v4addr) != in4_duplcheck.end())
                                        {
                                            exc = std::format("{} {}{}{} {}: {}{}{}", "duplicated value", RED, addr, NOR, "at line", RED, std::get<0>(res), NOR);
                                            throw std::logic_error(exc);
                                        }
                                        else
                                            in4_duplcheck.emplace_back(v4addr);

                                        newcnfdata.vdata = v4addr;

                                        parameters[i].cnfdata.push_front(newcnfdata);
                                    }
                                    else if (inet_pton(AF_INET6, addr.c_str(), &v6addr))
                                    {
                                        auto found = std::ranges::find_if(in6_duplcheck, [&v6addr](const in6_addr &addr)
                                            { return memcmp(&v6addr, &addr, sizeof(struct in6_addr)) == 0; });

                                        if (found != in6_duplcheck.end())
                                        {
                                            exc = std::format("{} {}{}{} {}: {}{}{}", "duplicated value", RED, addr, NOR, "at line", RED, std::get<0>(res), NOR);
                                            throw std::logic_error(exc);
                                        }
                                        else
                                            in6_duplcheck.emplace_back(v6addr);

                                        newcnfdata.vdata = v6addr;
                                        parameters[i].cnfdata.push_front(newcnfdata);
                                    }
                                    else
                                    {
                                        exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, addr, NOR, "at line", RED, std::get<0>(res), NOR);
                                        throw std::logic_error(exc);
                                    }
                                }
                            }

                            in4_duplcheck.clear();
                            in6_duplcheck.clear();
                        }
                        else if (parameters[i].tag == GRPVLAN)
                        {
                            std::string value;

                            std::istringstream iss(std::get<2>(res));
                            std::vector<long int> vlan_duplcheck;

                            while (iss >> value)
                            {
                                if (std::holds_alternative<std::monostate>(parameters[i].cnfdata.front().vdata))
                                {
                                    long int check = std::stol(value);

                                    if (std::ranges::find(vlan_duplcheck, check) != vlan_duplcheck.end())
                                    {
                                        exc = std::format("{} {}{}{} {}: {}{}{}", "duplicated value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                        throw std::logic_error(exc);
                                    }
                                    else
                                        vlan_duplcheck.emplace_back(check);

                                    parameters[i].cnfdata.front().vdata = check;
                                }
                                else
                                {
                                    long int check = std::stol(value);
                                    cnfdata_t newcnfdata;

                                    if (std::ranges::find(vlan_duplcheck, check) != vlan_duplcheck.end())
                                    {
                                        exc = std::format("{} {}{}{} {}: {}{}{}", "duplicated value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                        throw std::logic_error(exc);
                                    }
                                    else
                                        vlan_duplcheck.emplace_back(check);

                                    newcnfdata.vdata = check;
                                    parameters[i].cnfdata.push_front(newcnfdata);
                                }
                            }

                            vlan_duplcheck.clear();
                        }
                    }
                }
            }
            else
            {
                std::string value(std::get<2>(res));

                // store values
                for (unsigned short i = 0; i < paramsize; i++)
                {
                    if (std::get<1>(res).compare(parameters[i].name) == 0)
                    {
                        if (parameters[i].visited == true)
                        {
                            exc = std::format("{}: {}{}{}", "duplicate parameter name at line", RED, std::get<0>(res), NOR);
                            throw std::logic_error(exc);
                        }

                        parameters[i].visited = true;

                        if (std::holds_alternative<bool>(parameters[i].cnfdata.front().vdata))
                        {
                            switch (i) // only some bool values are accepted
                            {
                                /*	case strict:
                                        if (strncmp(value, "true", 4) == 0)
                                            parameters[i].cnfdata.front().vdata = (long int)true;
                                        else if	(strncmp(value, "false", 5) == 0)
                                            parameters[i].cnfdata.front().vdata = (long int)false;
                                        else
                                        {
                                            parameters[i].cnfdata.front().vdata = static_cast<long int>(0);
                                            std::cerr << "invalid value at line: " << RED << std::get<0>(res) << NOR << std::endl;
                                            fprintf(logstream, "%s can have values true or false, (using %s).\n", parameters[i].name, parameters[i].cnfdata.front().def->longdef ? "true" : "false");
                                            continue;
                                        }
                                break; */
                            default:
                                break;
                            };
                        }
                        else if (std::holds_alternative<long int>(parameters[i].cnfdata.front().vdata))
                        {
                            errno = 0;

                            switch (i)
                            {
                            case lbhf:
                                parameters[i].cnfdata.front().vdata = static_cast<long int>(std::stol(value, nullptr, 16));
                                break;
                            default:
                                parameters[i].cnfdata.front().vdata = static_cast<long int>(std::stol(value, nullptr, 10));
                                break;
                            };

                            // Check for various possible errors
                            auto check = std::get<long int>(parameters[i].cnfdata.front().vdata);

                            if ((check == LONG_MAX or check == LONG_MIN) or check == 0)
                            {
                                exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                throw std::logic_error(exc);
                            }
                            else if (check < parameters[i].cnfdata.front().def->longmin or check > parameters[i].cnfdata.front().def->longmax)
                            {
                                fprintf(logstream, "%s can have values between %ld and %ld %s, (using %ld).\n", parameters[i].name.c_str(), parameters[i].cnfdata.front().def->longmin, parameters[i].cnfdata.front().def->longmax, parameters[i].cnfdata.front().def->unit.data(), parameters[i].cnfdata.front().def->longdef);
                                exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                throw std::logic_error(exc);
                            }
                        }
                        else if (std::holds_alternative<in4_addr>(parameters[i].cnfdata.front().vdata))
                        {
                            if (inet_pton(AF_INET, value.c_str(), &parameters[i].cnfdata.front().vdata) <= 0)
                            {
                                exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                throw std::logic_error(exc);
                            }

                            switch (i)
                            {
                            case mainv4network: // must be a prefix with cidr 24
                                if ((std::get<in4_addr>(parameters[i].cnfdata.front().vdata) & 0xFF000000) > 0)
                                {
                                    exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                    throw std::logic_error(exc);
                                }
                                break;
                            default:
                                break;
                            }
                        }
                        else if (std::holds_alternative<struct in6_addr>(parameters[i].cnfdata.front().vdata))
                        {
                            if (inet_pton(AF_INET6, value.c_str(), &parameters[i].cnfdata.front().vdata) <= 0)
                            {
                                exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                throw std::logic_error(exc);
                            }

                            auto address = std::get<struct in6_addr>(parameters[i].cnfdata.front().vdata);

                            switch (i)
                            {
                            case mainv6network: // must be a prefix with cidr 48
                                if (address.s6_addr16[3] > 0 or address.s6_addr32[2] > 0 or address.s6_addr32[3] > 0)
                                {
                                    exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                    throw std::logic_error(exc);
                                }
                                break;
                            default:
                                break;
                            }
                        }
                        else if (std::holds_alternative<std::string>(parameters[i].cnfdata.front().vdata))
                        {
                            assert(std::get<std::string>(parameters[i].cnfdata.front().vdata).empty());

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
                                // Remove duplicate consecutive slashes
                                uniquestr(value, ASCII_SL);

                                // Removes the last slash if there is
                                if (not value.empty() && value.back() == ASCII_SL)
                                    value.pop_back(); // Removes the last slash if there is

                                break;
                            default:
                                break;
                            };

                            if (value.empty() or value.size() > PCONFMVSIZE)
                            {
                                exc = std::format("{} {}{}{} {}: {}{}{}", "invalid value", RED, value, NOR, "at line", RED, std::get<0>(res), NOR);
                                throw std::logic_error(exc);
                            }

                            parameters[i].cnfdata.front().vdata = value;
                        }
                    }
                }
            }
        }
    }
    catch (const std::bad_variant_access &e)
    {
        std::cout << e.what() << std::endl;
        abend = true;
    }
    catch (const std::invalid_argument &e)
    {
        std::cerr << e.what() << std::endl;
        abend = true;
    }
    catch (const std::out_of_range &e)
    {
        std::cerr << e.what() << std::endl;
        abend = true;
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << '\n';
        abend = true;
    }

    if (ifs.is_open())
        ifs.close();

    if (abend == true)
        return EXIT_FAILURE;

    for (unsigned short i = 0; i < paramsize; i++)
    {
        if (parameters[i].cnfdata.begin() == parameters[i].cnfdata.end())
        {
            std::cerr << RED << "Internal error." << NOR << std::endl;

            return EXIT_FAILURE;
        }
        else if (auto check = std::get_if<std::string>(&parameters[i].cnfdata.front().vdata); check and (check->empty()))
        {
            std::cerr << RED << "Missing parameter " << parameters[i].name << " in configuration file." << NOR << std::endl;

            return EXIT_FAILURE;
        }
    }

    if (std::holds_alternative<bool>(parameters[debug].cnfdata.front().vdata))
    {
        std::cout << LBR << "Display parameters of program:" << NOR << std::endl;

        for (unsigned short i = 0; i < paramsize; i++)
        {
            // std::vector<cnfdata_t> list;
            // std::ranges::reverse_copy(parameters[i].cnfdata, std::back_inserter(list));

            // std::ranges::reverse(parameters[i].cnfdata); // other solution

            std::deque<cnfdata_t> list;
            std::ranges::copy(parameters[i].cnfdata, std::front_inserter(list));
            std::deque<cnfdata_t>::iterator front = list.begin();
            std::deque<cnfdata_t>::iterator it = list.begin();

            if (++it != list.end())
            {
                std::cout << GRE << parameters[i].name << " = " << LBR << "[ " << GRE << variant_deduct_to_string(front->vdata, true);

                // Add this to the lambda capture list so that it can access the members of the enclosing class, including the variant_deduct_to_string() function.
                std::ranges::for_each(it, list.end(), [this](const auto &v)
                    { std::cout << " " << variant_deduct_to_string(v.vdata, true); });

                std::cout << LBR << " ]" << NOR << std::endl;
            }
            else if (front != list.end())
            {
                if (front->def)
                    switch (i)
                    {
                    case lbhf:
                        std::cout << GRE << parameters[i].name << " = 0x" << std::hex << variant_deduct_to_string(front->vdata, true) << std::dec << NOR << (char)ASCII_SP << front->def->unit.data() << std::endl;
                        break;
                    default:
                        std::cout << GRE << parameters[i].name << " = " << variant_deduct_to_string(front->vdata, true) << NOR << (char)ASCII_SP << front->def->unit.data() << std::endl;
                        break;
                    }
                else
                    switch (i)
                    {
                    case lbhf:
                        std::cout << GRE << parameters[i].name << " = 0x" << std::hex << variant_deduct_to_string(front->vdata, true) << std::dec << NOR << std::endl;
                        break;
                    default:
                        std::cout << GRE << parameters[i].name << " = " << variant_deduct_to_string(front->vdata, true) << NOR << std::endl;
                        break;
                    }
            }
        }
    }

    // free memory for structure of default and tolerance values
    for (unsigned short i = 0; i < paramsize; i++)
        if (parameters[i].cnfdata.front().def)
            parameters[i].cnfdata.front().def.reset();

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

    std::string *lockdir_ptr = std::get_if<std::string>(&parameters[lockdir].cnfdata.front().vdata);
    std::string *rundir_ptr = std::get_if<std::string>(&parameters[rundir].cnfdata.front().vdata);
    std::string *logdir_ptr = std::get_if<std::string>(&parameters[logdir].cnfdata.front().vdata);
    bool *debug_ptr = std::get_if<bool>(&parameters[debug].cnfdata.front().vdata);
    std::string *locale_ptr = std::get_if<std::string>(&parameters[locale].cnfdata.front().vdata);
    std::string *user_ptr = std::get_if<std::string>(&parameters[user].cnfdata.front().vdata);

    if (lockdir_ptr == nullptr or rundir_ptr == nullptr or lockdir_ptr == nullptr or debug_ptr == nullptr or locale_ptr == nullptr)
    {
        if (lockdir_ptr == nullptr or lockdir_ptr->empty())
            LOG("%s: %sAn error is happened finding lockdir parameter%s", progname, RED, NOR);
        else if (rundir_ptr == nullptr or rundir_ptr->empty())
            LOG("%s: %sAn error is happened finding rundir parameter%s", progname, RED, NOR);
        else if (logdir_ptr == nullptr or logdir_ptr->empty())
            LOG("%s: %sAn error is happened finding logdir parameter%s", progname, RED, NOR);
        else if (debug_ptr == nullptr)
            LOG("%s: %sAn error is happened finding debug parameter%s", progname, RED, NOR);
        else if (locale_ptr == nullptr or locale_ptr->empty())
            LOG("%s: %sAn error is happened finding locale parameter%s", progname, RED, NOR);
        else if (user_ptr == nullptr or user_ptr->empty())
            LOG("%s: %sAn error is happened finding user parameter%s", progname, RED, NOR);

        return EXIT_FAILURE;
    }

    if (lockdir_ptr->size() >= MAX_STR_LEN or rundir_ptr->size() >= MAX_STR_LEN or logdir_ptr->size() >= MAX_STR_LEN)
        THROW("errors in configuration file. Check lockdir,rundir or logdir parameters");

    if (stat64(lockdir_ptr->c_str(), &statbuf) == EOF and mkdir(lockdir_ptr->c_str(), 0700) != 0 and errno != EEXIST)
    {
        THROW("Failed to create %s directory", lockdir_ptr->c_str());
        return (EXIT_FAILURE);
    }

    if (stat64(rundir_ptr->c_str(), &statbuf) == EOF and mkdir(rundir_ptr->c_str(), 0700) != 0 and errno != EEXIST)
    {
        THROW("Failed to create %s directory", rundir_ptr->c_str());
        return (EXIT_FAILURE);
    }

    if (stat64(logdir_ptr->c_str(), &statbuf) == EOF and mkdir(logdir_ptr->c_str(), 0700) != 0 and errno != EEXIST)
    {
        THROW("Failed to create %s directory", logdir_ptr->c_str());
        return (EXIT_FAILURE);
    }

    memset(&statbuf, 0, sizeof(struct stat64));

    if (stat64(rundir_ptr->c_str(), &statbuf) == EOF)
        THROW("directory %s not found.", rundir_ptr->c_str());

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
    if (alarm == true and sigaction(SIGALRM, &action, 0))
    {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    // In debug mode, program should shut down on SIGINT - ctrl+c - and display stats on SIGQUIT - ctrl+\ -.
    if (*debug_ptr == true)
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

    if (*debug_ptr == true)
    {
        sigdelset(&mask, SIGINT); // unset
        sigdelset(&mask, SIGQUIT); // unset
    }

    // Enable signals deleted from the bitwise (OR) mask
    // Now only checking '_signal' variable (handled by custom function sighandler(...)) program can exit with SIGTERM and SIGINT
    // Also SIGCHLD is enabled but not handled with '_signal' variable
#ifdef SYSTEMD_ACTIVE
    if (*debug_ptr == true)
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

    if (*debug_ptr == true)
        logstream = stderr;
    else
    {
        char logfile[MAX_STR_LEN];
        logfile[0] = ASCII_NUL;
        int size = snprintf(logfile, MAX_STR_LEN, "%s/%s.log", logdir_ptr->c_str(), progname);
        assert(size >= 0 and size < MAX_STR_LEN);
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
        struct passwd *pwd = getpwnam(user_ptr->c_str());

        if (pwd == nullptr)
        {
            LOG("Missing user %s and program cannot be executed.\n", user_ptr->c_str());
            return EXIT_FAILURE;
        }

        map_owner = pwd->pw_uid;
        map_group = pwd->pw_gid;
        /*
            if (setuid(result->pw_uid) != 0 or seteuid(result->pw_uid) != 0)
            {
                LOG("Cannot suid to user %s\n", user_ptr->c_str());
                return EXIT_FAILURE;
            } */
    }

    // get the pid
    pid = getpid(); // get pid of running process

    // Apply the specified locale
    if (std::setlocale(LC_ALL, locale_ptr->c_str()) == nullptr)
        THROW("setlocal %s failed.", locale_ptr->c_str());

    // System timezone always set to UTC
    utc_timezone_setup();

    LOG("%s: %sStarted%s", progname, LGR, NOR, false);

    if (*debug_ptr == true)
        std::cout << "Locale is: " << setlocale(LC_ALL, nullptr) << std::endl;
    /* // disabled because the new version of miero provides that a single call takes care of starting all the child processes.
            char *lockpath = nullptr;

            if ((lockpath = FCALLOC(char, CALLOC, MAX_STR_LEN)) == nullptr)
                    THROW("Bad memory allocation error");

            strcpy(lockpath, param()[lockdir].cnfdata.front().vdata.strval);
            strncat(lockpath, "/", 2);
            strncat(lockpath, progname, (strnlen(progname, MAX_STR_LEN) + 1));
            strncat(lockpath, ".lock", 6);

            errno = 0;

            // Create an empty file for locking program. This automatically unlock at the exit of program
            FILE *lock_file = fopen((const char *)lockpath, "w");

            free(lockpath); lockpath = nullptr;

            if (errno != 0 or lock_file == nullptr)
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
// Name: Setup::uniqueinstring
//
// Description: Remove all consecutive duplicate characters in a string
//
// Input:
//  str - the string passed by reference to modify
//  c - the character that must be without consecutive duplicate
//
// Output: The string modified
//
// Return:
//
void Setup::uniquestr(std::string &str, const char c) const
{
    const auto ret = std::ranges::unique(str, [c](char a, char b)
        { return (a == c and b == c); });
    str.erase(ret.begin(), ret.end());
}

//
// Name: Setup::variant_deduct_to_string
//
// Description: Deduct datatype of std::variant and convert it in a readable format
//
// Input:
//  vdata - the std::variant to handle
//
// Output:
//
// Return: std::string
//
std::string Setup::variant_deduct_to_string(const vdata_t vdata, bool dumpconf) const
{
    std::string ret;
    char ipv4address[INET_ADDRSTRLEN];
    char ipv6address[INET6_ADDRSTRLEN];

    // Check if 'vdata' at compile-time
    if (std::holds_alternative<std::string>(vdata))
    {
        std::stringstream ss;
        if (dumpconf == true)
            ss << std::quoted(std::get<std::string>(vdata));
        else
            ss << std::get<std::string>(vdata);
        return ss.str();
    }
    else if (std::holds_alternative<bool>(vdata))
    {
        std::stringstream ss;
        if (dumpconf == true)
            ss << (std::get<bool>(vdata) ? "\"on\"" : "\"off\"");
        else
            ss << (std::get<bool>(vdata) ? "on" : "off");
        ret.assign(ss.str());
    }
    else if (std::holds_alternative<in4_addr>(vdata))
    {
        in4_addr v4addr = std::get<in4_addr>(vdata);
        if (inet_ntop(AF_INET, &v4addr, ipv4address, INET_ADDRSTRLEN))
            ret.assign(ipv4address);
    }
    else if (std::holds_alternative<struct in6_addr>(vdata))
    {
        struct in6_addr v6addr = std::get<in6_addr>(vdata);
        if (inet_ntop(AF_INET6, &v6addr, ipv6address, INET6_ADDRSTRLEN))
            ret.assign(ipv6address);
    }
    else if (std::holds_alternative<long int>(vdata) or std::holds_alternative<double>(vdata))
    {
        const long int *li = std::get_if<long int>(&vdata);
        std::stringstream ss;
        ss << ((li) ? *li : std::get<double>(vdata));
        ret.assign(ss.str());
    }

    return ret;
    /*
            // Version using constexpr
            auto visitor = [&ipv4address, &ipv6address] (auto && arg) -> std::string {
                    // std::decay_t<decltype(arg)> is used to deduce the actual type of arg, ensuring that we get the correct type (including removing references and const if necessary).
            using T = std::decay_t<decltype(arg)>; // Get the underlying type of 'arg'
                    std::string ret;

                // Check if 'arg' at compile-time
            if constexpr (std::is_same_v<T, std::string>)
                    {
                    std::stringstream ss;
                    ss << std::quoted(arg);
                ret.assign(ss.str());
                    }
            else if constexpr (std::is_same_v<T, bool>)
                    {
                    std::stringstream ss;
                    ss << (arg ? "\"on\"" : "\"off\"");
                    ret.assign(ss.str());
                    }
            else if constexpr (std::is_same_v<T, in4_addr>) {
                            if (inet_ntop(AF_INET, &arg, ipv4address, INET_ADDRSTRLEN))
                                    ret.assign(ipv4address);
                    }
                else if constexpr (std::is_same_v<T, struct in6_addr>) {
                            if (inet_ntop(AF_INET6, &arg, ipv6address, INET6_ADDRSTRLEN))
                                    ret.assign(ipv6address);
                    }
            else if (std::is_same_v<T, long int> or std::is_same_v<T, double>)
                    {
                    std::stringstream ss;
                    ss << arg;
                    ret.assign(ss.str());
                    }

                    return ret;
            };

    #if (__cpp_lib_variant >= 202306L)
            return vdata.visit(visitor);
    #else
            return std::visit(visitor, vdata);
    #endif */
}

//
// Name: Setup::conf_getval
//
// Description: Get the value assigned to configuration parameter
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
    return parameters[parname].cnfdata.front().vdata;
}

//
// Name: Setup::conf_getlist
//
// Description: Get list of values assigned to a configuration parameter
//
// Input:
//  parname - the name of paramenter to fetch
//  vdata - pointer of area where value data must me stored
//
// Output:
//
// Return: The list of elements
//
std::vector<Setup::vdata_t> Setup::conf_getlist(const parname_t parname) const
{
    std::deque<cnfdata_t> list;
    std::vector<vdata_t> vdata_list;
    std::ranges::copy(parameters[parname].cnfdata, std::front_inserter(list));
    std::ranges::for_each(list, [this, &vdata_list](const auto &v)
        { vdata_list.emplace_back(v.vdata); });

    return vdata_list;
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
    if (not HIOpath.empty())
        HIOpath.clear();

    if (not NIOpath.empty())
        NIOpath.clear();

    if (not NETpath.empty())
        NETpath.clear();
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
std::optional<std::string> Setup::current_username(void) const
{
	if (username.empty())
        return std::nullopt;  // No username set

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
std::string Setup::current_hiopath(void) const
{
    if (HIOpath.empty())
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
std::string Setup::current_niopath(void) const
{
    if (NIOpath.empty())
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
std::string Setup::current_netpath(void) const
{
    if (NETpath.empty())
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

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
#include "mcommon.h"

FILE *logstream = stderr; // default to stderr
pthread_mutex_t *console_lock = nullptr;
bool leavelogs = false;
bool ischild = false;
bool entropy = false; //
bool disclog = true; // tell at functions when program is executed from parent
int verbose = 1;
const char *projectname = "mienro";
char *progname = nullptr;
program_t progid = INVALIDPROG;

// Flag that tells the daemon to exit.
volatile sig_atomic_t _signal = 0;
volatile sig_atomic_t _signal_quit = 0;

// the buffer when throw message
const size_t throw_buffer_size = 2000; // the size must be a constant value
char throw_buffer[throw_buffer_size];

// the buffer when put errno message
const unsigned short errbuflen = 500;
char errbuf[errbuflen];

// used by log functions
bool _debug = false;

// color for log functions
const char *_color = nullptr;

// http://www.functionx.com/cpp/articles/serialization.htm
// std::map<IPMAPTYPE, ByteCmp<briefaddr_t>> *ipmap = nullptr;

//
// Name: utc_timezone_setup
//
// Description: check if system timezone environment is setting to UTC and if not, force setting to UTC
//
// Arguments: none
//
// Return: none
//
void utc_timezone_setup(void)
{
    char *local_tz = getenv("TZ");

    // If not set to UTC. force setting to Universal Time Clock
    if (local_tz == nullptr)
    {
        setenv("TZ", "UTC", 1);
        tzset();
    }
    else if ((strlen(local_tz) != 3 or strncasecmp(local_tz, "UTC", 3) != 0))
    {
        setenv("TZ", "UTC", 1);
        tzset();

        char *_local_tz = getenv("TZ");

        if ((strlen(_local_tz) != 3 or strncasecmp(_local_tz, "UTC", 3) != 0))
            throw("Can't setup user TZ environment");
    }
}

//
// Description: get time string in readable format. After use timebuf memory must be deleted.
//
// Input:
//  timebuf - the pointer to nullptr address
//
// Output: the pointer to allocated timebuf
//
// Return: the pointer to allocated timebuf
//
char *Log::gettime_r(char *&timebuf)
{
    time_t rawtime;
    struct tm timeinfo;
    struct tm *ptimeinfo = nullptr;
    timebuf = new char[80];
    assert(timebuf);
    time(&rawtime);
    ptimeinfo = localtime_r(&rawtime, &timeinfo);
    assert(ptimeinfo);
    strftime(timebuf, 80, "%d-%m-%Y %H:%M:%S.", ptimeinfo);
    return timebuf;
}

//
// Name: SwVer::SwVer
//
// Description: Constructor for SwVer Class
//
// Input:
//   v - the sotfware version
//   sv - the sotfware version
//
SwVer::SwVer(int v, int sv, int d, int m, int y)
    : ver(v)
    , subver(sv)
    , day(d)
    , month(m)
    , year(y)
{
}

//
// Name:
//
// Description: Prepare for the Output Stream Object the formatted software version number (see class SwVer header section)
//
// Input:
//   v - the sotfware version
//   sv - the sotfware version
//
std::ostream &operator<<(std::ostream &os, const SwVer &v)
{
    assert(v.ver < 100);
    assert(v.subver < 100);

    os << "Mienro";
    os << (char)ASCII_US;
    os.width(2);
    os.fill('0');
    os << v.ver;
    os << (char)ASCII_DT;
    os.width(2);
    os.fill('0');
    os << v.subver;

    const std::string months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (v.month > 0 and v.month < 13 and v.day > 0 and v.day < 32 and v.year > 2022 and v.year < 2200)
    {
        os.width(8);
        os.fill(ASCII_SP);
        os << (char)ASCII_SP << (char)ASCII_SP;
        os.width(2);
        os.fill('0');
        os << v.day << (char)ASCII_SL << months[v.month - 1] << (char)ASCII_SL << v.year;
    }

    return os;
}

//
// Name: THROW
//
// Description:
//   Write log message to buffer and exit with throw. Then the content must be treated inside a catch ...
//
// Input:
//   args - String to print to screen
//
void Log::throw_(const char *funcname, const char *file, int line, const char *format, ...)
{
    leavelogs = true;

    throw_buffer[0] = ASCII_NUL;

    int n = snprintf(throw_buffer, throw_buffer_size, "%s%s%s%s", LRE, EXCEPBANNER, NOR, ": ");

    if (n > 0 and (size_t) n < throw_buffer_size)
    {
        va_list args;
        va_start(args, format);

        n += vsnprintf(throw_buffer + n, (throw_buffer_size - n), format, args);

        va_end(args);
    }

    std::string digits_str = std::to_string(line);
    size_t additional_info_size = (strnlen(file, throw_buffer_size) + strnlen(digits_str.c_str(), throw_buffer_size));

    additional_info_size += 22; // adding the space and some other string/characters (real 21 rounded to 22)

    if (n >= (int)(throw_buffer_size - additional_info_size))
    {
        n += snprintf(throw_buffer + n - additional_info_size - 5, throw_buffer_size - n - additional_info_size - 5, "... ");
        n -= (additional_info_size + 5);
    }

    if (n > 0 and (size_t) n < throw_buffer_size)
        snprintf(throw_buffer + n, throw_buffer_size - n, " at file %s line %d", file, line);

    throw(throw_buffer);
}

//
// Name: log
//
// Description:
//   Write log message to file descriptor.
//
// Input:
//   args - String to print to screen
//
void Log::log(const char *funcname, const char *file, int line, const char *format, ...)
{
    if (logstream == nullptr)
        return;

    size_t bufsize = ((_debug == true) ? (MAX_STR_LEN * 4) : MAX_STR_LEN);
    char buffer[bufsize];
    buffer[0] = ASCII_NUL;

    va_list args;
    va_start(args, format);

    int n = vsnprintf(buffer, bufsize, format, args);

    va_end(args);

    if (n <= 0)
    {
        if (_color)
            _color = nullptr;

        return;
    }

    if (_debug == false) // logstream put to log file
    {
        char *timebuf = nullptr;
        gettime_r(timebuf);
        assert(timebuf);

        std::string digits_str = std::to_string(line);
        size_t additional_info_size = (strnlen(file, throw_buffer_size) + strnlen(digits_str.c_str(), throw_buffer_size));

        additional_info_size += 22; // adding the space and some other string/characters (real 21 rounded to 22)

        if (n >= (int)(bufsize - additional_info_size))
            strncat(&buffer[bufsize - additional_info_size - 6], "... ", 5); // Truncate message

        if (console_lock)
            pthread_mutex_lock(console_lock);
        else
            file_lock(logstream, false);

        if (_color)
        {
            fprintf(logstream, "%s %s%s: %s%s at file %s line %d\n", timebuf, _color, funcname, buffer, NOR, file, line);

            _color = nullptr;
        }
        else
            fprintf(logstream, "%s %s: %s at file %s line %d\n", timebuf, funcname, buffer, file, line);

        fflush(logstream); // no write sync

        if (console_lock)
            pthread_mutex_unlock(console_lock);
        else
            file_unlock(logstream);

        delete[] timebuf;
    }
    else // logstream put to console
    {
        if (n >= (int)bufsize)
            strncat(&buffer[bufsize - 6], "... ", 5); // Truncate message

        if (console_lock)
            pthread_mutex_lock(console_lock);
        else
            file_lock(logstream, false);

        if (_color)
        {
            fprintf(logstream, "%s%s: %s%s at file %s line %d\n", _color, funcname, buffer, NOR, file, line);

            _color = nullptr;
        }
        else
            fprintf(logstream, "%s: %s at file %s line %d\n", funcname, buffer, file, line);

        if (console_lock)
            pthread_mutex_unlock(console_lock);
        else
            file_unlock(logstream);
    }
}

//
// Name: THROW
//
// Description:
//   Write log message to buffer and exit with throw. Then the content must be treated inside a catch ...
//
// Input:
//   args - String to print to screen
//
void Log::throw_(const char *format, ...)
{
    leavelogs = true;

    throw_buffer[0] = ASCII_NUL;

    int n = snprintf(throw_buffer, throw_buffer_size, "%s%s%s%s", LRE, EXCEPBANNER, NOR, ": ");

    if (n > 0 and (size_t) n < throw_buffer_size)
    {
        va_list args;
        va_start(args, format);

        n += vsnprintf(throw_buffer + n, (throw_buffer_size - n), format, args);

        va_end(args);
    }

    if (n >= (int)throw_buffer_size) // Truncate message
        strncat(&throw_buffer[throw_buffer_size - 6], "... ", 5);

    throw(throw_buffer);
}

//
// Name: log
//
// Description:
//   Write log message to file descriptor.
//
// Input:
//   args - String to print to screen
//
void Log::log(const char *format, ...)
{
    if (logstream == nullptr)
        return;

    size_t bufsize = ((_debug == true) ? (MAX_STR_LEN * 4) : MAX_STR_LEN);
    char buffer[bufsize];
    buffer[0] = ASCII_NUL;

    va_list args;
    va_start(args, format);

    int n = vsnprintf(buffer, bufsize, format, args);

    va_end(args);

    if (n <= 0)
    {
        if (_color)
            _color = nullptr;

        return;
    }

    if (_debug == false) // logstream put to log file
    {
        char *timebuf = nullptr;
        gettime_r(timebuf);
        assert(timebuf);

        if (n >= (int)(bufsize))
            strncat(&buffer[bufsize - 6], "... ", 5); // Truncate message

        if (console_lock)
            pthread_mutex_lock(console_lock);
        else
            file_lock(logstream, false);

        if (_color)
        {
            fprintf(logstream, "%s %s%s%s\n", timebuf, _color, buffer, NOR);

            _color = nullptr;
        }
        else
            fprintf(logstream, "%s %s\n", timebuf, buffer);

        fflush(logstream); // no write sync

        if (console_lock)
            pthread_mutex_unlock(console_lock);
        else
            file_unlock(logstream);

        delete[] timebuf;
    }
    else // logstream put to console
    {
        if (n >= (int)bufsize)
            strncat(&buffer[bufsize - 6], "... ", 5); // Truncate message

        if (console_lock)
            pthread_mutex_lock(console_lock);
        else
            file_lock(logstream, false);

        if (_color)
        {
            fprintf(logstream, "%s%s%s\n", _color, buffer, NOR);

            _color = nullptr;
        }
        else
            fprintf(logstream, "%s\n", buffer);

        if (console_lock)
            pthread_mutex_unlock(console_lock);
        else
            file_unlock(logstream);
    }
}

//
// Name: logexception
//
// Description:
//   Write the last log message to file descriptor. Usually called by catch of throw exception.
//
// Input:
//   args - String to print to screen
//
void Log::logexception(const char *exception_buffer)
{
    if (logstream == nullptr or exception_buffer == nullptr)
        return;

    if (_debug == false) // logstream put to log file
    {
        char *timebuf = nullptr;
        gettime_r(timebuf);
        assert(timebuf);

        if (_color)
        {
            fprintf(logstream, "%s %s%s%s\n", timebuf, _color, exception_buffer, NOR);

            _color = nullptr;
        }
        else
            fprintf(logstream, "%s %s\n", timebuf, exception_buffer);

        delete[] timebuf;

        fflush(logstream); // no write sync
    }
    else // logstream put to console
    {
        if (_color)
        {
            fprintf(logstream, "%s%s%s\n", _color, exception_buffer, NOR);

            _color = nullptr;
        }
        else
            fprintf(logstream, "%s\n", exception_buffer);
    }

    if (leavelogs == true and logstream != nullptr and logstream != stderr)
    {
        assert(fclose(logstream) == 0);
        logstream = nullptr;
    }
}

//
// Name: THROW
//
// Description:
//   Write log message to buffer and exit with throw. Then the content must be treated inside a catch ...
//
// Input:
//   args - String to print to screen
//
void fcthrow(const char *format, ...)
{
    throw_buffer[0] = ASCII_NUL;

    va_list args;
    va_start(args, format);

    int n = vsnprintf(throw_buffer, throw_buffer_size, format, args);

    va_end(args);

    if (n >= (int)throw_buffer_size) // Truncate message
        strncat(&throw_buffer[throw_buffer_size - 6], "... ", 5);

    throw(throw_buffer);
}

//
// Name: file_lock (on linux work with NFS)
//
// Description: Lock a file.
//
// Input:
//  file - The file stream
//  typelock - false (write lock) or true (read lock)
//
// Return: true on success, false on failure.
//
bool file_lock(FILE *file, const bool typelock)
{
    int fd = EOF;
    struct flock lock;

    if ((fd = fileno(file)) == EOF) // obtain the file descriptor
        return false;

    memset(&lock, 0, sizeof(lock));
    lock.l_whence = SEEK_SET;

    if (typelock == false)
        lock.l_type = F_WRLCK;
    else
        lock.l_type = F_RDLCK;
#ifdef __linux__
    auto flags = fcntl(fd, F_OFD_SETLKW, &lock);
#else
    auto flags = fcntl(fd, F_SETLKW, &lock);
#endif
    if (flags == EOF)
        return false;

    return true;
}

//
// Name: fd_lock (on linux work with NFS)
//
// Description: Lock a file descriptor.
//
// Input:
//  fd - The file descriptor
//  typelock - false (write lock) or true (read lock)
//
// Return: true on success, false on failure.
//
bool fd_lock(int fd, const bool typelock)
{
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_whence = SEEK_SET;

    if (typelock == false)
        lock.l_type = F_WRLCK;
    else
        lock.l_type = F_RDLCK;
#ifdef __linux__
    auto flags = fcntl(fd, F_OFD_SETLKW, &lock);
#else
    auto flags = fcntl(fd, F_SETLKW, &lock);
#endif
    if (flags == EOF)
        return false;

    return true;
}

//
// Name: get_flock
//
// Description: Get the lock type of a file. Note: with posix method also the pid of the locking process can be acquired
//
// Input:
//  file - The file stream
//  program - the program name owner of lock
//  posix - false (use F_OFD_GETLK) or true (F_GETLK)
//
// Return: the flock structure. l_len equal EOF (-1) if function fail
//
struct flock get_flock(const char *path, const char *program, const bool posix)
{
    int fd = EOF;
    struct flock lock;

    assert(path);

    errno = 0;

    memset(&lock, 0, sizeof(lock));
    lock.l_whence = SEEK_SET;

    if ((fd = open((const char *)path, O_RDONLY)) == EOF) // obtain the file descriptor
    {
        if (errno == ENOENT) // No such file or directory
        {
            lock.l_len = EOF;
            return lock;
        }

        if (program)
            THROW("open %s on %s. Hint: run first %s program", err2msg(errno), path, program);
        else
            THROW("open %s on %s.", err2msg(errno), path);
    }

    auto flags = fcntl(fd, F_GETFL);

    if (flags == EOF)
        THROW("fcntl %s on %s", err2msg(errno), path);

    memset(&lock, 0, sizeof(lock));
    lock.l_whence = SEEK_SET;

    if (posix == false)
        flags = fcntl(fd, F_OFD_GETLK, &lock); // use the linux method
    else
        flags = fcntl(fd, F_GETLK, &lock);

    assert(close(fd) == 0);

    if (flags == EOF)
        lock.l_len = EOF;

    return lock;
}

//
// Name: file_unlock (on linux work with NFS)
//
// Description: Unlock file.
//
// Input: file The file stream
//
// Return: true on success, false on failure.
//
bool file_unlock(FILE *file)
{
    int fd = EOF;
    struct flock lock;

    if ((fd = fileno(file)) == EOF) // obtain the file descriptor
        return false;

    memset(&lock, 0, sizeof(lock));
    lock.l_whence = SEEK_SET;

    lock.l_type = F_UNLCK;
#ifdef __linux__
    auto flags = fcntl(fd, F_OFD_SETLKW, &lock);
#else
    auto flags = fcntl(fd, F_SETLK, &lock);
#endif
    if (flags == EOF)
        return false;

    return true;
}

//
// Name: fd_unlock (on linux work with NFS)
//
// Description: Unlock file descriptor.
//
// Input: fd The file descriptor
//
// Return: true on success, false on failure.
//
bool fd_unlock(int fd)
{
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_whence = SEEK_SET;

    lock.l_type = F_UNLCK;
#ifdef __linux__
    auto flags = fcntl(fd, F_OFD_SETLKW, &lock);
#else
    auto flags = fcntl(fd, F_SETLK, &lock);
#endif
    if (flags == EOF)
        return false;

    return true;
}

//
// Description: Convert errno to message
//
// Input: errno - the errno status - this is thread local
//
// Output:
//
// Return: pointer to string error
//
char *err2msg(int &_errno)
{
    char *tse = nullptr;
    errbuf[0] = '\0';

// #if (_POSIX_C_SOURCE >= 200112L) && !  _GNU_SOURCE
#ifdef __OpenBSD__
    if (strerror_r(_errno, errbuf, errbuflen) == 0)
        tse = errbuf;
#else
    tse = strerror_r(_errno, errbuf, errbuflen);
#endif

    _errno = 0; // set errno for next checking

    return tse;
}

//
// Name: DataRetention::makedir
//
// Description: concatenate directory name
//
// Arguments:
// 	dir - the directory where append
// 	basename - the new dirname to append
//
// Return: relative path where document is found
//
char *DataRetention::makedir(const char *dir, const char *basename)
{
    size_t pathlen = strnlen(dir, PATH_MAX);

    if (pathlen >= (PATH_MAX - 1)) // chars in a path name including last nul -> PATH_LEN including last nul
        THROW("%s invalid path", dir);

    size_t dirlen = strnlen(basename, NAME_MAX);

    if (dirlen == NAME_MAX) // NAME_MAX -> 255 chars not 256
        THROW("%s invalid basename", basename);

    size_t len = (pathlen + dirlen + 1); // 1 is for the last slash

    if (len > (PATH_MAX + NAME_MAX))
        THROW("%s/%s/ is tool long", dir, basename);

    char *newdir = FCALLOC(char, MALLOC, (len + 1));
    newdir[0] = '\0';
    strcpy(newdir, dir);
    strcat(newdir, basename);
    strcat(newdir, "/");

    return newdir;
}

//
// Name: DataRetention::makedir
//
// Description: concatenate directory name
//
// Arguments:
// 	dir - the directory where append
// 	basename - the new dirname to append
//
// Return: relative path where document is found
//
char *DataRetention::makedir(const char *dir, std::string basename)
{
    size_t pathlen = strnlen(dir, PATH_MAX);

    if (pathlen >= (PATH_MAX - 1)) // chars in a path name including last nul -> PATH_LEN including last nul
        THROW("%s invalid path", dir);

    size_t dirlen = basename.length();

    if (dirlen >= NAME_MAX) // 255 chars
        THROW("%s invalid basename", basename);

    size_t len = (pathlen + dirlen + 2); // 2 is for the two slashs

    if (len > (PATH_MAX + NAME_MAX))
        THROW("%s/%s/ is tool long", dir, basename);

    char *newdir = FCALLOC(char, MALLOC, (len + 1));
    newdir[0] = '\0';
    strcpy(newdir, dir);
    strcat(newdir, "/");
    strcat(newdir, basename.c_str());
    strcat(newdir, "/");

    return newdir;
}

//
// Name: DataRetention::make
//
// Description: append filename to the current working directory
//
// Arguments:
// 	cwd - the current working directory
// 	filename - filename
//
// Return: path containing file
//
char *DataRetention::makefile(char *cwd, const char *filename)
{
    size_t filelen = strnlen(filename, NAME_MAX);

    if (filelen == 0 or filelen > NAME_MAX) // filename too long
        THROW("bad filename %s", filename);

    size_t pathlen = (strnlen(cwd, MAX_STR_LEN) + filelen);

    if (pathlen >= MAX_STR_LEN + filelen) // chars in a path name including nul
        THROW("%s/%s is too long", cwd, filename);

    char *path = FCALLOC(char, MALLOC, (pathlen + 1));
    path[0] = '\0';
    strcpy(path, cwd);
    strcat(path, filename);

    return path;
}

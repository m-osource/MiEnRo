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

#ifndef __TEMPLATES_INCLUDED_H
#define __TEMPLATES_INCLUDED_H

// System libraries
#include <openssl/objects.h>
// #include <typeinfo>
// #include <typeindex>

using namespace std;

// Local libraries
// #include "const.h"
// #include "cleanup.h"
// #include "pthread.h"
// #include "atomic"

// Preprocessor macros
#ifdef DEBUG
#define FCALLOC(type, am, size) FCloudAllocator<type>(am, size, (const char *)__FILE__, __LINE__)
#define FCREALLOC(type, type2, oldbuf, oldsize, newsize) FCloudReAllocator<type, type2>(oldbuf, oldsize, newsize, (const char *)__FILE__, __LINE__)
#else
#define FCALLOC(type, am, size) FCloudAllocator<type>(am, size)
#define FCREALLOC(type, type2, oldbuf, oldsize, newsize) FCloudReAllocator<type, type2>(oldbuf, oldsize, newsize)
#endif

template <typename T, typename D>
std::unique_ptr<T, D> make_handle(T *handle, D deleter)
{
    return std::unique_ptr<T, D> { handle, deleter };
}

template <typename T>
uint8_t twoexp(T target)
{
    assert(target > 0);

    uint8_t exponent = 1;

    for (uint8_t c = 0; c < ((target - 1) % 8); c++)
    {
        exponent *= 2;
    }

    return exponent;
}

enum am_t
{ // alloc method enum
    NEW = 0,
    MALLOC = 1,
    CALLOC = 2
};

#ifdef DEBUG

//
// Name: FCloudAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Alloc memory at pointer declared inside of function
//   N.B. i template se compilati attraverso moduli devono SEMPRE essere presenti nel file header
//
// Input:
//   method - enum 'am_t' allocation method
//   size - size of memory area
//   file - filename where function is called
//   line - line in the filename where function is called
//
// Return:
//   T *pointer
//
template <typename T>
T *FCloudAllocator(const am_t &method, const int &size, const char *file, const int &line)
{
    if (size <= 0)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: size %d of memory allocation is invalid!", __DATE__, __TIME__, file, line, size);
        return nullptr;
    }

    T *allocated = nullptr;

    bool bad_alloc_method = false;

    try
    {
        switch (method)
        {
        case (NEW):
            allocated = new T[size];
            break;
        case (MALLOC):
            allocated = (T *)malloc(size * sizeof(T));
            break;
        case (CALLOC):
            allocated = (T *)calloc(size, sizeof(T));
            break;
        default:
            bad_alloc_method = true;
            break;
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: bad_alloc caught %s!", __DATE__, __TIME__, file, line, ba.what());
        return nullptr;
    }

    if (bad_alloc_method == true)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: unsupported memory allocation method!", __DATE__, __TIME__, file, line);
        return nullptr;
    }

    if (allocated == nullptr)
    {
        fprintf(stderr, "%s %s %s %d FCALLOC: allocation failed!", __DATE__, __TIME__, file, line);
        return nullptr;
    }

    return allocated;
}

//
// Name: FCloudReAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Realloc memory for required new size
//
// Input:
//   oldbuf - the buffer to increase size
//   oldsize - the size of oldbuf
//   newsize - the needed size
//   file - filename where function is called
//   line - line in the filename where function is called
//
// Output:
//   size set to new size
//
// Return:
//   T *pointer to rellocated buffer
//
template <typename T, typename P>
T *FCloudReAllocator(T *oldbuf, const P size, const P required_size, const char *file, const int &line)
{
    if (oldbuf == nullptr)
    {
        fprintf(stderr, "%s %s FCREALLOC: memory (re)allocation is required for nullptr pointer file %s and line %d!", __DATE__, __TIME__, file, line);
        return nullptr;
    }

    T *newbuf = nullptr;

    unsigned short err_count = 0;
    const unsigned short max_realloc = 5;
    bool undefined_retries = false;

    try
    {
        if (required_size > size)
        {
            do
            {
                err_count++;
                newbuf = (T *)realloc(oldbuf, (required_size * sizeof(T)));

                if (newbuf == nullptr && err_count > max_realloc)
                    undefined_retries = true;
            } while (newbuf == nullptr); // ... fine processo assegnazione memoria puntatore 'base'
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "%s %s FCREALLOC: bad_alloc caught %s at source file %s and line %d!", __DATE__, __TIME__, ba.what(), file, line);
        return nullptr;
    }

    if (undefined_retries == true)
    {
        fprintf(stderr, "%s %s FCREALLOC: Error (re)allocating memory for %u times at file %s and line %d!", __DATE__, __TIME__, err_count, file, line);
        return nullptr;
    }

    return newbuf;
}

#else

//
// Name: FCloudAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Alloc memory at pointer declared inside of function
//   N.B. i template se compilati attraverso moduli devono SEMPRE essere presenti nel file header
//
// Input:
//   method - enum 'am_t' allocation method
//   size - size of memory area
//
// Return:
//   T *pointer
//
template <typename T>
T *FCloudAllocator(const am_t &method, const int &size)
{
    if (size <= 0)
    {
        fprintf(stderr, "FCALLOC: size %d of memory allocation is invalid!", size);
        return nullptr;
    }

    T *allocated = nullptr;

    bool bad_alloc_method = false;

    try
    {

        switch (method)
        {
        case (NEW):
            allocated = new T[size];
            break;
        case (MALLOC):
            allocated = (T *)malloc(size * sizeof(T));
            break;
        case (CALLOC):
            allocated = (T *)calloc(size, sizeof(T));
            break;
        default:
            bad_alloc_method = true;
            break;
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "FCALLOC: bad_alloc caught %s!", ba.what());
    }

    if (bad_alloc_method == true)
    {
        fprintf(stderr, "FCALLOC: unsupported memory allocation method!");
        return nullptr;
    }

    if (allocated == nullptr)
    {
        fprintf(stderr, "FCALLOC: allocation failed");
        return nullptr;
    }

    return allocated;
}

//
// Name: FCloudReAllocator
//
// Description:
//   Invoked by 'preprocessor macro' 'FCalloc'
//   Realloc memory for required new size
//
// Input:
//   oldbuf - the buffer to increase size
//   size - the size of oldbuf
//   required_size - the needed size
//   delta - the delta size used to increase size
//
// Output:
//   size set to new size
//
// Return:
//   T *pointer to rellocated buffer
//
template <typename T, typename P>
T *FCloudReAllocator(T *oldbuf, const P size, const P required_size)
{
    if (oldbuf == nullptr)
    {
        fprintf(stderr, "memory (re)allocation is required!");
        return nullptr;
    }

    T *newbuf = nullptr;

    unsigned short err_count = 0;
    const unsigned short max_realloc = 5;
    bool undefined_retries = false;

    try
    {
        if (required_size > size)
        {
            do
            {
                err_count++;
                newbuf = (T *)realloc(oldbuf, (required_size * sizeof(T)));

                if (newbuf == nullptr && err_count > max_realloc)
                    undefined_retries = true;
            } while (newbuf == nullptr); // ... fine processo assegnazione memoria puntatore 'base'
        }
    }
    catch (std::bad_alloc &ba)
    {
        fprintf(stderr, "FCREALLOC: bad_alloc caught %s!", ba.what());
        return nullptr;
    }

    if (undefined_retries == true)
    {
        fprintf(stderr, "FCREALLOC: Error (re)allocating memory for %u times!", err_count);
        return nullptr;
    }

    return newbuf;
}

#endif
#endif // __TEMPLATES_INCLUDED_H
